import Foundation
import LeakLockCore

func log(_ message: String) {
    let stamp = ISO8601DateFormatter().string(from: Date())
    FileHandle.standardError.write(Data("[\(stamp)] \(message)\n".utf8))
}

struct ShellResult {
    var status: Int32
    var stdout: String
    var stderr: String
    var ok: Bool { status == 0 }
    var combined: String { stdout + stderr }
}

enum Shell {
    /// Runs a tool synchronously. Output of both pipes is drained concurrently so a
    /// chatty tool cannot deadlock on a full pipe.
    @discardableResult
    static func run(_ path: String, _ args: [String], input: String? = nil, timeout: TimeInterval = 15) -> ShellResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        let out = Pipe(), err = Pipe(), inp = Pipe()
        process.standardOutput = out
        process.standardError = err
        process.standardInput = inp

        do {
            try process.run()
        } catch {
            return ShellResult(status: -1, stdout: "", stderr: "\(path): \(error)")
        }

        if let input { inp.fileHandleForWriting.write(Data(input.utf8)) }
        try? inp.fileHandleForWriting.close()

        let outData = DataBox(), errData = DataBox()
        let group = DispatchGroup()
        group.enter()
        // Own threads, not the GCD pool: busy IPC workers must not starve the readers.
        Thread { outData.value = out.fileHandleForReading.readDataToEndOfFile(); group.leave() }.start()
        group.enter()
        Thread { errData.value = err.fileHandleForReading.readDataToEndOfFile(); group.leave() }.start()

        if group.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            if group.wait(timeout: .now() + 5) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                group.wait()
            }
        }
        process.waitUntilExit()
        return ShellResult(
            status: process.terminationStatus,
            stdout: String(decoding: outData.value, as: UTF8.self),
            stderr: String(decoding: errData.value, as: UTF8.self)
        )
    }
}

/// Written by one reader thread, read after the group says it is done.
private final class DataBox: @unchecked Sendable {
    var value = Data()
}

/// Wrapper around `pfctl` for our anchor.
final class PF {
    private let pfctl = "/sbin/pfctl"
    private let anchor = Paths.pfAnchor
    /// Reference from `pfctl -E`; pf stays enabled while any reference is held.
    private var token: String?

    /// Takes a pf reference (once) and re-enables pf if someone force-disabled it.
    /// `tampered`: pf had been disabled behind our back. `enabled`: pf is on now; when
    /// false nothing we load is enforced.
    @discardableResult
    func ensureEnabled() -> (tampered: Bool, enabled: Bool) {
        if token != nil, isEnabled() { return (false, true) }
        let wasHeld = token != nil
        if wasHeld { log("pf was disabled by someone else; re-enabling") }
        let r = Shell.run(pfctl, ["-E"])
        if let t = Parse.pfToken(r.combined) {
            token = t
        } else {
            log("pfctl -E: \(r.combined.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        return (wasHeld, isEnabled())
    }

    func isEnabled() -> Bool {
        Parse.pfEnabled(Shell.run(pfctl, ["-s", "info"]).combined)
    }

    /// Drops our pf reference. pf stays enabled if other references exist.
    func release() {
        guard let t = token else { return }
        Shell.run(pfctl, ["-X", t])
        token = nil
    }

    /// Atomically replaces the anchor's rules. On a syntax error pf keeps the old rules.
    func load(_ rules: String) -> ShellResult {
        Shell.run(pfctl, ["-a", anchor, "-f", "-"], input: rules)
    }

    func flush() {
        Shell.run(pfctl, ["-a", anchor, "-F", "rules"])
    }

    /// What pf reports for the anchor right now: its rules and the protected table.
    /// Compared with the snapshot taken right after loading, it catches rules being
    /// flushed, replaced by others, or the table being emptied. nil when pfctl fails.
    func anchorSnapshot() -> String? {
        let rules = Shell.run(pfctl, ["-a", anchor, "-s", "rules"])
        guard rules.ok else { return nil }
        // Fails harmlessly when the ruleset has no table (`.everything`); the empty
        // output is then part of the expected snapshot.
        let table = Shell.run(pfctl, ["-a", anchor, "-t", PFRules.anchorTable, "-T", "show"])
        return rules.stdout + "\n--- table\n" + table.stdout
    }

    enum MainRulesetHealth: Equatable {
        case ok
        /// Was broken and has been restored from /etc/pf.conf.
        case repaired
        /// Still broken after a reload; the message says how.
        case broken(String)
    }

    /// Our anchor only takes effect while the main ruleset contains `anchor "com.apple/*"`
    /// (stock /etc/pf.conf does) and pf filters every interface (no `set skip on en0`).
    /// Another tool may have replaced the main ruleset; restore the stock one then.
    /// - Parameter repair: false while a previous reload already failed, so a
    ///   pf.conf that itself bypasses the anchor is not reloaded every second.
    func checkMainRuleset(repair: Bool = true) -> MainRulesetHealth {
        guard let problem = mainRulesetProblem() else { return .ok }
        guard repair else { return .broken(problem) }
        log("\(problem); reloading /etc/pf.conf")
        let r = Shell.run(pfctl, ["-f", "/etc/pf.conf"])
        if !r.ok { log("pfctl -f /etc/pf.conf failed: \(r.stderr)") }
        if let still = mainRulesetProblem() { return .broken(still) }
        return .repaired
    }

    private func mainRulesetProblem() -> String? {
        if !Parse.mainRulesetHasAppleAnchor(Shell.run(pfctl, ["-s", "rules"]).stdout) {
            return "в основных правилах pf пропал якорь com.apple/*"
        }
        let skipped = Parse.skippedInterfaces(Shell.run(pfctl, ["-s", "Interfaces", "-v"]).stdout)
        if !skipped.isEmpty {
            return "pf не фильтрует \(skipped.joined(separator: ", "))"
        }
        return nil
    }

    /// Kills existing connections so nothing keeps using a path that is now closed.
    /// Returns false when pfctl failed and the old connections may still be alive.
    func flushStates() -> Bool {
        Shell.run(pfctl, ["-F", "states"]).ok
    }
}

enum Routing {
    static func table() -> [RouteEntry] {
        let r = Shell.run("/usr/sbin/netstat", ["-rn", "-f", "inet"], timeout: 5)
        return r.ok ? Routes.parse(r.stdout) : []
    }

    /// `scutil --nc list`: the system's VPN services and their state.
    static func vpnServices() -> String {
        Shell.run("/usr/sbin/scutil", ["--nc", "list"], timeout: 5).stdout
    }

    static func onLinkV6() -> [String] {
        let r = Shell.run("/usr/sbin/netstat", ["-rn", "-f", "inet6"], timeout: 5)
        return r.ok ? Routes.onLinkIPv6Prefixes(r.stdout) : []
    }
}

enum LearnedRoutesStore {
    static func load() -> LearnedRoutes {
        if let data = FileManager.default.contents(atPath: Paths.learnedRoutesByClientFile),
           let routes = try? JSONDecoder().decode(LearnedRoutes.self, from: data) {
            return routes
        }
        guard let data = FileManager.default.contents(atPath: Paths.learnedRoutesFile),
              let table = try? JSONDecoder().decode(ProtectedTable.self, from: data) else { return LearnedRoutes() }
        return LearnedRoutes(legacy: table)
    }

    static func save(_ routes: LearnedRoutes) {
        do {
            try FileManager.default.createDirectory(
                atPath: Paths.configDirectory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755]
            )
            try JSONEncoder().encode(routes).write(to: URL(fileURLWithPath: Paths.learnedRoutesByClientFile), options: .atomic)
        } catch {
            log("cannot save learned routes: \(error)")
        }
    }
}

/// Wakes the engine on any routing-table change (tunnel up/down, default route moves).
final class RouteWatcher {
    private var source: DispatchSourceRead?

    func start(queue: DispatchQueue, onChange: @escaping () -> Void) {
        let fd = socket(PF_ROUTE, SOCK_RAW, 0)
        guard fd >= 0 else {
            log("routing socket unavailable: errno \(errno); relying on polling")
            return
        }
        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        src.setEventHandler {
            var buffer = [UInt8](repeating: 0, count: 8192)
            _ = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            onChange()
        }
        src.setCancelHandler { close(fd) }
        src.resume()
        source = src
    }
}

enum ExternalIP {
    enum Failure: Error, CustomStringConvertible {
        case noAnswer(String)
        var description: String {
            switch self { case .noAnswer(let detail): return detail }
        }
    }

    /// Darwin's IP_BOUND_IF (netinet/in.h); not always exported to Swift.
    private static let ipBoundIF: Int32 = 25
    private static let timeoutSeconds = 5

    /// Asks IP-echo services which address `tunnel` exits from. Every request goes
    /// through a socket bound to `tunnel`, so it cannot leave through any other
    /// interface: if the tunnel is gone, the check simply fails.
    ///
    /// The first answer that `accept`s wins; without one, the first answer is returned.
    /// A client that routes inside the tunnel (Incy with the RoscomVPN profile) may send
    /// some echo services direct on purpose, so one answer with the home IP does not
    /// mean the tunnel leads elsewhere while another service sees the VPN server.
    static func fetch(tunnel: String, accept: @escaping (IPAddress) -> Bool,
                      completion: @escaping (Result<IPAddress, Failure>) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            let index = if_nametoindex(tunnel)
            guard index != 0 else {
                completion(.failure(.noAnswer("\(tunnel): no such interface")))
                return
            }
            var errors: [String] = []
            var firstAnswer: IPAddress?
            for endpoint in PFRules.ipCheckEndpoints {
                switch ask(endpoint, interfaceIndex: index) {
                case .success(let ip):
                    if accept(ip) {
                        completion(.success(ip))
                        return
                    }
                    firstAnswer = firstAnswer ?? ip
                case .failure(let reason):
                    errors.append("\(endpoint.host): \(reason)")
                }
            }
            if let firstAnswer {
                completion(.success(firstAnswer))
            } else {
                completion(.failure(.noAnswer(errors.joined(separator: "; "))))
            }
        }
    }

    private struct Reason: Error, CustomStringConvertible {
        let description: String
        init(_ d: String) { description = d }
    }

    private static func ask(_ endpoint: IPCheckEndpoint, interfaceIndex: UInt32) -> Result<IPAddress, Reason> {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var list: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(endpoint.host, "80", &hints, &list)
        guard rc == 0, let first = list else {
            return .failure(Reason("DNS: \(String(cString: gai_strerror(rc)))"))
        }
        defer { freeaddrinfo(first) }

        var lastError = "адрес не найден"
        var node: UnsafeMutablePointer<addrinfo>? = first
        while let ai = node {
            node = ai.pointee.ai_next
            switch request(endpoint, address: ai.pointee, interfaceIndex: interfaceIndex) {
            case .success(let raw):
                guard let response = Parse.httpResponse(raw) else { lastError = "непонятный ответ HTTP"; continue }
                guard response.status == 200 else { lastError = "HTTP \(response.status)"; continue }
                guard let ip = Parse.echoedIP(response.body) else { lastError = "в ответе нет IP"; continue }
                return .success(ip)
            case .failure(let reason):
                lastError = reason.description
            }
        }
        return .failure(Reason(lastError))
    }

    private static func request(_ endpoint: IPCheckEndpoint, address: addrinfo, interfaceIndex: UInt32) -> Result<String, Reason> {
        let fd = socket(address.ai_family, address.ai_socktype, address.ai_protocol)
        guard fd >= 0 else { return .failure(Reason("socket: \(errnoText())")) }
        defer { close(fd) }

        var index = interfaceIndex
        guard setsockopt(fd, IPPROTO_IP, ipBoundIF, &index, socklen_t(MemoryLayout<UInt32>.size)) == 0 else {
            return .failure(Reason("IP_BOUND_IF: \(errnoText())"))
        }
        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Non-blocking connect so an unreachable host costs at most the timeout.
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        if connect(fd, address.ai_addr, address.ai_addrlen) != 0 {
            guard errno == EINPROGRESS else { return .failure(Reason("connect: \(errnoText())")) }
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&pfd, 1, Int32(timeoutSeconds * 1000))
            guard ready > 0 else { return .failure(Reason(ready == 0 ? "connect timed out" : "poll: \(errnoText())")) }
            var soError: Int32 = 0
            var len = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len)
            guard soError == 0 else { return .failure(Reason("connect: \(String(cString: strerror(soError)))")) }
        }
        _ = fcntl(fd, F_SETFL, flags)

        let bytes = Array(endpoint.request.utf8)
        var sent = 0
        while sent < bytes.count {
            let n = bytes[sent...].withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
            guard n > 0 else { return .failure(Reason("send: \(errnoText())")) }
            sent += n
        }

        var data = [UInt8]()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while data.count < 65536 {
            let n = buffer.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
            if n > 0 { data += buffer[0..<n]; continue }
            if n == 0 { break }
            return .failure(Reason(errno == EAGAIN ? "read timed out" : "recv: \(errnoText())"))
        }
        return .success(String(decoding: data, as: UTF8.self))
    }

    private static func errnoText() -> String { String(cString: strerror(errno)) }
}

enum ConfigStore {
    static func load() -> GuardConfig {
        guard let data = FileManager.default.contents(atPath: Paths.configFile) else { return GuardConfig() }
        do {
            return try JSONDecoder().decode(GuardConfig.self, from: data).sanitized()
        } catch {
            log("config unreadable (\(error)); keeping protection ON with no exceptions")
            // A corrupt file must not silently disable protection.
            return GuardConfig(enabled: true)
        }
    }

    static func save(_ config: GuardConfig) throws {
        let fm = FileManager.default
        try fm.createDirectory(
            atPath: Paths.configDirectory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(config).write(to: URL(fileURLWithPath: Paths.configFile), options: .atomic)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: Paths.configFile)
    }
}
