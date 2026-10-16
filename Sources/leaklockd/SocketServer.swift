import Foundation
import LeakLockCore

/// Line-delimited JSON over a Unix domain socket. Anyone may read status; changing
/// settings requires the peer to be root or a member of the `admin` group.
final class SocketServer {
    typealias Handler = (IPCRequest, _ peerIsAdmin: Bool) -> IPCResponse

    private let path: String
    private let handler: Handler
    private var listenFD: Int32 = -1
    private let workers = DispatchQueue(label: "com.leaklock.ipc", attributes: .concurrent)
    private let slots = DispatchSemaphore(value: 8)
    /// A whole request must arrive within this time, however slowly it trickles in.
    private let requestDeadline: TimeInterval = 3

    init(path: String, handler: @escaping Handler) {
        self.path = path
        self.handler = handler
    }

    func start() throws {
        unlink(path)
        listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listenFD >= 0 else { throw posixError("socket") }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard bytes.count < capacity else { throw posixError("socket path too long") }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listenFD, $0, size) }
        }
        guard bound == 0 else { throw posixError("bind") }
        chmod(path, 0o666)
        guard listen(listenFD, 16) == 0 else { throw posixError("listen") }

        let thread = Thread { [weak self] in self?.acceptLoop() }
        thread.name = "ipc-accept"
        thread.start()
    }

    private func acceptLoop() {
        while true {
            let client = accept(listenFD, nil, nil)
            if client < 0 {
                if errno == EINTR { continue }
                log("accept failed: errno \(errno)")
                usleep(100_000)
                continue
            }
            // Bounded so local clients cannot tie up every worker thread.
            guard slots.wait(timeout: .now()) == .success else {
                close(client)
                continue
            }
            workers.async {
                defer { self.slots.signal() }
                self.serve(client)
            }
        }
    }

    private func serve(_ fd: Int32) {
        defer { close(fd) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0 else { return }

        guard let line = readLine(fd) else { return }
        let response: IPCResponse
        do {
            let request = try IPCCoding.decoder().decode(IPCRequest.self, from: line)
            response = handler(request, isAdmin(uid))
        } catch {
            response = IPCResponse(ok: false, error: "Некорректный запрос: \(error)")
        }
        guard var data = try? IPCCoding.encoder().encode(response) else { return }
        data.append(0x0A)
        data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                if n <= 0 { return }
                offset += n
            }
        }
    }

    private func readLine(_ fd: Int32) -> Data? {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        let deadline = Date().addingTimeInterval(requestDeadline)
        while data.count < 256 * 1024, Date() < deadline {
            let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if n <= 0 { return nil }
            data.append(contentsOf: buffer[0..<n])
            if let newline = data.firstIndex(of: 0x0A) { return data.prefix(upTo: newline) }
        }
        return nil
    }

    private func isAdmin(_ uid: uid_t) -> Bool {
        if uid == 0 { return true }
        guard let pw = getpwuid(uid), let admin = getgrnam("admin") else { return false }
        let adminGID = Int32(bitPattern: admin.pointee.gr_gid)
        var count: Int32 = 128
        var groups = [Int32](repeating: 0, count: Int(count))
        _ = getgrouplist(pw.pointee.pw_name, Int32(bitPattern: pw.pointee.pw_gid), &groups, &count)
        return groups.prefix(Int(max(0, count))).contains(adminGID)
    }

    private func posixError(_ what: String) -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: "\(what) failed"])
    }
}
