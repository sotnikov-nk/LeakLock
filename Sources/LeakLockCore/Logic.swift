import Foundation

/// Parsers for the command-line tools the daemon shells out to.
public enum Parse {
    /// `route -n get <ip>` → value of the `interface:` line.
    public static func routeInterface(_ output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("interface:") else { continue }
            let value = trimmed.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces)
            return value.isEmpty ? nil : value
        }
        return nil
    }

    /// Cloudflare `/cdn-cgi/trace` body → value of `ip=`.
    public static func traceIP(_ body: String) -> IPAddress? {
        for line in body.split(whereSeparator: \.isNewline) where line.hasPrefix("ip=") {
            return IPAddress(String(line.dropFirst(3)))
        }
        return nil
    }

    /// Body of an IP-echo endpoint: a bare address or a Cloudflare trace.
    public static func echoedIP(_ body: String) -> IPAddress? {
        traceIP(body) ?? IPAddress(body.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// `scutil --nc list` → bundle IDs of the connected VPN services, from the trailing
    /// `[VPN:<bundle id>]` of each `(Connected)` line. The last bracket is used, since the
    /// quoted service name before it is free text.
    public static func connectedVPNClients(_ output: String) -> [String] {
        output.split(whereSeparator: \.isNewline).compactMap { line in
            guard line.contains("(Connected)"), let open = line.range(of: "[VPN:", options: .backwards),
                  let close = line[open.upperBound...].firstIndex(of: "]") else { return nil }
            let id = String(line[open.upperBound..<close])
            return id.isEmpty ? nil : id
        }
    }

    /// `pfctl -E` prints `Token : 1234` (to stderr).
    public static func pfToken(_ output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":", maxSplits: 1).map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            if parts.count == 2, parts[0] == "Token", !parts[1].isEmpty,
               parts[1].allSatisfy({ ("0"..."9").contains($0) }) {
                return parts[1]
            }
        }
        return nil
    }

    /// `pfctl -s info` → whether pf is enabled.
    public static func pfEnabled(_ output: String) -> Bool {
        output.split(whereSeparator: \.isNewline).contains {
            $0.trimmingCharacters(in: .whitespaces).hasPrefix("Status: Enabled")
        }
    }

    /// Splits a raw HTTP/1.x response into status code and body, decoding chunked bodies.
    public static func httpResponse(_ raw: String) -> (status: Int, body: String)? {
        guard let split = raw.range(of: "\r\n\r\n") else { return nil }
        let head = raw[..<split.lowerBound]
        var body = String(raw[split.upperBound...])
        let lines = head.components(separatedBy: "\r\n")
        let statusParts = lines.first?.split(separator: " ") ?? []
        guard statusParts.count >= 2, statusParts[0].hasPrefix("HTTP/"), let status = Int(statusParts[1]) else { return nil }
        let chunked = lines.dropFirst().contains {
            let l = $0.lowercased()
            return l.hasPrefix("transfer-encoding:") && l.contains("chunked")
        }
        if chunked {
            // Work on bytes: Swift treats "\r\n" as one Character, which makes
            // character-based offsets unreliable here.
            let bytes = Array(body.utf8)
            var decoded = [UInt8]()
            var i = 0
            while true {
                guard let lineEnd = Self.crlf(in: bytes, from: i) else { return nil }
                let sizeText = String(decoding: bytes[i..<lineEnd], as: UTF8.self)
                    .split(separator: ";").first.map(String.init) ?? ""
                // The body is untrusted: reject negative sizes and compare against what
                // is left instead of adding, so a huge size cannot overflow Int.
                guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16), size >= 0 else { return nil }
                if size == 0 { break }
                let start = lineEnd + 2
                guard size <= bytes.count - start else { return nil }
                decoded += bytes[start..<(start + size)]
                i = start + size + 2
                guard i <= bytes.count else { break }
            }
            body = String(decoding: decoded, as: UTF8.self)
        }
        return (status, body)
    }

    private static func crlf(in bytes: [UInt8], from start: Int) -> Int? {
        var i = start
        while i + 1 < bytes.count {
            if bytes[i] == 13, bytes[i + 1] == 10 { return i }
            i += 1
        }
        return nil
    }

    /// Interfaces pf ignores entirely (`set skip on …`), from `pfctl -s Interfaces -v`.
    /// Loopback is skipped by many configs and is harmless.
    public static func skippedInterfaces(_ output: String) -> [String] {
        output.split(whereSeparator: \.isNewline).compactMap { line in
            guard line.contains("(skip)"), let name = line.split(separator: " ").first else { return nil }
            let n = String(name)
            return n.hasPrefix("lo") ? nil : n
        }
    }

    /// `pfctl -s rules` (main ruleset) → whether Apple's sub-anchor hook, which our
    /// anchor hangs off, is present and actually reached by outbound traffic: it must
    /// apply to all traffic (not `in` only), and no outbound `quick` pass may come
    /// before it, since that would decide packets before our rules see them.
    public static func mainRulesetHasAppleAnchor(_ output: String) -> Bool {
        for raw in output.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line == "anchor \"com.apple/*\" all" { return true }
            let words = line.split(separator: " ")
            if words.first == "pass", words.contains("quick"), !words.contains("in"),
               !line.contains(" on lo0 ") {
                return false
            }
        }
        return false
    }
}

/// Pure decision of what to enforce, given the daemon's observations.
public enum Decision {
    public struct Result: Equatable {
        /// nil means "no rules at all" (protection disabled).
        public var mode: FilterMode?
        public var state: GuardState
    }

    /// - Parameters:
    ///   - tunnel: the VPN client's tunnel interface, if one is up.
    ///   - verifiedTunnel: tunnel whose external IP last matched a server IP.
    ///   - mismatchedTunnel: tunnel whose external IP last did not match.
    public static func decide(
        config: GuardConfig,
        tunnel: String?,
        verifiedTunnel: String?,
        mismatchedTunnel: String?
    ) -> Result {
        guard config.enabled else { return Result(mode: nil, state: .disabled) }
        guard !config.validServerIPs.isEmpty else { return Result(mode: .locked, state: .notConfigured) }
        guard let iface = tunnel, PFRules.isTunnelInterface(iface) else {
            return Result(mode: .locked, state: .noTunnel)
        }
        if verifiedTunnel == iface { return Result(mode: .open(tunnel: iface), state: .protected) }
        if mismatchedTunnel == iface { return Result(mode: .verifying(tunnel: iface), state: .ipMismatch) }
        return Result(mode: .verifying(tunnel: iface), state: .verifying)
    }

    /// Whether the external IP proves traffic exits through one of the VPN servers.
    public static func ipMatches(_ ip: IPAddress, config: GuardConfig) -> Bool {
        config.validServerIPs.contains(ip)
    }
}

public extension GuardState {
    /// Short Russian description for the menu.
    func title(scope: BlockScope) -> String {
        let blocked = scope == .everything ? "интернет заблокирован" : "адреса из VPN заблокированы"
        switch self {
        case .disabled: return "Защита выключена"
        case .notConfigured: return "Не указан IP VPN-сервера"
        case .noTunnel: return "VPN не подключён, \(blocked)"
        case .verifying: return "Проверяю внешний IP…"
        case .ipMismatch: return "Внешний IP не совпадает, \(blocked)"
        case .protected: return "VPN работает, трафик разрешён"
        case .error: return "Ошибка файрвола pf"
        }
    }
}
