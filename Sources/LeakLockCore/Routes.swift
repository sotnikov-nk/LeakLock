import Foundation

/// An IPv4 network in CIDR form.
public struct IPv4Network: Hashable, Codable, CustomStringConvertible {
    public let address: UInt32
    public let prefix: Int

    private enum CodingKeys: String, CodingKey { case address, prefix }

    /// Validates like `init?(address:prefix:)`, so a corrupt learned-routes file cannot
    /// produce entries pf would reject.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        guard let n = IPv4Network(address: try c.decode(UInt32.self, forKey: .address),
                                  prefix: try c.decode(Int.self, forKey: .prefix))
        else { throw DecodingError.dataCorruptedError(forKey: .prefix, in: c, debugDescription: "prefix out of range") }
        self = n
    }

    public init?(address: UInt32, prefix: Int) {
        guard (0...32).contains(prefix) else { return nil }
        self.prefix = prefix
        self.address = address & IPv4Network.mask(prefix)
    }

    /// Parses `a.b.c.d/n` or `a.b.c.d`.
    public init?(_ text: String) {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, let ip = IPAddress(String(parts[0])), ip.family == .v4,
              let value = IPv4Network.parseDotted(ip.description) else { return nil }
        let prefix = parts.count == 2 ? Int(parts[1]) : 32
        guard let prefix else { return nil }
        self.init(address: value, prefix: prefix)
    }

    public var description: String {
        let a = address
        return "\(a >> 24).\((a >> 16) & 0xFF).\((a >> 8) & 0xFF).\(a & 0xFF)/\(prefix)"
    }

    public func contains(_ other: IPv4Network) -> Bool {
        other.prefix >= prefix && (other.address & IPv4Network.mask(prefix)) == address
    }

    static func mask(_ prefix: Int) -> UInt32 {
        prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
    }

    static func parseDotted(_ text: String) -> UInt32? {
        let octets = text.split(separator: ".").compactMap { UInt32($0) }
        guard octets.count == 4, octets.allSatisfy({ $0 <= 255 }) else { return nil }
        return octets.reduce(0) { ($0 << 8) | $1 }
    }

    /// netstat's abbreviated destinations: `default`, `0/1`, `128.0/1`, `10.33/16`,
    /// `192.168.1` (implied /24), `1.2.3.4` (host).
    static func parseNetstat(_ text: String) -> IPv4Network? {
        if text == "default" { return IPv4Network(address: 0, prefix: 0) }
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { return nil }
        let octetText = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        guard (1...4).contains(octetText.count) else { return nil }
        var octets: [UInt32] = []
        for o in octetText {
            guard let v = UInt32(o), v <= 255 else { return nil }
            octets.append(v)
        }
        let implied = octets.count * 8
        while octets.count < 4 { octets.append(0) }
        let value = octets.reduce(0) { ($0 << 8) | $1 }
        let prefix: Int
        if parts.count == 2 {
            guard let p = Int(parts[1]) else { return nil }
            prefix = p
        } else {
            prefix = implied
        }
        return IPv4Network(address: value, prefix: prefix)
    }
}

public struct RouteEntry: Equatable {
    public var destination: IPv4Network
    public var flags: String
    public var interface: String
}

public enum Routes {
    /// Parses `netstat -rn -f inet`. Unparseable lines (headers, IPv6, scoped
    /// entries with `%`) are skipped.
    public static func parse(_ output: String) -> [RouteEntry] {
        var entries: [RouteEntry] = []
        for line in output.split(whereSeparator: \.isNewline) {
            let cols = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard cols.count >= 4, !cols[0].contains("%"),
                  let dest = IPv4Network.parseNetstat(cols[0]) else { continue }
            entries.append(RouteEntry(destination: dest, flags: cols[2], interface: cols[3]))
        }
        return entries
    }

    /// Networks that never identify a remote service: loopback, link-local, multicast,
    /// broadcast.
    private static let ignored: [IPv4Network] = [
        IPv4Network("127.0.0.0/8")!, IPv4Network("169.254.0.0/16")!,
        IPv4Network("224.0.0.0/3")!,
    ]

    private static func isIgnored(_ n: IPv4Network) -> Bool {
        ignored.contains { $0.contains(n) }
    }

    /// The tunnel interface the VPN client is using: the `utunN` with the most IPv4
    /// routes. macOS's own utun0…N carry no IPv4 routes, so they are never picked.
    public static func vpnTunnel(_ entries: [RouteEntry]) -> String? {
        var counts: [String: Int] = [:]
        for e in entries where PFRules.isTunnelInterface(e.interface) && !isIgnored(e.destination) {
            counts[e.interface, default: 0] += 1
        }
        return counts.max { a, b in a.value == b.value ? a.key > b.key : a.value < b.value }?.key
    }

    /// Exemptions broader than this are never trusted: split-tunnel lists use /8 and
    /// narrower, while a hostile network pushing DHCP option 121 routes ("TunnelVision")
    /// needs a few very broad ones (0/2, 64/2, …) to pull all traffic off the tunnel.
    public static let minExemptPrefix = 8
    /// If exemptions cover more than this share of the tunnel's address space, none is
    /// trusted (fail closed): a split-tunnel country list is a few percent at most.
    public static let maxExemptShare = 0.25

    /// What the VPN client sends into `tunnel`, as a pf table: the tunnel's routes, minus
    /// more specific routes inside them that go elsewhere (e.g. the VPN server's own
    /// host route, or the LAN under a full-tunnel 0/1 + 128/1).
    ///
    /// The routing table is not authenticated: the local network can add routes via
    /// DHCP. Exemptions are therefore bounded (see `minExemptPrefix`, `maxExemptShare`);
    /// a dropped exemption only blocks that traffic, it never opens anything.
    public static func protectedTable(_ entries: [RouteEntry], tunnel: String) -> ProtectedTable {
        let usable = entries.filter { !$0.flags.contains("W") && !isIgnored($0.destination) }
        let included = Set(usable.filter { $0.interface == tunnel }.map(\.destination))
        var excluded = Set(usable.filter { e in
            e.interface != tunnel && e.destination.prefix >= minExemptPrefix
                && included.contains { $0.contains(e.destination) && $0.prefix < e.destination.prefix }
        }.map(\.destination)).subtracting(included)
        if Double(addressCount(excluded)) > Double(addressCount(included)) * maxExemptShare {
            excluded = []
        }
        return ProtectedTable(
            included: included.sorted(by: Routes.order),
            excluded: excluded.sorted(by: Routes.order)
        )
    }

    /// Upper bound of the addresses covered (overlaps counted twice).
    static func addressCount(_ networks: Set<IPv4Network>) -> UInt64 {
        networks.reduce(0) { $0 + (UInt64(1) << UInt64(32 - $1.prefix)) }
    }

    static func order(_ a: IPv4Network, _ b: IPv4Network) -> Bool {
        a.address == b.address ? a.prefix < b.prefix : a.address < b.address
    }
}

/// Destinations the VPN client routes through the tunnel. Blocked on every other path.
public struct ProtectedTable: Codable, Equatable {
    public var included: [IPv4Network]
    public var excluded: [IPv4Network]

    public init(included: [IPv4Network] = [], excluded: [IPv4Network] = []) {
        self.included = included
        self.excluded = excluded
    }

    public var isEmpty: Bool { included.isEmpty }

    /// Protection never narrows on its own: everything either table sends into the
    /// tunnel stays included. Exemptions come from `current` only, the routes the VPN
    /// client has right now; an old exemption that is gone just means more is blocked.
    /// A network the VPN now sends direct is an exemption, not an entry, since pf
    /// cannot hold both.
    public func merged(with current: ProtectedTable) -> ProtectedTable {
        let excluded = Set(current.excluded)
        return ProtectedTable(
            included: Set(included).union(current.included).subtracting(excluded).sorted(by: Routes.order),
            excluded: excluded.sorted(by: Routes.order)
        )
    }

    /// pf table entries, negations last-match by longest prefix inside pf.
    public var pfEntries: [String] {
        included.map(\.description) + excluded.map { "!" + $0.description }
    }
}

extension Routes {
    /// IPv6 prefixes that are on-link on a physical interface, from
    /// `netstat -rn -f inet6`: the home network's own prefix(es). Devices on the same
    /// Wi-Fi talk to each other over these (Continuity, iPhone Mirroring) directly,
    /// without a router, so allowing them cannot expose the public IP.
    ///
    /// Only routes whose gateway is `link#N` count; link-local, multicast and
    /// tunnel/loopback/peer-to-peer interfaces are skipped, and anything shorter than
    /// /32 is ignored so a bogus on-link default can never open the internet.
    public static func onLinkIPv6Prefixes(_ netstat: String) -> [String] {
        var result: [String] = []
        for line in netstat.split(whereSeparator: \.isNewline) {
            let f = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard f.count >= 4, f[1].hasPrefix("link#") else { continue }
            let iface = f[3]
            guard !["utun", "lo", "awdl", "llw", "gif", "stf", "anpi", "ipsec"].contains(where: { iface.hasPrefix($0) }) else { continue }
            let parts = f[0].split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 2, !parts[0].contains("%"), let prefix = Int(parts[1]), (32...128).contains(prefix),
                  let ip = IPAddress(String(parts[0])), ip.family == .v6 else { continue }
            let text = ip.description.lowercased()
            guard !text.hasPrefix("fe80"), !text.hasPrefix("ff") else { continue }
            let entry = "\(ip.description)/\(prefix)"
            if !result.contains(entry) { result.append(entry) }
        }
        return result
    }
}
