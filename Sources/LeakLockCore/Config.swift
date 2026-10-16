import Foundation

/// What gets blocked while the VPN is not verified.
public enum BlockScope: String, Codable, CaseIterable {
    /// Only destinations the VPN client routes into the tunnel (works with split
    /// tunneling: everything else keeps going direct). IPv6 is blocked outside the
    /// tunnel so nothing bypasses the IPv4 routes.
    case vpnRoutes
    /// All traffic outside the tunnel.
    case everything
}

/// User settings, persisted by the daemon in `Paths.configFile`.
public struct GuardConfig: Codable, Equatable {
    /// Master switch. When false the pf anchor is empty and nothing is blocked.
    public var enabled: Bool
    public var blockScope: BlockScope
    /// Public IP addresses of the VPN server(s). Used twice: traffic to them is always
    /// allowed (so the VPN client can connect), and the external IP seen through the
    /// tunnel must be one of them before the tunnel is opened.
    public var vpnServerIPs: [String]
    /// Allow private/link-local/multicast destinations while the VPN is down.
    public var allowLAN: Bool
    /// Allow DNS (port 53) to any resolver while the VPN is down. Needed only when the
    /// VPN client resolves the server by host name.
    public var allowDNS: Bool
    /// How often the external IP is re-checked while the tunnel is open, in seconds.
    public var recheckIntervalSeconds: Int

    public init(
        enabled: Bool = false,
        blockScope: BlockScope = .vpnRoutes,
        vpnServerIPs: [String] = [],
        allowLAN: Bool = false,
        allowDNS: Bool = false,
        recheckIntervalSeconds: Int = 60
    ) {
        self.enabled = enabled
        self.blockScope = blockScope
        self.vpnServerIPs = vpnServerIPs
        self.allowLAN = allowLAN
        self.allowDNS = allowDNS
        self.recheckIntervalSeconds = recheckIntervalSeconds
    }

    public init(from decoder: Decoder) throws {
        // Tolerate missing keys so older config files keep loading.
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = GuardConfig()
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? d.enabled
        blockScope = try c.decodeIfPresent(BlockScope.self, forKey: .blockScope) ?? d.blockScope
        vpnServerIPs = try c.decodeIfPresent([String].self, forKey: .vpnServerIPs) ?? d.vpnServerIPs
        allowLAN = try c.decodeIfPresent(Bool.self, forKey: .allowLAN) ?? d.allowLAN
        allowDNS = try c.decodeIfPresent(Bool.self, forKey: .allowDNS) ?? d.allowDNS
        recheckIntervalSeconds = try c.decodeIfPresent(Int.self, forKey: .recheckIntervalSeconds)
            ?? d.recheckIntervalSeconds
    }

    /// Server IPs that parse as IPv4/IPv6, normalized and de-duplicated.
    public var validServerIPs: [IPAddress] {
        var seen = Set<IPAddress>()
        var result: [IPAddress] = []
        for raw in vpnServerIPs {
            guard let ip = IPAddress(raw), !seen.contains(ip) else { continue }
            seen.insert(ip)
            result.append(ip)
        }
        return result
    }

    /// Returns a copy with invalid IPs dropped and values clamped to sane ranges.
    public func sanitized() -> GuardConfig {
        var copy = self
        copy.vpnServerIPs = validServerIPs.map(\.description)
        copy.recheckIntervalSeconds = min(max(recheckIntervalSeconds, 15), 3600)
        return copy
    }
}

public enum Paths {
    public static let daemonLabel = "com.leaklock.daemon"
    public static let socketPath = "/var/run/com.leaklock.daemon.sock"
    public static let configDirectory = "/Library/Application Support/LeakLock"
    public static let configFile = configDirectory + "/config.json"
    /// Last known set of tunnel destinations, kept so they stay blocked after the VPN
    /// (and its routes) disappear.
    public static let learnedRoutesFile = configDirectory + "/learned-routes.json"
    public static let helperPath = "/Library/PrivilegedHelperTools/com.leaklock.daemon"
    public static let launchDaemonPlist = "/Library/LaunchDaemons/com.leaklock.daemon.plist"
    /// Sub-anchor of Apple's `com.apple/*`, which the stock /etc/pf.conf already
    /// evaluates, so the main ruleset never has to be edited. The numeric prefix puts
    /// it before Apple's own sub-anchors.
    public static let pfAnchor = "com.apple/050.LeakLock"
}
