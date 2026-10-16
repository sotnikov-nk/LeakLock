import Foundation

/// What the generated ruleset lets through the tunnel, besides the always-on exceptions.
public enum FilterMode: Equatable {
    /// Nothing through any tunnel.
    case locked
    /// Only HTTP and DNS through the given tunnel, so the IP check can run.
    case verifying(tunnel: String)
    /// All traffic through the given tunnel.
    case open(tunnel: String)

    public var tunnel: String? {
        switch self {
        case .locked: return nil
        case .verifying(let t), .open(let t): return t
        }
    }
}

public enum PFRules {
    /// Endpoints used for the external IP check, tried in order. Each answers with the
    /// caller's IP as plain text. The daemon asks them over plain HTTP from a socket
    /// bound to the tunnel interface (IP_BOUND_IF), so a check can only ever leave
    /// through the tunnel being verified: never through Wi-Fi, whatever the routing
    /// table says. Plain HTTP is enough: the request travels inside the tunnel.
    public static let ipCheckEndpoints: [IPCheckEndpoint] = [
        IPCheckEndpoint(host: "api.ipify.org", path: "/"),
        IPCheckEndpoint(host: "checkip.amazonaws.com", path: "/"),
        IPCheckEndpoint(host: "icanhazip.com", path: "/"),
        IPCheckEndpoint(host: "ifconfig.me", path: "/ip"),
    ]

    public static let anchorTable = "leaklock_vpn"

    public static let lanV4 = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255",
    ]
    /// Apple Wireless Direct Link and low-latency WLAN: device-to-device only.
    public static let peerToPeerInterfaces = ["awdl0", "llw0"]
    /// Destinations that cannot leave the local link.
    public static let linkLocalV6 = ["fe80::/10", "ff02::/16"]
    public static let linkLocalV4 = ["169.254.0.0/16", "224.0.0.0/24"]

    public static let lanV6 = ["fc00::/7", "fe80::/10", "ff00::/8"]

    /// Only `utunN` names are accepted, so nothing user-controlled reaches pf syntax
    /// except validated IP addresses.
    public static func isTunnelInterface(_ name: String) -> Bool {
        guard name.hasPrefix("utun") else { return false }
        let digits = name.dropFirst(4)
        return !digits.isEmpty && digits.count <= 4 && digits.allSatisfy(\.isASCIIDigit)
    }

    /// Builds the anchor ruleset. Only outbound traffic is filtered; replies to allowed
    /// connections pass through pf state.
    ///
    /// - Parameter protected: destinations the VPN routes into the tunnel. Used with
    ///   `.vpnRoutes`; when it is nil or empty the ruleset falls back to blocking
    ///   everything (fail closed: we do not know yet what to protect).
    /// - Parameter onLinkV6: the home network's own IPv6 prefixes (see
    ///   `Routes.onLinkIPv6Prefixes`), allowed together with the LAN.
    /// - Parameter ifBoundStates: bind tunnel connections' pf states to the tunnel
    ///   interface, so packets of a connection opened through the VPN can never leave
    ///   through Wi-Fi after the tunnel drops (pf states float across interfaces by
    ///   default).
    public static func ruleset(
        mode: FilterMode, config: GuardConfig, protected: ProtectedTable? = nil, ifBoundStates: Bool = true,
        onLinkV6: [String] = []
    ) -> String {
        let states = ifBoundStates ? " keep state (if-bound)" : ""
        let scopedToRoutes = config.blockScope == .vpnRoutes && !(protected?.isEmpty ?? true)

        // Local paths pass statelessly. pf's implicit inbound pass creates no state, so
        // when a nearby device connects to the Mac (AirDrop, iPhone Mirroring, LAN
        // shares) the Mac's SYN-ACK is the first packet any rule here sees. A stateful
        // rule only matches a fresh SYN (`flags S/SA`), so the reply would fall through
        // to the block rules and the connection would be reset.
        let local = " no state"

        var lines: [String] = ["# LeakLock \(LeakLockVersion.current): generated, do not edit"]
        if scopedToRoutes, let protected {
            lines.append("table <\(anchorTable)> { \(protected.pfEntries.joined(separator: ", ")) }")
        }
        lines += [
            "pass out quick on lo0 all" + local,
            // DHCP / DHCPv6 so the Mac keeps its address on Wi-Fi/Ethernet.
            "pass out quick inet proto udp from any port 68 to any port 67",
            "pass out quick inet6 proto udp from any port 546 to any port 547",
            // Apple peer-to-peer (AirDrop, AirPlay, iPhone Mirroring, Sidecar) runs over
            // AWDL and its low-latency companion. These links only reach nearby Apple
            // devices, never a router, so nothing on them can expose the public IP.
            "pass out quick on { \(peerToPeerInterfaces.joined(separator: ", ")) } all" + local,
            // Link-local and on-link multicast (neighbor discovery, Bonjour/mDNS) never
            // leave the local segment: routers do not forward them.
            "pass out quick inet6 from any to { \(linkLocalV6.joined(separator: ", ")) }" + local,
            "pass out quick inet from any to { \(linkLocalV4.joined(separator: ", ")) }" + local,
        ]

        let servers = config.validServerIPs
        let v4 = servers.filter { $0.family == .v4 }.map(\.description)
        let v6 = servers.filter { $0.family == .v6 }.map(\.description)
        if !v4.isEmpty {
            lines.append("pass out quick inet from any to { \(v4.joined(separator: ", ")) }")
        }
        if !v6.isEmpty {
            lines.append("pass out quick inet6 from any to { \(v6.joined(separator: ", ")) }")
        }

        if config.allowDNS {
            lines.append("pass out quick proto { tcp, udp } from any to any port 53")
        }
        if config.allowLAN {
            lines.append("pass out quick inet from any to { \(lanV4.joined(separator: ", ")) }" + local)
            lines.append("pass out quick inet6 from any to { \((lanV6 + onLinkV6).joined(separator: ", ")) }" + local)
        }

        switch mode {
        case .locked:
            break
        case .verifying(let tunnel):
            // An invalid name degrades to `.locked` rather than producing bad syntax.
            // Just enough for the IP check (HTTP + DNS), bound to the tunnel like `.open`.
            if isTunnelInterface(tunnel) {
                lines.append("pass out quick on \(tunnel) inet proto tcp from any to any port 80" + states)
                lines.append("pass out quick on \(tunnel) inet proto { tcp, udp } from any to any port 53" + states)
            }
        case .open(let tunnel):
            if isTunnelInterface(tunnel) {
                lines.append("pass out quick on \(tunnel) all" + states)
            }
        }

        if scopedToRoutes {
            // Everything the VPN would carry is blocked on any other path; IPv6 is
            // blocked outright so it cannot bypass the IPv4-only tunnel routes.
            lines.append("block return out quick inet from any to <\(anchorTable)>")
            lines.append("block return out quick inet6 all")
        } else {
            lines.append("block return out quick all")
        }
        return lines.joined(separator: "\n") + "\n"
    }
}

extension PFRules {
    /// Whether existing pf states must be killed after loading `new` over `old`.
    /// pf passes packets of an existing connection without consulting the rules, so
    /// any change that closes a path must also end the connections using it. Only a
    /// pure widening (locked → verifying → open on the same tunnel, or an unchanged
    /// open tunnel) keeps them.
    ///
    /// - Parameter old: the mode currently loaded; nil after start, enabling, or when
    ///   the rules were found missing (anything could have connected meanwhile).
    public static func needsStateFlush(from old: FilterMode?, to new: FilterMode, rulesChanged: Bool) -> Bool {
        guard let old else { return true }
        switch (old, new) {
        case (.locked, .verifying), (.locked, .open):
            return false
        case (.verifying(let a), .open(let b)):
            return a != b
        case (.open(let a), .open(let b)):
            return a != b
        case (.verifying(let a), .verifying(let b)):
            return a != b || rulesChanged
        case (.locked, .locked):
            return rulesChanged
        default:
            return true
        }
    }
}

public struct IPCheckEndpoint: Equatable {
    public let host: String
    public let path: String

    public init(host: String, path: String) {
        self.host = host
        self.path = path
    }

    /// Minimal HTTP/1.1 request; `Connection: close` lets the reader stop at EOF.
    public var request: String {
        "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: LeakLock\r\nAccept: text/plain\r\nConnection: close\r\n\r\n"
    }
}

private extension Character {
    var isASCIIDigit: Bool { ("0"..."9").contains(self) }
}
