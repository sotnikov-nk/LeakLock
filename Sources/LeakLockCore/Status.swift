import Foundation

/// What the daemon is currently enforcing.
public enum GuardState: String, Codable {
    /// Protection is off; pf anchor is empty.
    case disabled
    /// Protection is on but no VPN server IPs are configured, so the tunnel can never be
    /// verified. Everything except LAN/DNS exceptions is blocked.
    case notConfigured
    /// No tunnel interface carries the default route. Internet is blocked.
    case noTunnel
    /// A tunnel is up and its external IP is being checked. Internet is blocked.
    case verifying
    /// The tunnel's external IP is not one of the VPN server IPs. Internet is blocked.
    case ipMismatch
    /// The tunnel is verified; traffic is allowed only through it.
    case protected
    /// pf could not be configured. The last successfully loaded rules stay in place.
    case error

    /// True when ordinary internet traffic is allowed.
    public var isOpen: Bool { self == .protected || self == .disabled }
}

public struct GuardStatus: Codable, Equatable {
    public var state: GuardState
    public var config: GuardConfig
    /// The VPN client's tunnel interface, e.g. `utun22`, when one is up.
    public var routeInterface: String?
    /// Tunnel interface currently trusted (only in `.protected`).
    public var tunnelInterface: String?
    /// External IP returned by the last successful check.
    public var externalIP: String?
    public var lastCheck: Date?
    /// Human-readable detail in Russian for the menu.
    public var message: String
    /// Number of learned tunnel routes that are blocked outside the tunnel
    /// (`.vpnRoutes` only).
    public var protectedCount: Int?
    /// Whether the client's own routing is trusted right now (setting on and a trusted
    /// client connected). Optional so an app can still read an older daemon's status.
    public var clientRoutingTrusted: Bool?
    public var daemonVersion: String

    public init(
        state: GuardState,
        config: GuardConfig,
        routeInterface: String? = nil,
        tunnelInterface: String? = nil,
        externalIP: String? = nil,
        lastCheck: Date? = nil,
        message: String = "",
        protectedCount: Int? = nil,
        clientRoutingTrusted: Bool? = nil,
        daemonVersion: String = LeakLockVersion.current
    ) {
        self.state = state
        self.config = config
        self.routeInterface = routeInterface
        self.tunnelInterface = tunnelInterface
        self.externalIP = externalIP
        self.lastCheck = lastCheck
        self.message = message
        self.protectedCount = protectedCount
        self.clientRoutingTrusted = clientRoutingTrusted
        self.daemonVersion = daemonVersion
    }
}

// MARK: - IPC

/// One JSON object per line over the daemon's Unix socket.
public struct IPCRequest: Codable {
    public enum Command: String, Codable {
        case status
        case setConfig
        case recheck
        /// Forget the learned tunnel routes (admin only). Protection never narrows on
        /// its own, so this is how a smaller split-tunnel list takes effect.
        case resetLearnedRoutes
    }

    public var command: Command
    public var config: GuardConfig?

    public init(command: Command, config: GuardConfig? = nil) {
        self.command = command
        self.config = config
    }
}

public struct IPCResponse: Codable {
    public var ok: Bool
    public var error: String?
    public var status: GuardStatus?

    public init(ok: Bool, error: String? = nil, status: GuardStatus? = nil) {
        self.ok = ok
        self.error = error
        self.status = status
    }
}

public enum IPCCoding {
    public static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }

    public static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}
