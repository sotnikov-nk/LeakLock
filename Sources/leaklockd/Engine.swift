import Foundation
import LeakLockCore

/// Owns all daemon state. Every mutation happens on `queue`.
final class Engine {
    let queue = DispatchQueue(label: "com.leaklock.engine")

    private let pf = PF()
    private let routeWatcher = RouteWatcher()
    private var timer: DispatchSourceTimer?

    private var config: GuardConfig
    private var tunnel: String?
    /// Destinations the VPN routes into the tunnel; persisted so they stay blocked
    /// after the VPN goes down. Never narrows on its own (see `ProtectedTable.merged`);
    /// the user shrinks it with `resetLearnedRoutes`.
    private var learned: ProtectedTable
    /// Every client's table; `learned` is the one of `routesClient`.
    private var store: LearnedRoutes
    /// The connected client, or the last one while no tunnel is up.
    private var routesClient: VPNClient
    /// A table seen while the tunnel is up. New tunnel destinations are protected at
    /// once; its exemptions are adopted only once it has stayed the same for
    /// `learnSettleSeconds` on a verified tunnel, so a half-built table caught while
    /// the VPN is reconnecting cannot punch holes.
    private var candidate: (table: ProtectedTable, since: Date)?
    private var lastForcedCheck = Date.distantPast
    private let learnSettleSeconds: TimeInterval = 5
    private var verifiedTunnel: String?
    /// Incy is the connected VPN and the setting is on.
    private var trustedClientConnected = false
    private var mismatchedTunnel: String?
    private var externalIP: String?
    private var lastCheck: Date?
    private var lastCheckError: String?
    private var consecutiveFailures = 0
    private var checkInFlight = false
    private var nextCheckAt = Date.distantPast

    /// Ruleset text last loaded into the anchor; nil when the anchor is flushed.
    private var appliedRules: String?
    /// The `.locked` rendering of the policy behind `appliedRules`: what is allowed
    /// outside the tunnel. A change means connections must be flushed.
    private var appliedPolicy: String?
    /// What pf reported for the anchor right after `appliedRules` was loaded.
    private var appliedSnapshot: String?
    private var appliedMode: FilterMode?
    /// A state flush that is required but has not succeeded yet.
    private var flushPending = false
    /// Why the loaded rules may not be enforced (pf off, unreadable, rewritten by
    /// someone else). Reported as an error until a health check clears it.
    private var enforcementError: String?
    private var lastTamperReload = Date.distantPast
    private var initialized = false
    private var lastHealthCheck = Date.distantPast
    private var pfError: String?
    /// Set while the main pf ruleset bypasses our anchor and cannot be repaired.
    private var mainRulesetError: String?
    private var state: GuardState = .disabled
    private var tickScheduled = false
    /// Last status, readable without waiting for `queue`: a tick runs several pfctl
    /// commands, and the menu should not wait for them just to show the status.
    private let statusLock = NSLock()
    private var publishedStatus: GuardStatus?

    init(config: GuardConfig) {
        self.config = config
        let loaded = LearnedRoutesStore.load()
        store = loaded
        routesClient = loaded.lastClient
        learned = loaded[loaded.lastClient]
        publishStatus()
    }

    func start() {
        queue.async { self.tick() }
        routeWatcher.start(queue: queue) { [weak self] in self?.scheduleTick() }
        let t = DispatchSource.makeTimerSource(queue: queue)
        // Every second: catches lost routing events; pf health runs on its own interval.
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    /// Coalesces bursts of routing messages into one tick.
    private func scheduleTick() {
        guard !tickScheduled else { return }
        tickScheduled = true
        queue.asyncAfter(deadline: .now() + 0.2) {
            self.tickScheduled = false
            self.tick()
        }
    }

    // MARK: - Main loop

    private func tick() {
        let routes = Routing.table()
        let current = Routes.vpnTunnel(routes)
        if current != tunnel {
            log("VPN tunnel: \(tunnel ?? "none") -> \(current ?? "none")")
            tunnel = current
        }
        // Verification belongs to one interface; a new or vanished tunnel starts over.
        if verifiedTunnel != current { verifiedTunnel = nil }
        if mismatchedTunnel != current { mismatchedTunnel = nil }

        let client = current.map { _ in VPNClient.detect(Routing.vpnServices()) }
        if let client, client != routesClient {
            log("VPN client: \(routesClient.rawValue) -> \(client.rawValue)")
            routesClient = client
            learned = store[client]
            candidate = nil
            saveLearned()
        }

        if let current {
            learn(Routes.protectedTable(routes, tunnel: current), tunnel: current)
        } else {
            candidate = nil
        }

        let trusted = config.enabled && config.trustClientRouting && client == .incy
        if trusted != trustedClientConnected {
            log("client routing \(trusted ? "trusted" : "not trusted")")
            trustedClientConnected = trusted
        }

        let decision = Decision.decide(
            config: config, tunnel: current,
            verifiedTunnel: verifiedTunnel, mismatchedTunnel: mismatchedTunnel
        )
        apply(decision.mode)
        let healthy = pfError == nil && mainRulesetError == nil && enforcementError == nil && !flushPending
        state = decision.mode == nil || healthy ? decision.state : .error

        if config.enabled, !config.validServerIPs.isEmpty, let current,
           pfError == nil, !checkInFlight, Date() >= nextCheckAt {
            startCheck(tunnel: current)
        }
        publishStatus()
    }

    private func learn(_ table: ProtectedTable, tunnel: String) {
        guard !table.isEmpty else {
            candidate = nil
            return
        }
        // Widening is always safe: protect new tunnel destinations right away, keeping
        // the exemptions we already trust. Not from a tunnel whose exit IP is known to
        // be someone else's (another VPN): its routes are not ours to keep blocking.
        let grown = learned.merged(with: ProtectedTable(included: table.included, excluded: learned.excluded))
        if grown != learned, mismatchedTunnel != tunnel {
            learned = grown
            saveLearned()
            log("now protecting \(grown.included.count) tunnel routes")
        }
        let merged = learned.merged(with: table)
        guard merged != learned else {
            candidate = nil
            return
        }
        let now = Date()
        guard let c = candidate, c.table == table else {
            candidate = (table, now)
            return
        }
        guard verifiedTunnel == tunnel, now.timeIntervalSince(c.since) >= learnSettleSeconds else { return }
        learned = merged
        candidate = nil
        saveLearned()
        log("learned \(merged.included.count) tunnel routes, \(merged.excluded.count) exclusions")
    }

    private func saveLearned() {
        store[routesClient] = learned
        store.lastClient = routesClient
        LearnedRoutesStore.save(store)
    }

    private func apply(_ mode: FilterMode?) {
        let now = Date()
        // A little under the interval, so timer jitter does not skip a whole second.
        let healthDue = now.timeIntervalSince(lastHealthCheck) >= Double(config.pfCheckIntervalSeconds) - 0.1

        guard let mode else {
            if appliedRules != nil || !initialized {
                pf.flush()
                pf.release()
                log("protection disabled; anchor flushed")
            }
            appliedRules = nil
            appliedPolicy = nil
            appliedSnapshot = nil
            appliedMode = nil
            pfError = nil
            enforcementError = nil
            flushPending = false
            initialized = true
            return
        }

        let onLinkV6 = config.allowLAN ? Routing.onLinkV6() : []
        // The setting only counts while a trusted client is connected; its change also
        // changes `policy`, so connections are flushed when trust ends.
        var enforced = config
        enforced.trustClientRouting = trustedClientConnected
        let rules = PFRules.ruleset(mode: mode, config: enforced, protected: learned, onLinkV6: onLinkV6)
        let policy = PFRules.ruleset(mode: .locked, config: enforced, protected: learned, onLinkV6: onLinkV6)
        var mustLoad = rules != appliedRules || !initialized
        if healthDue {
            lastHealthCheck = now
            var problem: String?
            let pfState = pf.ensureEnabled()
            var tampered = pfState.tampered
            if !pfState.enabled { problem = "pf выключен и не включается" }
            switch pf.checkMainRuleset(repair: mainRulesetError == nil) {
            case .ok: mainRulesetError = nil
            case .repaired: mainRulesetError = nil; tampered = true
            case .broken(let why): mainRulesetError = why
            }
            if appliedRules != nil {
                // Not just "some rules are loaded": exactly ours, with the table intact.
                switch pf.anchorSnapshot() {
                case nil:
                    problem = problem ?? "не удаётся прочитать правила pf"
                case let snapshot? where snapshot != appliedSnapshot:
                    log("anchor rules or table changed behind our back; reloading")
                    tampered = true
                default:
                    break
                }
            }
            if tampered {
                mustLoad = true
                if now.timeIntervalSince(lastTamperReload) < 5 {
                    // Changed again right after a reload: something keeps rewriting pf.
                    // Keep reloading, but do not cut every connection each second.
                    problem = problem ?? "правила LeakLock в pf постоянно меняет другая программа"
                } else {
                    // Anything may have connected while the rules were off: start over.
                    appliedMode = nil
                }
                lastTamperReload = now
            }
            enforcementError = problem
        }

        if mustLoad {
            pf.ensureEnabled()
            // No fallback without `keep state (if-bound)`: macOS pf supports it, and
            // without it tunnel connections could carry on over Wi-Fi. If pf rejects
            // the rules, the previous ones stay loaded and the menu shows the error.
            let result = pf.load(rules)
            if result.ok {
                if PFRules.needsStateFlush(from: appliedMode, to: mode, policyChanged: policy != appliedPolicy) {
                    flushPending = true
                }
                if appliedRules != rules { log("loaded rules for mode \(mode)") }
                appliedRules = rules
                appliedPolicy = policy
                appliedMode = mode
                appliedSnapshot = pf.anchorSnapshot()
                pfError = nil
                initialized = true
            } else {
                pfError = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
                log("pfctl load failed: \(pfError ?? "")")
            }
        }

        if flushPending {
            if pf.flushStates() {
                flushPending = false
                log("pf states flushed")
            } else {
                log("pfctl -F states failed; will retry")
            }
        }
    }

    // MARK: - External IP check

    private func startCheck(tunnel: String) {
        checkInFlight = true
        let config = self.config
        ExternalIP.fetch(tunnel: tunnel, accept: { Decision.ipMatches($0, config: config) }) { [weak self] result in
            guard let self else { return }
            self.queue.async { self.finishCheck(tunnel: tunnel, result: result) }
        }
    }

    private func finishCheck(tunnel: String, result: Result<IPAddress, ExternalIP.Failure>) {
        checkInFlight = false
        let now = Date()
        lastCheck = now

        // The route moved while we were checking: the answer says nothing about the
        // current path.
        guard Routes.vpnTunnel(Routing.table()) == tunnel else {
            nextCheckAt = .distantPast
            tick()
            return
        }

        switch result {
        case .success(let ip):
            externalIP = ip.description
            lastCheckError = nil
            consecutiveFailures = 0
            if Decision.ipMatches(ip, config: config) {
                if verifiedTunnel != tunnel { log("tunnel \(tunnel) verified, exit IP \(ip)") }
                verifiedTunnel = tunnel
                mismatchedTunnel = nil
                nextCheckAt = now.addingTimeInterval(TimeInterval(config.recheckIntervalSeconds))
            } else {
                if mismatchedTunnel != tunnel { log("tunnel \(tunnel) exit IP \(ip) is not a VPN server IP") }
                verifiedTunnel = nil
                mismatchedTunnel = tunnel
                nextCheckAt = now.addingTimeInterval(15)
            }
        case .failure(let error):
            consecutiveFailures += 1
            lastCheckError = error.description
            log("IP check failed (\(consecutiveFailures)): \(error)")
            // An already verified tunnel survives brief hiccups; three misses in a row
            // close it again.
            if verifiedTunnel == tunnel, consecutiveFailures >= 3 {
                verifiedTunnel = nil
                log("tunnel \(tunnel) closed after repeated IP check failures")
            }
            nextCheckAt = now.addingTimeInterval(verifiedTunnel == nil ? 5 : 10)
        }
        tick()
    }

    // MARK: - IPC

    func handle(_ request: IPCRequest, peerIsAdmin: Bool) -> IPCResponse {
        if request.command == .status {
            return IPCResponse(ok: true, status: currentStatus())
        }
        // Changes only update the engine's state here; the tick that applies them runs
        // right after on `queue`, so the reply does not wait for pfctl.
        return queue.sync { () -> IPCResponse in
            switch request.command {
            case .status:
                return IPCResponse(ok: true, status: makeStatus())
            case .recheck:
                // Anyone may ask; at most one forced check every few seconds.
                let now = Date()
                if now.timeIntervalSince(lastForcedCheck) >= 3 {
                    lastForcedCheck = now
                    nextCheckAt = .distantPast
                    queue.async { self.tick() }
                }
                return IPCResponse(ok: true, status: makeStatus())
            case .resetLearnedRoutes:
                guard peerIsAdmin else {
                    return IPCResponse(ok: false, error: "Менять настройки может только администратор Mac.")
                }
                learned = ProtectedTable()
                candidate = nil
                saveLearned()
                log("learned routes of \(routesClient.rawValue) reset")
                queue.async { self.tick() }
                return IPCResponse(ok: true, status: publishStatus())
            case .setConfig:
                guard peerIsAdmin else {
                    return IPCResponse(ok: false, error: "Менять настройки может только администратор Mac.")
                }
                guard let newConfig = request.config?.sanitized() else {
                    return IPCResponse(ok: false, error: "Нет настроек в запросе.")
                }
                do {
                    try ConfigStore.save(newConfig)
                } catch {
                    return IPCResponse(ok: false, error: "Не удалось сохранить настройки: \(error.localizedDescription)")
                }
                if newConfig.validServerIPs != config.validServerIPs {
                    verifiedTunnel = nil
                    mismatchedTunnel = nil
                    nextCheckAt = .distantPast
                }
                config = newConfig
                log("config updated: enabled=\(config.enabled) servers=\(config.vpnServerIPs) lan=\(config.allowLAN) dns=\(config.allowDNS)")
                queue.async { self.tick() }
                return IPCResponse(ok: true, status: publishStatus())
            }
        }
    }

    private func currentStatus() -> GuardStatus {
        statusLock.lock()
        defer { statusLock.unlock() }
        // Set in init, so never nil; makeStatus itself must only run on `queue`.
        return publishedStatus ?? GuardStatus(state: .error, config: GuardConfig())
    }

    @discardableResult
    private func publishStatus() -> GuardStatus {
        let status = makeStatus()
        statusLock.lock()
        publishedStatus = status
        statusLock.unlock()
        return status
    }

    private func makeStatus() -> GuardStatus {
        var message = state.title(scope: config.blockScope)
        if state == .error {
            let why = pfError ?? mainRulesetError ?? enforcementError
                ?? (flushPending ? "не удалось сбросить старые соединения" : nil)
            if let why { message += ": \(why)" }
        }
        if state == .verifying, let lastCheckError, consecutiveFailures > 0 {
            message = "Не удалось проверить IP: \(lastCheckError)"
        }
        return GuardStatus(
            state: state,
            config: config,
            routeInterface: tunnel,
            tunnelInterface: state == .protected ? verifiedTunnel : nil,
            externalIP: externalIP,
            lastCheck: lastCheck,
            message: message,
            protectedCount: config.blockScope == .vpnRoutes && !learned.isEmpty ? learned.included.count : nil,
            clientRoutingTrusted: trustedClientConnected && state == .protected,
            routesClient: routesClient
        )
    }
}
