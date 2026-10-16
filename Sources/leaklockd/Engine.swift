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
    /// after the VPN goes down.
    private var learned = LearnedRoutesStore.load()
    /// A table seen while the tunnel is up, adopted only once it has stayed the same
    /// for `learnSettleSeconds` on a verified tunnel. A half-built table caught while
    /// the VPN is reconnecting would otherwise be persisted and leave the rest
    /// unprotected once the VPN goes down.
    private var candidate: (table: ProtectedTable, since: Date)?
    private var lastForcedCheck = Date.distantPast
    private let learnSettleSeconds: TimeInterval = 5
    private var verifiedTunnel: String?
    private var mismatchedTunnel: String?
    private var externalIP: String?
    private var lastCheck: Date?
    private var lastCheckError: String?
    private var consecutiveFailures = 0
    private var checkInFlight = false
    private var nextCheckAt = Date.distantPast

    /// Ruleset text last loaded into the anchor; nil when the anchor is flushed.
    private var appliedRules: String?
    private var appliedMode: FilterMode?
    private var initialized = false
    private var lastHealthCheck = Date.distantPast
    private var pfError: String?
    /// Set while the main pf ruleset bypasses our anchor and cannot be repaired.
    private var mainRulesetError: String?
    private var state: GuardState = .disabled
    private var tickScheduled = false
    /// Cleared if this pf rejects `keep state (if-bound)`.
    private var ifBoundSupported = true

    init(config: GuardConfig) {
        self.config = config
    }

    func start() {
        queue.async { self.tick() }
        routeWatcher.start(queue: queue) { [weak self] in self?.scheduleTick() }
        let t = DispatchSource.makeTimerSource(queue: queue)
        // Every second: catches lost routing events and pf tampering quickly.
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

        if let current {
            learn(Routes.protectedTable(routes, tunnel: current), tunnel: current)
        } else {
            candidate = nil
        }

        let decision = Decision.decide(
            config: config, tunnel: current,
            verifiedTunnel: verifiedTunnel, mismatchedTunnel: mismatchedTunnel
        )
        apply(decision.mode)
        state = pfError == nil && mainRulesetError == nil ? decision.state : .error

        if config.enabled, !config.validServerIPs.isEmpty, let current,
           pfError == nil, !checkInFlight, Date() >= nextCheckAt {
            startCheck(tunnel: current)
        }
    }

    private func learn(_ table: ProtectedTable, tunnel: String) {
        guard !table.isEmpty, table != learned else {
            candidate = nil
            return
        }
        let now = Date()
        guard let c = candidate, c.table == table else {
            candidate = (table, now)
            return
        }
        guard verifiedTunnel == tunnel, now.timeIntervalSince(c.since) >= learnSettleSeconds else { return }
        learned = table
        candidate = nil
        LearnedRoutesStore.save(table)
        log("learned \(table.included.count) tunnel routes, \(table.excluded.count) exclusions")
    }

    private func apply(_ mode: FilterMode?) {
        let now = Date()
        let healthDue = now.timeIntervalSince(lastHealthCheck) >= 1

        guard let mode else {
            if appliedRules != nil || !initialized {
                pf.flush()
                pf.release()
                log("protection disabled; anchor flushed")
            }
            appliedRules = nil
            appliedMode = nil
            pfError = nil
            initialized = true
            return
        }

        let onLinkV6 = config.allowLAN ? Routing.onLinkV6() : []
        var rules = PFRules.ruleset(mode: mode, config: config, protected: learned, ifBoundStates: ifBoundSupported, onLinkV6: onLinkV6)
        var mustLoad = rules != appliedRules || !initialized
        if healthDue {
            lastHealthCheck = now
            var tampered = pf.ensureEnabled()
            switch pf.checkMainRuleset(repair: mainRulesetError == nil) {
            case .ok: mainRulesetError = nil
            case .repaired: mainRulesetError = nil; tampered = true
            case .broken(let why): mainRulesetError = why
            }
            if pf.loadedRuleCount() == 0 {
                if appliedRules != nil { log("anchor rules disappeared; reloading") }
                tampered = true
            }
            if tampered {
                // Anything may have connected while the rules were off: start over.
                appliedMode = nil
                mustLoad = true
            }
        }
        guard mustLoad else { return }

        pf.ensureEnabled()
        var result = pf.load(rules)
        if !result.ok, ifBoundSupported, rules.contains("if-bound") {
            log("pf rejected if-bound states (\(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))); retrying without")
            let fallback = PFRules.ruleset(mode: mode, config: config, protected: learned, ifBoundStates: false, onLinkV6: onLinkV6)
            let retry = pf.load(fallback)
            // Only a load that works without if-bound proves the kernel lacks it; a
            // failure for any other reason must not weaken later rulesets.
            if retry.ok {
                ifBoundSupported = false
                rules = fallback
                result = retry
            }
        }
        if result.ok {
            let flush = PFRules.needsStateFlush(from: appliedMode, to: mode, rulesChanged: rules != appliedRules)
            if appliedRules != rules { log("loaded rules for mode \(mode)") }
            appliedRules = rules
            appliedMode = mode
            pfError = nil
            initialized = true
            if flush {
                pf.flushStates()
                log("pf states flushed")
            }
        } else {
            pfError = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            log("pfctl load failed: \(pfError ?? "")")
        }
    }

    // MARK: - External IP check

    private func startCheck(tunnel: String) {
        checkInFlight = true
        ExternalIP.fetch(tunnel: tunnel) { [weak self] result in
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
                    tick()
                }
                return IPCResponse(ok: true, status: makeStatus())
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
                tick()
                return IPCResponse(ok: true, status: makeStatus())
            }
        }
    }

    private func makeStatus() -> GuardStatus {
        var message = state.title(scope: config.blockScope)
        if state == .error, let why = pfError ?? mainRulesetError { message += ": \(why)" }
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
            protectedCount: config.blockScope == .vpnRoutes && !learned.isEmpty ? learned.included.count : nil
        )
    }
}
