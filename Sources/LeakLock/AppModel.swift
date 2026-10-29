import AppKit
import Foundation
import ServiceManagement
import SwiftUI
import LeakLockCore

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var status: GuardStatus?
    @Published private(set) var daemonReachable = false
    @Published private(set) var helperInstalled = HelperInstaller.isInstalled
    @Published var lastError: String?
    @Published private(set) var busy = false

    private var timer: Timer?
    private var requestInFlight = false
    /// Bumped on every settings change. A reply to a request sent before the latest
    /// change carries outdated settings and is not shown.
    private var configGeneration = 0

    init() {
        if UserDefaults.standard.bool(forKey: Updater.pendingLoginItemKey) {
            UserDefaults.standard.removeObject(forKey: Updater.pendingLoginItemKey)
            try? SMAppService.mainApp.unregister()
            try? SMAppService.mainApp.register()
        }
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    // MARK: - Daemon

    func refresh() {
        // Assign only on change: every assignment redraws the menu bar item and menu.
        let installed = HelperInstaller.isInstalled
        if helperInstalled != installed { helperInstalled = installed }
        guard !requestInFlight else { return }
        send(IPCRequest(command: .status), reportErrors: false)
    }

    func recheck() {
        send(IPCRequest(command: .recheck))
    }

    func resetLearnedRoutes() {
        send(IPCRequest(command: .resetLearnedRoutes))
    }

    /// Shows the change at once and sends it to the daemon; quick repeated changes
    /// (stepper clicks) build on each other instead of on the daemon's last reply.
    func updateConfig(_ change: (inout GuardConfig) -> Void) {
        guard var config = status?.config else { return }
        change(&config)
        configGeneration += 1
        status?.config = config
        send(IPCRequest(command: .setConfig, config: config))
        // The daemon applies the change right after replying; pick up the new state.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { self.refresh() }
    }

    private func send(_ request: IPCRequest, reportErrors: Bool = true) {
        requestInFlight = true
        let generation = configGeneration
        Task.detached(priority: .userInitiated) {
            let result = Result { try DaemonClient.send(request) }
            await MainActor.run {
                self.requestInFlight = false
                switch result {
                case .success(let response):
                    if !self.daemonReachable { self.daemonReachable = true }
                    if let status = response.status, generation == self.configGeneration {
                        if self.status != status { self.status = status }
                        self.finishPendingUpdate()
                    }
                    if response.ok {
                        if reportErrors { self.lastError = nil }
                    } else {
                        self.lastError = response.error
                    }
                case .failure(let error):
                    self.daemonReachable = false
                    self.status = nil
                    if reportErrors { self.lastError = error.localizedDescription }
                }
            }
        }
    }

    // MARK: - Helper

    var helperNeedsUpdate: Bool {
        guard let version = status?.daemonVersion else { return false }
        return version != LeakLockVersion.current
    }

    /// After an app update the service still runs the old version; update it right
    /// away instead of waiting for the user to notice the button.
    private func finishPendingUpdate() {
        let key = Updater.pendingServiceUpdateKey
        guard UserDefaults.standard.bool(forKey: key) else { return }
        UserDefaults.standard.removeObject(forKey: key)
        if helperNeedsUpdate { DispatchQueue.main.async { self.installHelper() } }
    }

    func installHelper() {
        runInstaller { try HelperInstaller.install() }
    }

    func uninstallHelper() {
        runInstaller { try HelperInstaller.uninstall() }
    }

    private func runInstaller(_ body: () throws -> Void) {
        busy = true
        defer { busy = false }
        NSApp.activate(ignoringOtherApps: true)
        do {
            try body()
            lastError = nil
        } catch HelperInstaller.Failure.cancelled {
            // User closed the password prompt; nothing to report.
        } catch {
            lastError = error.localizedDescription
        }
        helperInstalled = HelperInstaller.isInstalled
        // The daemon needs a moment to open its socket.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.refresh() }
    }

    // MARK: - Launch at login

    var launchAtLogin: Bool {
        get { SMAppService.mainApp.status == .enabled }
        set {
            do {
                if newValue { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
                lastError = nil
            } catch {
                lastError = "Не удалось изменить автозапуск: \(error.localizedDescription)"
            }
            objectWillChange.send()
        }
    }

    // MARK: - Presentation

    var iconName: String {
        guard helperInstalled, daemonReachable, let state = status?.state else { return "exclamationmark.shield" }
        switch state {
        case .disabled: return "shield.slash"
        case .protected: return "checkmark.shield.fill"
        case .verifying: return "shield.lefthalf.filled"
        case .noTunnel, .ipMismatch, .notConfigured: return "xmark.shield.fill"
        case .error: return "exclamationmark.shield.fill"
        }
    }

    var tint: Color {
        guard daemonReachable, let state = status?.state else { return .orange }
        switch state {
        case .protected: return .green
        case .disabled: return .secondary
        case .verifying: return .yellow
        case .noTunnel, .ipMismatch, .notConfigured, .error: return .red
        }
    }

    var headline: String {
        if !helperInstalled { return "Служба не установлена" }
        guard daemonReachable, let status else { return "Служба не отвечает" }
        return status.state.title(scope: status.config.blockScope)
    }

    var details: [String] {
        guard let status, daemonReachable else { return [] }
        var lines: [String] = []
        if status.message != status.state.title(scope: status.config.blockScope) { lines.append(status.message) }
        lines.append("Туннель VPN: \(status.routeInterface ?? "не найден")")
        if let count = status.protectedCount { lines.append("Маршрутов VPN под защитой: \(count)") }
        if status.clientRoutingTrusted == true, let client = status.routesClient {
            lines.append("Прямые правила \(client.title) действуют")
        }
        if let ip = status.externalIP, status.state != .disabled { lines.append("Внешний IP: \(ip)") }
        if let date = status.lastCheck {
            lines.append("Проверено: \(date.formatted(date: .omitted, time: .standard))")
        }
        return lines
    }
}
