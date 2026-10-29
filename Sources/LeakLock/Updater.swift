import AppKit
import Foundation
import ServiceManagement
import LeakLockCore

/// Checks GitHub releases and replaces the app with the DMG of the latest one.
@MainActor
final class Updater: ObservableObject {
    enum Phase: Equatable {
        case idle
        case checking
        case upToDate
        case available(ReleaseInfo)
        case installing(ReleaseInfo)
        case failed(String)
    }

    struct Failure: LocalizedError {
        let message: String
        init(_ message: String) { self.message = message }
        var errorDescription: String? { message }
    }

    /// Set right before relaunching into a new version, so that version updates the
    /// service as soon as it starts (the service is a separate binary under root).
    static let pendingServiceUpdateKey = "pendingServiceUpdate"
    /// Set when the update moves the app (LeakLock.app → Breaker.app): the login item
    /// is registered for the old path and is renewed on the next start.
    static let pendingLoginItemKey = "pendingLoginItem"

    @Published private(set) var phase: Phase = .idle
    private var timer: Timer?

    init() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in self?.check(silent: true) }
        timer = Timer.scheduledTimer(withTimeInterval: 6 * 3600, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.check(silent: true) }
        }
    }

    var available: ReleaseInfo? {
        if case .available(let release) = phase { return release }
        return nil
    }

    var busy: Bool {
        switch phase {
        case .checking, .installing: return true
        default: return false
        }
    }

    /// Silent checks (on launch and periodically) never show errors: without VPN the
    /// protection blocks GitHub, and that is expected.
    func check(silent: Bool = false) {
        guard !busy else { return }
        if silent, available != nil { return }
        if !silent { phase = .checking }
        Task {
            do {
                let release = try await Self.fetchLatest()
                phase = Updates.isNewer(release.version, than: LeakLockVersion.current) ? .available(release) : .upToDate
            } catch {
                if !silent { phase = .failed("Не удалось проверить обновления: \(error.localizedDescription)") }
            }
        }
    }

    func install(_ release: ReleaseInfo) {
        guard !busy else { return }
        phase = .installing(release)
        Task {
            do {
                let staged = try await Self.download(release)
                try Self.relaunch(into: staged)
            } catch {
                phase = .failed("Не удалось обновить: \(error.localizedDescription)")
            }
        }
    }

    private static func fetchLatest() async throws -> ReleaseInfo {
        var request = URLRequest(url: Updates.latestReleaseAPI, timeoutInterval: 20)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("LeakLock/\(LeakLockVersion.current)", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        if code == 404 { throw Failure("релизы на GitHub не найдены (репозиторий закрыт или релизов нет)") }
        guard code == 200 else { throw Failure("GitHub ответил кодом \(code)") }
        guard let release = Updates.parseLatestRelease(data) else { throw Failure("в последнем релизе нет DMG") }
        return release
    }

    /// Downloads the DMG and copies the app out of it into a temporary folder.
    private static func download(_ release: ReleaseInfo) async throws -> URL {
        let (file, response) = try await URLSession.shared.download(from: release.dmgURL)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw Failure("DMG не скачался") }
        let work = FileManager.default.temporaryDirectory.appendingPathComponent("LeakLock-update-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        let dmg = work.appendingPathComponent("LeakLock.dmg")
        try FileManager.default.moveItem(at: file, to: dmg)
        let identifier = Bundle.main.bundleIdentifier ?? "com.leaklock.app"
        let version = release.version
        do {
            return try await Task.detached {
                try Updater.stage(dmg: dmg, in: work, version: version, identifier: identifier)
            }.value
        } catch {
            try? FileManager.default.removeItem(at: work)
            throw error
        }
    }

    nonisolated private static func stage(dmg: URL, in work: URL, version: String, identifier: String) throws -> URL {
        let mount = work.appendingPathComponent("mnt")
        try run("/usr/bin/hdiutil", ["attach", dmg.path, "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mount.path])
        defer { _ = try? run("/usr/bin/hdiutil", ["detach", mount.path, "-force"]) }

        // Called LeakLock up to 0.4.4; its DMGs only have the old name.
        let name = ["Breaker.app", "LeakLock.app"].first {
            FileManager.default.fileExists(atPath: mount.appendingPathComponent($0).path)
        } ?? "Breaker.app"
        let app = work.appendingPathComponent(name)
        try run("/usr/bin/ditto", [mount.appendingPathComponent(name).path, app.path])
        let info = NSDictionary(contentsOf: app.appendingPathComponent("Contents/Info.plist"))
        guard info?["CFBundleIdentifier"] as? String == identifier,
              info?["CFBundleShortVersionString"] as? String == version
        else { throw Failure("в DMG не то приложение или не та версия") }
        try run("/usr/bin/codesign", ["--verify", "--strict", app.path])
        return app
    }

    /// Swaps the bundle once this process has exited, then starts the new version.
    /// The old bundle is moved aside first and only deleted after the new one is in
    /// place, so a failed copy leaves the current version working.
    private static func relaunch(into staged: URL) throws {
        let target = Bundle.main.bundleURL
        let fm = FileManager.default
        // An install from before the rename moves to Breaker.app next to it, unless
        // something else already has that name.
        var final = target
        if target.lastPathComponent == "LeakLock.app" {
            let renamed = target.deletingLastPathComponent().appendingPathComponent("Breaker.app")
            if !fm.fileExists(atPath: renamed.path) { final = renamed }
        }
        guard fm.isWritableFile(atPath: target.deletingLastPathComponent().path), fm.isWritableFile(atPath: target.path) else {
            throw Failure("нет прав на запись в \(target.deletingLastPathComponent().path). Установите новую версию из DMG вручную")
        }
        let script = """
        while kill -0 "$1" 2>/dev/null; do sleep 0.2; done
        NEW="$5.update"; OLD="$3.old"; APP="$3"
        rm -rf "$NEW" "$OLD"
        if /usr/bin/ditto "$2" "$NEW" && mv "$3" "$OLD"; then
            if mv "$NEW" "$5"; then rm -rf "$OLD"; APP="$5"; else mv "$OLD" "$3"; fi
        fi
        rm -rf "$NEW" "$4"
        /usr/bin/xattr -cr "$APP"
        /usr/bin/open "$APP"
        """
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [
            "-c", script, "sh",
            String(ProcessInfo.processInfo.processIdentifier), staged.path, target.path,
            staged.deletingLastPathComponent().path, final.path,
        ]
        try process.run()
        UserDefaults.standard.set(true, forKey: pendingServiceUpdateKey)
        if final != target, SMAppService.mainApp.status == .enabled {
            UserDefaults.standard.set(true, forKey: pendingLoginItemKey)
        }
        NSApp.terminate(nil)
    }

    nonisolated private static func run(_ tool: String, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw Failure("\(URL(fileURLWithPath: tool).lastPathComponent): \(text)")
        }
    }
}
