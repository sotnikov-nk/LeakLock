import AppKit
import Foundation
import LeakLockCore

/// Installs/removes the root LaunchDaemon with a one-time administrator password
/// prompt. No Developer ID is needed for this path.
enum HelperInstaller {
    enum Failure: LocalizedError {
        case cancelled
        case missingResources
        case script(String)

        var errorDescription: String? {
            switch self {
            case .cancelled: return "Установка отменена."
            case .missingResources: return "В приложении не найдены файлы службы. Переустановите Breaker."
            case .script(let detail): return detail
            }
        }
    }

    static var isInstalled: Bool {
        FileManager.default.fileExists(atPath: Paths.launchDaemonPlist)
            && FileManager.default.fileExists(atPath: Paths.helperPath)
    }

    static func install() throws {
        try runPrivileged(script: "install-helper.sh")
    }

    static func uninstall() throws {
        try runPrivileged(script: "uninstall-helper.sh")
    }

    private static func runPrivileged(script name: String) throws {
        guard let resources = Bundle.main.resourcePath else { throw Failure.missingResources }
        let scriptPath = resources + "/" + name
        guard FileManager.default.fileExists(atPath: scriptPath) else { throw Failure.missingResources }

        let source = """
        do shell script "/bin/sh " & quoted form of "\(escape(scriptPath))" & " " & quoted form of "\(escape(resources))" with prompt "Breaker устанавливает службу, которая управляет файрволом." with administrator privileges
        """
        var errorInfo: NSDictionary?
        guard let appleScript = NSAppleScript(source: source) else { throw Failure.script("AppleScript не создан") }
        _ = appleScript.executeAndReturnError(&errorInfo)
        if let errorInfo {
            if (errorInfo[NSAppleScript.errorNumber] as? Int) == -128 { throw Failure.cancelled }
            let message = errorInfo[NSAppleScript.errorMessage] as? String ?? "\(errorInfo)"
            throw Failure.script(message)
        }
    }

    private static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }
}
