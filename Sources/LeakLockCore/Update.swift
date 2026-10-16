import Foundation

/// A published release the app can update to.
public struct ReleaseInfo: Equatable {
    /// Without the leading "v" of the tag, e.g. "0.4.3".
    public let version: String
    public let pageURL: URL
    public let dmgURL: URL
}

public enum Updates {
    public static let repository = "sotnikov-nk/LeakLock"
    public static let latestReleaseAPI = URL(string: "https://api.github.com/repos/\(repository)/releases/latest")!

    private struct GitHubRelease: Decodable {
        struct Asset: Decodable {
            let name: String
            let browser_download_url: String
        }
        let tag_name: String
        let html_url: String
        let draft: Bool?
        let prerelease: Bool?
        let assets: [Asset]
    }

    /// Parses GitHub's "latest release" response. Only a DMG attached to a release of
    /// this repository is accepted, so the download always comes from its releases.
    public static func parseLatestRelease(_ data: Data) -> ReleaseInfo? {
        guard let release = try? JSONDecoder().decode(GitHubRelease.self, from: data),
              release.draft != true, release.prerelease != true,
              let version = normalizedVersion(release.tag_name),
              let page = URL(string: release.html_url)
        else { return nil }
        let prefix = "https://github.com/\(repository)/releases/download/"
        let dmg = release.assets.first {
            $0.name.hasPrefix("LeakLock-") && $0.name.hasSuffix(".dmg") && $0.browser_download_url.hasPrefix(prefix)
        }
        guard let dmg, let url = URL(string: dmg.browser_download_url) else { return nil }
        return ReleaseInfo(version: version, pageURL: page, dmgURL: url)
    }

    /// "v0.4.3" → "0.4.3"; nil unless it is dot-separated numbers.
    public static func normalizedVersion(_ tag: String) -> String? {
        let version = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
        let parts = version.split(separator: ".", omittingEmptySubsequences: false)
        guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && Int($0) != nil }) else { return nil }
        return version
    }

    /// Numeric comparison, so 0.4.10 is newer than 0.4.9 and 1.0 equals 1.0.0.
    public static func isNewer(_ candidate: String, than current: String) -> Bool {
        func numbers(_ v: String) -> [Int] { v.split(separator: ".").map { Int($0) ?? 0 } }
        let a = numbers(candidate), b = numbers(current)
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }
}
