import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A validated, normalized IPv4 or IPv6 address. Only values that `inet_pton`
/// accepts can be constructed, so a description is always safe to put into pf rules.
public struct IPAddress: Hashable, CustomStringConvertible {
    public enum Family { case v4, v6 }

    public let family: Family
    public let description: String

    public init?(_ raw: String) {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= 64 else { return nil }

        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            guard let s = Self.format(AF_INET, &v4, length: Int(INET_ADDRSTRLEN)) else { return nil }
            family = .v4
            description = s
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            guard let s = Self.format(AF_INET6, &v6, length: Int(INET6_ADDRSTRLEN)) else { return nil }
            family = .v6
            description = s
            return
        }
        return nil
    }

    private static func format<T>(_ af: Int32, _ addr: inout T, length: Int) -> String? {
        var buffer = [CChar](repeating: 0, count: length)
        let ok = withUnsafePointer(to: &addr) { ptr in
            inet_ntop(af, UnsafeRawPointer(ptr), &buffer, socklen_t(length)) != nil
        }
        return ok ? String(cString: buffer) : nil
    }
}
