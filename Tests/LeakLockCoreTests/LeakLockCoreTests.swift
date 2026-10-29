import XCTest
@testable import LeakLockCore

final class IPAddressTests: XCTestCase {
    func testParsesAndNormalizes() {
        XCTAssertEqual(IPAddress(" 203.0.113.10 ")?.description, "203.0.113.10")
        XCTAssertEqual(IPAddress("203.0.113.10")?.family, .v4)
        XCTAssertEqual(IPAddress("2001:DB8:0:0::1")?.description, "2001:db8::1")
        XCTAssertEqual(IPAddress("2001:db8::1")?.family, .v6)
    }

    func testRejectsGarbageAndInjection() {
        XCTAssertNil(IPAddress(""))
        XCTAssertNil(IPAddress("example.com"))
        XCTAssertNil(IPAddress("1.2.3.4 }; pass out all"))
        XCTAssertNil(IPAddress("10.0.0.0/8"))
        XCTAssertNil(IPAddress("256.1.1.1"))
    }
}

final class ConfigTests: XCTestCase {
    func testSanitizeDropsInvalidAndDuplicates() {
        let c = GuardConfig(vpnServerIPs: ["1.2.3.4", "bad", "1.2.3.4", "2001:db8::1"], recheckIntervalSeconds: 1)
            .sanitized()
        XCTAssertEqual(c.vpnServerIPs, ["1.2.3.4", "2001:db8::1"])
        XCTAssertEqual(c.recheckIntervalSeconds, 15)
        XCTAssertEqual(GuardConfig(pfCheckIntervalSeconds: 0).sanitized().pfCheckIntervalSeconds, 1)
        XCTAssertEqual(GuardConfig(pfCheckIntervalSeconds: 60).sanitized().pfCheckIntervalSeconds, 10)
    }

    func testDecodesPartialJSON() throws {
        let c = try JSONDecoder().decode(GuardConfig.self, from: Data(#"{"enabled":true}"#.utf8))
        XCTAssertTrue(c.enabled)
        XCTAssertFalse(c.allowLAN)
        XCTAssertEqual(c.recheckIntervalSeconds, 60)
        XCTAssertEqual(c.pfCheckIntervalSeconds, 1)
    }

    func testStatusRoundTrip() throws {
        let status = GuardStatus(state: .protected, config: GuardConfig(enabled: true, vpnServerIPs: ["1.2.3.4"]),
                                 routeInterface: "utun22", tunnelInterface: "utun22", externalIP: "1.2.3.4",
                                 lastCheck: Date(timeIntervalSince1970: 1_700_000_000), message: "ok")
        let data = try IPCCoding.encoder().encode(IPCResponse(ok: true, status: status))
        let back = try IPCCoding.decoder().decode(IPCResponse.self, from: data)
        XCTAssertEqual(back.status, status)
    }
}

final class PFRulesTests: XCTestCase {
    private let config = GuardConfig(enabled: true, vpnServerIPs: ["203.0.113.10", "2001:db8::1"])

    func testTunnelNames() {
        XCTAssertTrue(PFRules.isTunnelInterface("utun22"))
        XCTAssertTrue(PFRules.isTunnelInterface("utun0"))
        XCTAssertFalse(PFRules.isTunnelInterface("utun"))
        XCTAssertFalse(PFRules.isTunnelInterface("en0"))
        XCTAssertFalse(PFRules.isTunnelInterface("utun1 all"))
        XCTAssertFalse(PFRules.isTunnelInterface("utun12345"))
    }

    func testLockedAllowsOnlyExceptionsAndEndsWithBlock() {
        let rules = PFRules.ruleset(mode: .locked, config: config)
        let lines = rules.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.last, "block return out quick all")
        XCTAssertTrue(lines.contains("pass out quick inet from any to { 203.0.113.10 } no state"))
        XCTAssertTrue(lines.contains("pass out quick inet6 from any to { 2001:db8::1 } no state"))
        XCTAssertFalse(rules.contains("utun"))
        XCTAssertFalse(rules.contains("port 53"))
        XCTAssertFalse(rules.contains("192.168.0.0/16"))
    }

    func testOptionalExceptions() {
        var c = config
        c.allowLAN = true
        c.allowDNS = true
        let rules = PFRules.ruleset(mode: .locked, config: c)
        XCTAssertTrue(rules.contains("port 53"))
        XCTAssertTrue(rules.contains("192.168.0.0/16"))
        XCTAssertTrue(rules.contains("fe80::/10"))
    }

    func testVerifyingAllowsOnlyHTTPAndDNSThroughTunnel() {
        let rules = PFRules.ruleset(mode: .verifying(tunnel: "utun22"), config: config)
        XCTAssertTrue(rules.contains("pass out quick on utun22 inet proto tcp from any to any port 80 keep state (if-bound)\n"))
        XCTAssertTrue(rules.contains("pass out quick on utun22 inet proto { tcp, udp } from any to any port 53 keep state (if-bound)\n"))
        XCTAssertFalse(rules.contains("port 443"))
        XCTAssertFalse(rules.contains("pass out quick on utun22 all"))
        XCTAssertTrue(rules.hasSuffix("block return out quick all\n"))
    }

    func testOpenAllowsTunnel() {
        let rules = PFRules.ruleset(mode: .open(tunnel: "utun22"), config: config)
        XCTAssertTrue(rules.contains("pass out quick on utun22 all keep state (if-bound)"))
        XCTAssertTrue(rules.hasSuffix("block return out quick all\n"))
    }

    func testApplePeerToPeerAlwaysAllowed() {
        for mode in [FilterMode.locked, .verifying(tunnel: "utun22"), .open(tunnel: "utun22")] {
            let rules = PFRules.ruleset(mode: mode, config: config)
            XCTAssertTrue(rules.contains("pass out quick on { awdl0, llw0 } all no state\n"))
            XCTAssertTrue(rules.contains("pass out quick inet6 from any to { fe80::/10, ff02::/16 } no state\n"))
            XCTAssertTrue(rules.contains("pass out quick inet from any to { 169.254.0.0/16, 224.0.0.0/24 } no state\n"))
            // Routable LAN ranges stay behind the LAN toggle.
            XCTAssertFalse(rules.contains("192.168.0.0/16"))
        }
    }

    func testOnLinkIPv6Prefixes() {
        let netstat = """
        Routing tables

        Internet6:
        Destination                             Gateway                                 Flags               Netif Expire
        default                                 fe80::1%en0                             UGcg                  en0
        default                                 fe80::%utun0                            UGcIg               utun0
        ::1                                     ::1                                     UHL                   lo0
        2a00:1370:8170:1a2b::/64                link#11                                 UC                    en0
        2a00:1370:8170:1a2b::5                  link#11                                 UHLWI                 en0
        fd12:3456::/64                          link#11                                 UC                    en0
        fd99::/64                               link#20                                 UC                  utun3
        ::/0                                    link#11                                 UC                    en0
        fe80::%en0/64                           link#11                                 UCI                   en0
        ff02::%en0/16                           link#11                                 UmCI                  en0
        """
        XCTAssertEqual(Routes.onLinkIPv6Prefixes(netstat), ["2a00:1370:8170:1a2b::/64", "fd12:3456::/64"])

        var c = config
        c.allowLAN = true
        let rules = PFRules.ruleset(mode: .open(tunnel: "utun22"), config: c, onLinkV6: ["2a00:1370:8170:1a2b::/64"])
        XCTAssertTrue(rules.contains("pass out quick inet6 from any to { fc00::/7, fe80::/10, ff00::/8, 2a00:1370:8170:1a2b::/64 } no state\n"))
        c.allowLAN = false
        XCTAssertFalse(PFRules.ruleset(mode: .open(tunnel: "utun22"), config: c, onLinkV6: ["2a00:1370:8170:1a2b::/64"])
            .contains("2a00"))
    }

    func testStateFlushPolicy() {
        let t = "utun22"
        XCTAssertTrue(PFRules.needsStateFlush(from: nil, to: .locked, policyChanged: false))
        XCTAssertTrue(PFRules.needsStateFlush(from: nil, to: .open(tunnel: t), policyChanged: false))
        XCTAssertFalse(PFRules.needsStateFlush(from: .locked, to: .verifying(tunnel: t), policyChanged: false))
        XCTAssertFalse(PFRules.needsStateFlush(from: .verifying(tunnel: t), to: .open(tunnel: t), policyChanged: false))
        XCTAssertFalse(PFRules.needsStateFlush(from: .open(tunnel: t), to: .open(tunnel: t), policyChanged: false))
        XCTAssertFalse(PFRules.needsStateFlush(from: .locked, to: .locked, policyChanged: false))
        XCTAssertTrue(PFRules.needsStateFlush(from: .locked, to: .locked, policyChanged: true))
        XCTAssertTrue(PFRules.needsStateFlush(from: .verifying(tunnel: t), to: .locked, policyChanged: false))
        XCTAssertTrue(PFRules.needsStateFlush(from: .open(tunnel: t), to: .verifying(tunnel: t), policyChanged: false))
        XCTAssertTrue(PFRules.needsStateFlush(from: .open(tunnel: t), to: .open(tunnel: "utun23"), policyChanged: false))
        // Tightening while the tunnel stays open (e.g. "DNS без VPN" switched off) must
        // end connections opened under the old rules.
        XCTAssertTrue(PFRules.needsStateFlush(from: .open(tunnel: t), to: .open(tunnel: t), policyChanged: true))
        XCTAssertTrue(PFRules.needsStateFlush(from: .locked, to: .open(tunnel: t), policyChanged: true))
    }

    func testServerRulesSurviveStateFlush() {
        // Stateless, so the VPN client's connection is not cut by a state flush.
        let rules = PFRules.ruleset(mode: .open(tunnel: "utun22"), config: config)
        XCTAssertTrue(rules.contains("pass out quick inet from any to { 203.0.113.10 } no state\n"))
    }

    func testIPCheckEndpointsAreHostnamesOverHTTP() {
        XCTAssertFalse(PFRules.ipCheckEndpoints.isEmpty)
        for e in PFRules.ipCheckEndpoints {
            XCTAssertNil(IPAddress(e.host), "\(e.host) must be a hostname")
            XCTAssertTrue(e.request.hasPrefix("GET \(e.path) HTTP/1.1\r\nHost: \(e.host)\r\n"))
            XCTAssertTrue(e.request.hasSuffix("\r\n\r\n"))
        }
    }

    func testInvalidTunnelDegradesToLocked() {
        let rules = PFRules.ruleset(mode: .open(tunnel: "en0"), config: config)
        XCTAssertEqual(rules, PFRules.ruleset(mode: .locked, config: config))
    }
}

final class DecisionTests: XCTestCase {
    private let config = GuardConfig(enabled: true, vpnServerIPs: ["203.0.113.10"])

    private func decide(_ c: GuardConfig, route: String?, verified: String? = nil, mismatched: String? = nil)
        -> Decision.Result {
        Decision.decide(config: c, tunnel: route, verifiedTunnel: verified, mismatchedTunnel: mismatched)
    }

    func testDisabledHasNoRules() {
        XCTAssertEqual(decide(GuardConfig(), route: "en0"), .init(mode: nil, state: .disabled))
    }

    func testNoServersFailsClosed() {
        XCTAssertEqual(decide(GuardConfig(enabled: true), route: "utun22", verified: "utun22"),
                       .init(mode: .locked, state: .notConfigured))
    }

    func testPhysicalRouteIsLocked() {
        XCTAssertEqual(decide(config, route: "en0"), .init(mode: .locked, state: .noTunnel))
        XCTAssertEqual(decide(config, route: nil), .init(mode: .locked, state: .noTunnel))
    }

    func testUnverifiedTunnelOnlyVerifies() {
        XCTAssertEqual(decide(config, route: "utun22"), .init(mode: .verifying(tunnel: "utun22"), state: .verifying))
        XCTAssertEqual(decide(config, route: "utun22", verified: "utun7"),
                       .init(mode: .verifying(tunnel: "utun22"), state: .verifying))
    }

    func testMismatchStaysBlocked() {
        XCTAssertEqual(decide(config, route: "utun22", mismatched: "utun22"),
                       .init(mode: .verifying(tunnel: "utun22"), state: .ipMismatch))
    }

    func testVerifiedTunnelOpens() {
        XCTAssertEqual(decide(config, route: "utun22", verified: "utun22"),
                       .init(mode: .open(tunnel: "utun22"), state: .protected))
    }

    func testIPMatch() {
        XCTAssertTrue(Decision.ipMatches(IPAddress("203.0.113.10")!, config: config))
        XCTAssertFalse(Decision.ipMatches(IPAddress("198.51.100.1")!, config: config))
    }
}

final class ParseTests: XCTestCase {
    func testRouteInterface() {
        let out = """
           route to: 1.1.1.1
        destination: default
               mask: default
            gateway: 192.168.1.1
          interface: en0
              flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
        """
        XCTAssertEqual(Parse.routeInterface(out), "en0")
        XCTAssertNil(Parse.routeInterface("route: writing to routing socket: not in table"))
    }

    func testTrace() {
        let body = "fl=12f1\nh=1.1.1.1\nip=203.0.113.10\nts=1700000000.1\nvisit_scheme=https\n"
        XCTAssertEqual(Parse.traceIP(body)?.description, "203.0.113.10")
        XCTAssertNil(Parse.traceIP("h=1.1.1.1\n"))
    }

    func testEchoedIP() {
        XCTAssertEqual(Parse.echoedIP("198.51.100.170\n")?.description, "198.51.100.170")
        XCTAssertEqual(Parse.echoedIP("fl=1\nip=198.51.100.170\n")?.description, "198.51.100.170")
        XCTAssertNil(Parse.echoedIP("<html>blocked</html>"))
    }

    func testPfctlOutputs() {
        XCTAssertEqual(Parse.pfToken("No ALTQ support in kernel\npf enabled\nToken : 13425683981\n"), "13425683981")
        XCTAssertNil(Parse.pfToken("pfctl: pf already enabled\n"))
        XCTAssertTrue(Parse.pfEnabled("Status: Enabled for 0 days 00:01:02           Debug: Urgent\n"))
        XCTAssertFalse(Parse.pfEnabled("Status: Disabled                             Debug: Urgent\n"))
        XCTAssertTrue(Parse.mainRulesetHasAppleAnchor("scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"))
        XCTAssertFalse(Parse.mainRulesetHasAppleAnchor("scrub-anchor \"com.apple/*\" all\npass all\n"))
        // Inbound-only hook, or an outbound quick pass ahead of the hook: our rules
        // would never see outgoing packets.
        XCTAssertFalse(Parse.mainRulesetHasAppleAnchor("anchor \"com.apple/*\" in all\n"))
        XCTAssertFalse(Parse.mainRulesetHasAppleAnchor("pass out quick all flags S/SA keep state\nanchor \"com.apple/*\" all\n"))
        XCTAssertTrue(Parse.mainRulesetHasAppleAnchor("pass in quick on en0 all\npass quick on lo0 all\nanchor \"com.apple/*\" all\n"))
    }
}

final class RoutesTests: XCTestCase {
    // Real output from AmneziaVPN (Xray, split tunneling) on macOS, plus typical
    // exclusions it adds via en0.
    private let netstat = """
    Routing tables

    Internet:
    Destination        Gateway            Flags               Netif Expire
    0/1                10.33.0.2          UGScg              utun22
    default            192.168.1.1       UGScg                 en0
    1.1.1.1            192.168.1.1       UGHS                  en0
    10.33.0.2          10.33.0.2          UHr                utun22
    127                127.0.0.1          UCS                   lo0
    127.0.0.1          127.0.0.1          UH                    lo0
    128.0/1            10.33.0.2          UGSc               utun22
    169.254            link#15            UCS                   en0      !
    192.168.1          link#15            UCS                   en0      !
    192.168.1.1/32    link#15            UCS                   en0      !
    192.168.1.1       a4:39:b3:1:2:3     UHLWIir               en0   1170
    198.51.100.170/32   192.168.1.1       UGSc                  en0
    224.0.0/4          link#15            UmCS                  en0      !
    255.255.255.255/32 link#15            UCS                   en0      !
    """

    func testParsesNetstatDestinations() {
        XCTAssertEqual(IPv4Network.parseNetstat("0/1")?.description, "0.0.0.0/1")
        XCTAssertEqual(IPv4Network.parseNetstat("128.0/1")?.description, "128.0.0.0/1")
        XCTAssertEqual(IPv4Network.parseNetstat("192.168.1")?.description, "192.168.1.0/24")
        XCTAssertEqual(IPv4Network.parseNetstat("10.33/16")?.description, "10.33.0.0/16")
        XCTAssertEqual(IPv4Network.parseNetstat("1.1.1.1")?.description, "1.1.1.1/32")
        XCTAssertEqual(IPv4Network.parseNetstat("default")?.description, "0.0.0.0/0")
        XCTAssertNil(IPv4Network.parseNetstat("fe80::1%lo0"))
        XCTAssertNil(IPv4Network.parseNetstat("Destination"))
    }

    func testFindsAmneziaTunnel() {
        let entries = Routes.parse(netstat)
        XCTAssertEqual(Routes.vpnTunnel(entries), "utun22")
        XCTAssertNil(Routes.vpnTunnel(Routes.parse("default 192.168.1.1 UGScg en0\n")))
    }

    // Incy from the App Store (Network Extension packet tunnel, Xray) with "global
    // proxy" on: a plain default route into the tunnel instead of 0/1 + 128/1, a
    // 198.18/16 interface address and many cloned host routes. The server's own
    // connection is excluded by the system, so it has no route of its own.
    private let incyNetstat = """
    Destination        Gateway            Flags               Netif Expire
    default            link#26            UCSg                utun4
    default            192.168.1.1        UGScIg                en0
    17.248.150.3       link#26            UHW3Ig              utun4     26
    149.154.167.41     link#26            UHWIig              utun4
    192.168.1          link#15            UCS                   en0      !
    198.18.0.1         198.18.0.1         UH                  utun4
    198.18.0.2         link#26            UHWIig              utun4
    224.0.0/4          link#26            UmCSI               utun4
    240.0.0.17         link#26            UHWIig              utun4
    255.255.255.255/32 link#26            UCSI                utun4
    """

    func testIncyNetworkExtensionTunnel() {
        let entries = Routes.parse(incyNetstat)
        XCTAssertEqual(Routes.vpnTunnel(entries), "utun4")
        let table = Routes.protectedTable(entries, tunnel: "utun4")
        XCTAssertEqual(table.included.map(\.description), ["0.0.0.0/0", "198.18.0.1/32"])
        XCTAssertEqual(table.excluded.map(\.description), ["192.168.1.0/24"])
        let config = GuardConfig(enabled: true, blockScope: .vpnRoutes, vpnServerIPs: ["198.51.100.170"])
        let rules = PFRules.ruleset(mode: .open(tunnel: "utun4"), config: config, protected: table)
        XCTAssertTrue(rules.contains("pass out quick inet from any to { 198.51.100.170 }"))
        XCTAssertTrue(rules.contains("pass out quick on utun4 all"))
        XCTAssertTrue(rules.contains("block return out quick inet from any to <leaklock_vpn>"))
    }

    func testTrustedClientRoutingOpensOnlyWhileVerified() {
        let table = Routes.protectedTable(Routes.parse(incyNetstat), tunnel: "utun4")
        let config = GuardConfig(enabled: true, blockScope: .vpnRoutes, vpnServerIPs: ["198.51.100.170"])
        let open = PFRules.ruleset(mode: .open(tunnel: "utun4"), config: config, protected: table, trustClient: true)
        XCTAssertTrue(open.contains("pass out quick all keep state (if-bound)"))
        let lines = open.split(separator: "\n").map(String.init)
        XCTAssertLessThan(lines.firstIndex(of: "pass out quick all keep state (if-bound)")!,
                          lines.firstIndex { $0.hasPrefix("block") }!)
        for mode in [FilterMode.locked, .verifying(tunnel: "utun4")] {
            XCTAssertFalse(PFRules.ruleset(mode: mode, config: config, protected: table, trustClient: true)
                .contains("pass out quick all keep"))
        }
        // Trust ending changes the policy, so the daemon flushes direct states.
        XCTAssertNotEqual(PFRules.ruleset(mode: .locked, config: config, protected: table, trustClient: true),
                          PFRules.ruleset(mode: .locked, config: config, protected: table))
        XCTAssertFalse(PFRules.ruleset(mode: .open(tunnel: "utun4"), config: config, protected: table)
            .contains("pass out quick all keep"))
        // Trust needs Incy itself to be the connected VPN.
        let scutil = """
        Available network connection services in the current set (*=enabled):
        * (Disconnected)   CF01C6CF-0000-0000-0000-000000000001 VPN (org.outline.macos.client) "Outline"    [VPN:org.outline.macos.client]
        * (Connected)      AAA04198-0000-0000-0000-000000000002 VPN (llc.itdev.incy) "incy"                  [VPN:llc.itdev.incy]
        """
        XCTAssertEqual(Parse.connectedVPNClients(scutil), ["llc.itdev.incy"])
        XCTAssertEqual(VPNClient.detect(scutil), .incy)
        XCTAssertEqual(VPNClient.detect(scutil.replacingOccurrences(of: "(Connected)", with: "(Disconnected)")), .amnezia)
        XCTAssertEqual(VPNClient.detect(
            "* (Connected)  ID VPN (com.example.vpn) \"x [VPN:llc.itdev.incy]\"  [VPN:com.example.vpn]\n"), .amnezia)
        XCTAssertEqual(VPNClient.detect(""), .amnezia)
        XCTAssertEqual(VPNClient.detect(
            "* (Connected)      7A77DC79-0000-0000-0000-000000000003 VPN (su.ffg.happ)  \"Happ\"  [VPN:su.ffg.happ]\n"), .happ)
        // Incy and Happ route traffic themselves; Amnezia uses system routes.
        XCTAssertTrue(VPNClient.incy.routesOwnTraffic)
        XCTAssertTrue(VPNClient.happ.routesOwnTraffic)
        XCTAssertFalse(VPNClient.amnezia.routesOwnTraffic)
        // Incy Desktop: only its root-owned Xray may go direct, and the policy differs,
        // so moving between the App Store and desktop builds flushes states.
        let desktopOpen = PFRules.ruleset(mode: .open(tunnel: "utun4"), config: config, protected: table,
                                          trustClient: true, trustedUser: "root")
        XCTAssertTrue(desktopOpen.contains("pass out quick proto { tcp, udp } from any to any user root keep state (if-bound)"))
        XCTAssertFalse(desktopOpen.contains("pass out quick all keep"))
        XCTAssertNotEqual(PFRules.ruleset(mode: .locked, config: config, protected: table,
                                          trustClient: true, trustedUser: "root"),
                          PFRules.ruleset(mode: .locked, config: config, protected: table, trustClient: true))
        let ps = """
        alice      3651 /Applications/INCY Desktop.app/Contents/MacOS/incy
        root       /Applications/INCY Desktop.app/Contents/app/resources/bin/xray run -config /var/tmp/incy-xray/config.json
        """
        XCTAssertTrue(VPNClient.incyDesktopRunning(ps))
        XCTAssertFalse(VPNClient.incyDesktopRunning(ps.replacingOccurrences(of: "root ", with: "user ")))
        XCTAssertFalse(VPNClient.incyDesktopRunning("root /usr/local/bin/xray run -config x.json\n"))
        // Config files of the test builds, with the removed switch, still load.
        let old = try! JSONDecoder().decode(GuardConfig.self, from: Data(#"{"enabled":true,"trustClientRouting":false}"#.utf8))
        XCTAssertTrue(old.enabled)
    }

    func testLearnedRoutesAreKeptPerClient() {
        let n = { (s: String) in IPv4Network(s)! }
        let amnezia = ProtectedTable(included: [n("0.0.0.0/1"), n("128.0.0.0/1")], excluded: [n("203.0.113.0/24")])
        // A 0.4.4 file holds Amnezia's routes.
        var routes = LearnedRoutes(legacy: amnezia)
        XCTAssertEqual(routes.lastClient, .amnezia)
        XCTAssertEqual(routes[.amnezia], amnezia)
        XCTAssertTrue(routes[.incy].isEmpty)
        // Incy's whole-internet table does not leak into Amnezia's.
        routes[.incy] = ProtectedTable(included: [n("0.0.0.0/0")])
        routes.lastClient = .incy
        XCTAssertEqual(routes[.amnezia], amnezia)
        let decoded = try! JSONDecoder().decode(LearnedRoutes.self, from: try! JSONEncoder().encode(routes))
        XCTAssertEqual(decoded, routes)
        XCTAssertTrue(LearnedRoutes(legacy: ProtectedTable()).tables.isEmpty)
    }

    func testMergedTableNeverNarrowsOnItsOwn() {
        let n = { (s: String) in IPv4Network(s)! }
        let full = ProtectedTable(included: [n("0.0.0.0/1"), n("128.0.0.0/1")], excluded: [n("198.51.100.170/32")])
        // Half the routes vanish on the same tunnel: the other half stays protected.
        let half = ProtectedTable(included: [n("0.0.0.0/1")], excluded: [n("198.51.100.170/32")])
        XCTAssertEqual(full.merged(with: half), full)
        // A new profile adds destinations: protected together with the old ones.
        let other = ProtectedTable(included: [n("203.0.113.0/24")])
        let both = full.merged(with: other)
        XCTAssertEqual(both.included, [n("0.0.0.0/1"), n("128.0.0.0/1"), n("203.0.113.0/24")])
        // Exemptions are the current ones only.
        XCTAssertEqual(both.excluded, [])
        // A network the VPN now sends direct becomes an exemption, never both.
        let direct = ProtectedTable(included: [n("0.0.0.0/1")], excluded: [n("203.0.113.0/24")])
        let moved = both.merged(with: direct)
        XCTAssertFalse(moved.included.contains(n("203.0.113.0/24")))
        XCTAssertEqual(moved.excluded, [n("203.0.113.0/24")])
    }

    func testProtectedTableExcludesDirectRoutes() {
        let table = Routes.protectedTable(Routes.parse(netstat), tunnel: "utun22")
        XCTAssertEqual(table.included.map(\.description), ["0.0.0.0/1", "10.33.0.2/32", "128.0.0.0/1"])
        XCTAssertEqual(table.excluded.map(\.description), [
            "1.1.1.1/32", "192.168.1.0/24", "192.168.1.1/32", "198.51.100.170/32",
        ])
        XCTAssertEqual(table.pfEntries.last, "!198.51.100.170/32")
    }

    func testHostileNetworkRoutesAreNotExempted() {
        // TunnelVision: a rogue DHCP server pushes broad routes via Wi-Fi to pull all
        // traffic off the tunnel. They must stay blocked off-tunnel.
        let rogue = netstat + "\n" + """
        0/2                192.168.1.1        UGSc                  en0
        64/2               192.168.1.1        UGSc                  en0
        128/2              192.168.1.1        UGSc                  en0
        192/2              192.168.1.1        UGSc                  en0
        """
        let table = Routes.protectedTable(Routes.parse(rogue), tunnel: "utun22")
        XCTAssertFalse(table.excluded.contains { $0.prefix < Routes.minExemptPrefix })
        XCTAssertTrue(table.excluded.contains { $0.description == "198.51.100.170/32" })

        // Many /8s covering most of the space: nothing is exempted at all.
        let many = netstat + "\n" + (1...120).map { "\($0)          192.168.1.1        UGSc                  en0" }
            .joined(separator: "\n")
        XCTAssertEqual(Routes.protectedTable(Routes.parse(many), tunnel: "utun22").excluded, [])
    }

    func testLearnedRoutesRejectBadPrefix() {
        XCTAssertNil(try? JSONDecoder().decode(IPv4Network.self, from: Data(#"{"address":0,"prefix":40}"#.utf8)))
        XCTAssertEqual(try? JSONDecoder().decode(IPv4Network.self, from: Data(#"{"address":167772160,"prefix":8}"#.utf8)),
                       IPv4Network("10.0.0.0/8"))
    }

    func testScopedRulesetBlocksOnlyTunnelRoutes() {
        let table = Routes.protectedTable(Routes.parse(netstat), tunnel: "utun22")
        let config = GuardConfig(enabled: true, blockScope: .vpnRoutes, vpnServerIPs: ["198.51.100.170"])
        let rules = PFRules.ruleset(mode: .open(tunnel: "utun22"), config: config, protected: table)
        XCTAssertTrue(rules.contains("table <leaklock_vpn> { 0.0.0.0/1, 10.33.0.2/32, 128.0.0.0/1, !1.1.1.1/32"))
        XCTAssertTrue(rules.contains("pass out quick on utun22 all"))
        XCTAssertTrue(rules.contains("block return out quick inet from any to <leaklock_vpn>"))
        XCTAssertTrue(rules.contains("block return out quick inet6 all"))
        XCTAssertFalse(rules.contains("block return out quick all"))
    }

    func testScopedRulesetWithoutLearnedRoutesFailsClosed() {
        let config = GuardConfig(enabled: true, blockScope: .vpnRoutes, vpnServerIPs: ["198.51.100.170"])
        let rules = PFRules.ruleset(mode: .locked, config: config, protected: ProtectedTable())
        XCTAssertTrue(rules.hasSuffix("block return out quick all\n"))
        XCTAssertFalse(rules.contains("table"))
    }

    func testEverythingScopeIgnoresLearnedRoutes() {
        let table = Routes.protectedTable(Routes.parse(netstat), tunnel: "utun22")
        let config = GuardConfig(enabled: true, blockScope: .everything, vpnServerIPs: ["198.51.100.170"])
        let rules = PFRules.ruleset(mode: .locked, config: config, protected: table)
        XCTAssertTrue(rules.hasSuffix("block return out quick all\n"))
    }
}

final class HTTPAndPFParseTests: XCTestCase {
    func testPlainResponse() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 15\r\n\r\n198.51.100.170\n"
        let r = Parse.httpResponse(raw)
        XCTAssertEqual(r?.status, 200)
        XCTAssertEqual(r.flatMap { Parse.echoedIP($0.body) }?.description, "198.51.100.170")
    }

    func testChunkedResponse() {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n198.51.\r\n7\r\n100.170\r\n0\r\n\r\n"
        XCTAssertEqual(Parse.httpResponse(raw)?.body, "198.51.100.170")
    }

    func testMalformedChunkSizes() {
        let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        // Used to overflow Int and crash the root daemon.
        XCTAssertNil(Parse.httpResponse(head + "7fffffffffffffff\r\n"))
        XCTAssertNil(Parse.httpResponse(head + "7fffffffffffffff\r\nabc\r\n0\r\n\r\n"))
        XCTAssertNil(Parse.httpResponse(head + "-1\r\nabc\r\n0\r\n\r\n"))
        XCTAssertNil(Parse.httpResponse(head + "ffffffffffffffffff\r\nabc\r\n"))
        XCTAssertNil(Parse.httpResponse(head + "10\r\nshort\r\n"))
        XCTAssertNil(Parse.httpResponse(head + "5\r\nabc"))
    }

    func testBadResponses() {
        XCTAssertNil(Parse.httpResponse(""))
        XCTAssertNil(Parse.httpResponse("garbage\r\n\r\n"))
        XCTAssertEqual(Parse.httpResponse("HTTP/1.1 403 Forbidden\r\n\r\nno")?.status, 403)
    }

    func testSkippedInterfaces() {
        let out = """
        all
        en0 (skip)
        lo0 (skip)
        utun22
        """
        XCTAssertEqual(Parse.skippedInterfaces(out), ["en0"])
        XCTAssertEqual(Parse.skippedInterfaces("lo0 (skip)\nen0\n"), [])
    }

    func testUpdateVersionCompare() {
        XCTAssertTrue(Updates.isNewer("0.4.10", than: "0.4.9"))
        XCTAssertTrue(Updates.isNewer("1.0", than: "0.9.9"))
        XCTAssertFalse(Updates.isNewer("1.0", than: "1.0.0"))
        XCTAssertFalse(Updates.isNewer("0.4.2", than: "0.4.3"))
        XCTAssertEqual(Updates.normalizedVersion("v0.4.3"), "0.4.3")
        XCTAssertNil(Updates.normalizedVersion("v0.4.3-beta"))
        XCTAssertNil(Updates.normalizedVersion("latest"))
    }

    func testParseLatestRelease() {
        func json(tag: String = "v0.4.4", url: String, prerelease: Bool = false) -> Data {
            Data("""
            {"tag_name": "\(tag)", "html_url": "https://github.com/sotnikov-nk/LeakLock/releases/tag/\(tag)",
             "draft": false, "prerelease": \(prerelease),
             "assets": [{"name": "notes.txt", "browser_download_url": "https://github.com/sotnikov-nk/LeakLock/releases/download/\(tag)/notes.txt"},
                        {"name": "LeakLock-0.4.4.dmg", "browser_download_url": "\(url)"}]}
            """.utf8)
        }
        let good = "https://github.com/sotnikov-nk/LeakLock/releases/download/v0.4.4/LeakLock-0.4.4.dmg"
        let release = Updates.parseLatestRelease(json(url: good))
        XCTAssertEqual(release?.version, "0.4.4")
        XCTAssertEqual(release?.dmgURL.absoluteString, good)
        // Downloads from anywhere but this repository's releases are refused.
        XCTAssertNil(Updates.parseLatestRelease(json(url: "https://evil.example/LeakLock-0.4.4.dmg")))
        XCTAssertNil(Updates.parseLatestRelease(json(url: good, prerelease: true)))
        XCTAssertNil(Updates.parseLatestRelease(Data("{}".utf8)))
    }
}
