import Testing
import Foundation
@testable import FortiVPNHelper

/// Argument lists and parsers for routes and DNS. Nothing here touches the real system.
struct NetworkCommandTests {
    @Test func testRouteArgumentsAreFixedAndTakeOnlyIPv4() throws {
        #expect(RouteCommand.path == "/sbin/route")
        #expect(RouteCommand.getDefault == ["-n", "get", "default"])
        #expect(RouteCommand.deleteDefault == ["-n", "delete", "default"])
        #expect(try RouteCommand.deleteHost("198.51.100.7") == ["-n", "delete", "-host", "198.51.100.7"])
        #expect(try RouteCommand.addDefault(gateway: "192.0.2.1") == ["-n", "add", "default", "192.0.2.1"])
        for bad in ["", "default", "-net", "vpn.example.com", "192.0.2.1 -ifscope en0", "192.0.2.1\n", "192.0.2.256", "192.0.2.01"] {
            #expect(throws: NetworkFailure.self, "\(bad)") { try RouteCommand.deleteHost(bad) }
            #expect(throws: NetworkFailure.self, "\(bad)") { try RouteCommand.addDefault(gateway: bad) }
        }
    }

    /// Output of `route -n get -host` on macOS 26.7 for the three kinds of answer.
    @Test func testOnlyAHostRouteOfItsOwnCounts() throws {
        #expect(try RouteCommand.getHost("198.51.100.7") == ["-n", "get", "-host", "198.51.100.7"])
        #expect(throws: NetworkFailure.self) { try RouteCommand.getHost("198.51.100.7 -ifscope en0") }
        let loopback = """
           route to: 127.0.0.1
        destination: 127.0.0.1
          interface: lo0
              flags: <UP,HOST,DONE,LOCAL>
        """
        #expect(RouteCommand.parseOwnHostRoute(loopback, address: "127.0.0.1"))
        let userStatic = """
           route to: 198.51.100.7
        destination: 198.51.100.7
            gateway: 192.0.2.1
          interface: en0
              flags: <UP,GATEWAY,HOST,DONE,STATIC>
        """
        #expect(RouteCommand.parseOwnHostRoute(userStatic, address: "198.51.100.7"))
        // No host route: the lookup falls through to the default route.
        let viaDefault = """
           route to: 198.51.100.7
        destination: default
               mask: default
            gateway: 192.0.2.1
          interface: en0
              flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
        """
        #expect(!RouteCommand.parseOwnHostRoute(viaDefault, address: "198.51.100.7"))
        // A neighbour on the local network: cloned by the kernel, recreated on demand.
        let cloned = """
           route to: 192.0.2.1
        destination: 192.0.2.1
          interface: en0
              flags: <UP,HOST,DONE,LLINFO,WASCLONED,IFSCOPE,IFREF,ROUTER>
        """
        #expect(!RouteCommand.parseOwnHostRoute(cloned, address: "192.0.2.1"))
        #expect(!RouteCommand.parseOwnHostRoute(loopback, address: "127.0.0.2"))
        #expect(!RouteCommand.parseOwnHostRoute("destination: 127.0.0.1\n      flags: <UP,GHOST>\n", address: "127.0.0.1"))
        #expect(!RouteCommand.parseOwnHostRoute("route: writing to routing socket: not in table", address: "127.0.0.1"))
        #expect(!RouteCommand.parseOwnHostRoute("", address: "127.0.0.1"))
    }

    @Test func testWhichAddressesCanBeAGateway() {
        for address in ["198.51.100.7", "10.0.0.1", "192.168.1.1", "172.16.0.1", "1.1.1.1", "223.255.255.254", "169.254.1.1"] {
            #expect(SessionController.canBeAGateway(address), "\(address)")
        }
        for address in ["127.0.0.1", "127.255.255.254", "0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "", "vpn.example.com", "1.2.3"] {
            #expect(!SessionController.canBeAGateway(address), "\(address)")
        }
    }

    @Test func testParseDefaultRoute() {
        let wifi = """
           route to: default
        destination: default
               mask: default
            gateway: 192.0.2.1
          interface: en0
              flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
        """
        #expect(RouteCommand.parseDefault(wifi) == DefaultRoute(gateway: "192.0.2.1", interface: "en0"))
        let tunnel = """
           route to: default
        destination: default
               mask: default
          interface: ppp0
              flags: <UP,DONE,STATIC,PRCLONING>
        """
        #expect(RouteCommand.parseDefault(tunnel) == DefaultRoute(gateway: nil, interface: "ppp0"))
        #expect(RouteCommand.parseDefault("route: writing to routing socket: not in table") == nil)
        #expect(RouteCommand.parseDefault("    gateway: 192.0.2.1\n  interface: en0;rm\n") == nil)
        #expect(RouteCommand.parseDefault("    gateway: fe80::1%en0\n  interface: en0\n") == DefaultRoute(gateway: nil, interface: "en0"))
    }

    @Test func testInterfaceLine() {
        #expect(SessionController.interface(in: "INFO:   Interface ppp0 is UP.") == "ppp0")
        #expect(SessionController.interface(in: "INFO:   Interface ppp12 is UP.") == "ppp12")
        for line in ["INFO:   Interface en0 is UP.", "INFO:   Interface ppp0; is UP.", "DEBUG:  Interface ppp0 is UP.",
                     "INFO:   Interface ppp0 is UP. extra", "INFO:   Setting ppp0 interface down."] {
            #expect(SessionController.interface(in: line) == nil, "\(line)")
        }
    }

    @Test func testDNSConfiguration() throws {
        let split = try DNSConfiguration(servers: ["192.0.2.53", "192.0.2.54"], domains: ["corp.example.com"])
        #expect(split.dictionary == ["ServerAddresses": ["192.0.2.53", "192.0.2.54"],
                                     "SupplementalMatchDomains": ["corp.example.com"], "SearchDomains": ["corp.example.com"]])
        let all = try DNSConfiguration(servers: ["192.0.2.53"], domains: [])
        #expect(all.dictionary == ["ServerAddresses": ["192.0.2.53"], "SupplementalMatchDomains": [""]])
        #expect(throws: NetworkFailure.self) { try DNSConfiguration(servers: [], domains: []) }
        #expect(throws: NetworkFailure.self) { try DNSConfiguration(servers: ["192.0.2.53\nd.add"], domains: []) }
        #expect(throws: NetworkFailure.self) { try DNSConfiguration(servers: ["192.0.2.53"], domains: ["bad domain"]) }
    }

    @Test func testSystemCommandRefusesAnUntrustedPath() throws {
        let fake = try FakeInstall()
        // Owned by the test user, so not root-owned: refused before anything runs.
        #expect(throws: FileTrust.Failure.self) { _ = try SystemCommand.run(fake.install.binary, []) }
        #expect(fake.waitForReport(timeout: 0.2) == nil)
        #expect(throws: FileTrust.Failure.self) { _ = try SystemCommand.run("sbin/route", []) }
    }
}
