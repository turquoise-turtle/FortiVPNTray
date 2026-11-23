import Testing
import Foundation
import FortiVPNShared

struct HelperTransportTests {
    private let hash = "0123456789ABCDEF0123456789ABCDEF01234567"
    private typealias Arguments = HelperLaunchArguments

    private func expectRejected(_ arguments: [String], _ fragment: String, sourceLocation: SourceLocation = #_sourceLocation) {
        do {
            _ = try Arguments(parsing: arguments)
            Issue.record("accepted \(arguments)", sourceLocation: sourceLocation)
        } catch let error as Arguments.ParseError {
            #expect(error.description.contains(fragment), "\(error.description)", sourceLocation: sourceLocation)
        } catch {
            Issue.record(error, sourceLocation: sourceLocation)
        }
    }

    @Test func testMachServiceIsTheHelperLabel() {
        #expect(HelperTransport.machServiceName == "eu.dvad.fortivpntray.helper")
        #expect(HelperTransport.protocolVersion == 1)
    }

    @Test func testSignedArgumentsParse() throws {
        let parsed = try Arguments(parsing: ["--allowed-uid", "501", "--client-req-leaf", hash])
        #expect(parsed.allowedUID == 501)
        #expect(parsed.callerCheck == .signed(leafSHA1: hash))
        #expect(parsed.callerCheck.mode == .signed)
        // Order does not matter, and a lowercase hash is normalised.
        let swapped = try Arguments(parsing: ["--client-req-leaf", hash.lowercased(), "--allowed-uid", "501"])
        #expect(swapped == parsed)
    }

    @Test func testUIDOnlyArgumentsParse() throws {
        let parsed = try Arguments(parsing: ["--uid-only", "--allowed-uid", "502"])
        #expect(parsed.allowedUID == 502)
        #expect(parsed.callerCheck == .uidOnly)
        #expect(parsed.callerCheck.mode == .uidOnly)
    }

    @Test func testBuiltArgumentsParseBack() throws {
        let signed = try Arguments(allowedUID: 501, callerCheck: .signed(leafSHA1: hash.lowercased()))
        #expect(signed.arguments == ["--allowed-uid", "501", "--client-req-leaf", hash])
        #expect(try Arguments(parsing: signed.arguments) == signed)
        let uidOnly = try Arguments(allowedUID: 502, callerCheck: .uidOnly)
        #expect(uidOnly.arguments == ["--allowed-uid", "502", "--uid-only"])
        #expect(try Arguments(parsing: uidOnly.arguments) == uidOnly)
        #expect(throws: Arguments.ParseError.self) { try Arguments(allowedUID: 501, callerCheck: .signed(leafSHA1: "abc")) }
    }

    @Test func testNothingIsDefaulted() {
        expectRejected([], "--allowed-uid is required")
        expectRejected(["--uid-only"], "--allowed-uid is required")
        expectRejected(["--client-req-leaf", hash], "--allowed-uid is required")
        // A plist that lost its mode must not start the helper in the weaker one.
        expectRejected(["--allowed-uid", "501"], "one of --client-req-leaf or --uid-only is required")
        expectRejected(["--allowed-uid", "501", "--client-req-leaf", hash, "--uid-only"], "exclude each other")
    }

    @Test func testBadUserIDsRejected() {
        for uid in ["", "abc", "-1", "+501", "501x", " 501", "5 01", "0x1f5", "4294967296", "１２"] {
            expectRejected(["--allowed-uid", uid, "--uid-only"], "is not a user id")
        }
        expectRejected(["--uid-only", "--allowed-uid"], "needs a value")
    }

    @Test func testRootUIDRejected() {
        expectRejected(["--allowed-uid", "0", "--uid-only"], "must not be 0")
        expectRejected(["--allowed-uid", "0", "--client-req-leaf", hash], "must not be 0")
        #expect(throws: Arguments.ParseError.self) { try Arguments(allowedUID: 0, callerCheck: .uidOnly) }
        #expect(throws: Arguments.ParseError.self) { try Arguments(allowedUID: 0, callerCheck: .signed(leafSHA1: hash)) }
    }

    @Test func testBadHashesRejected() {
        let bad = ["", String(hash.dropLast()), hash + "0", String(hash.dropLast()) + "G", String(hash.dropLast()) + "\"",
                   "sha1:" + String(hash.dropLast(5)), String(repeating: "é", count: 40), String(hash.dropLast()) + "\n"]
        for value in bad {
            expectRejected(["--allowed-uid", "501", "--client-req-leaf", value], "is not a 40-digit SHA-1")
        }
        expectRejected(["--allowed-uid", "501", "--client-req-leaf"], "needs a value")
    }

    @Test func testUnknownAndRepeatedArgumentsRejected() {
        expectRejected(["--allowed-uid", "501", "--uid-only", "--verbose"], "unknown argument: --verbose")
        expectRejected(["--allowed-uid", "501", "--uid-only", "extra"], "unknown argument: extra")
        expectRejected(["--allowed-uid=501", "--uid-only"], "unknown argument")
        expectRejected(["--allowed-uid", "501", "--allowed-uid", "502", "--uid-only"], "given twice")
        expectRejected(["--allowed-uid", "501", "--uid-only", "--uid-only"], "given twice")
        expectRejected(["--allowed-uid", "501", "--client-req-leaf", hash, "--client-req-leaf", hash], "given twice")
    }

    // MARK: Approved gateways

    private let pinA = String(repeating: "a1", count: 32)
    private let pinB = String(repeating: "b2", count: 32)

    @Test func testGatewayArgumentRoundTrip() throws {
        let plain = try AllowedGateway(host: "vpn.example.com", port: 10443)
        #expect(plain.argument == "vpn.example.com:10443")
        #expect(try AllowedGateway(parsing: plain.argument) == plain)
        let pinned = try AllowedGateway(host: "VPN.Example.com", port: 443, trustedCerts: [pinA, pinB, pinA])
        #expect(pinned.host == "vpn.example.com")
        #expect(pinned.trustedCerts == [pinA, pinB])
        #expect(pinned.argument == "vpn.example.com:443,\(pinA),\(pinB)")
        #expect(try AllowedGateway(parsing: pinned.argument) == pinned)
        #expect(try AllowedGateway(parsing: "192.0.2.10:8443").host == "192.0.2.10")
    }

    @Test func testGatewayArgumentRejectsAnythingElse() {
        for text in ["", "vpn.example.com", "vpn.example.com:", ":443", "vpn.example.com:0", "vpn.example.com:65536", "vpn.example.com:+443",
                     "vpn.example.com:0443", "vpn.example.com:443:1", "VPN.example.com:443", "-c/tmp/x:443", "vpn.example.com:443,",
                     "vpn.example.com:443,abc", "vpn.example.com:443,\(pinA.uppercased())", "vpn.example.com:443,\(pinA),\(pinA)",
                     "vpn.example.com:443 ", "vpn.example.com:443\n", "vpn.exa mple.com:443", "vpn.example.com:443,\(pinA) "] {
            #expect(throws: AllowedGateway.Invalid.self, "\(text)") { try AllowedGateway(parsing: text) }
        }
        #expect(throws: AllowedGateway.Invalid.self) { try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: Array(repeating: pinA, count: 17)) }
    }

    @Test func testGatewayAllowsOnlyItsOwnHostPortAndPins() throws {
        let gateway = try AllowedGateway(host: "vpn.example.com", port: 10443, trustedCerts: [pinA])
        func request(_ host: String, _ port: Int, _ pins: [String] = []) throws -> ConnectRequest {
            try ConnectRequest(host: host, port: port, trustedCerts: pins)
        }
        #expect(gateway.allows(try request("vpn.example.com", 10443)))
        #expect(gateway.allows(try request("VPN.EXAMPLE.COM", 10443, [pinA])))
        #expect(!gateway.allows(try request("vpn.example.com", 443)))
        #expect(!gateway.allows(try request("vpn.example.org", 10443)))
        #expect(!gateway.allows(try request("evil.vpn.example.com", 10443)))
        #expect(!gateway.allows(try request("vpn.example.com", 10443, [pinB])), "a pin the helper was not given")
        #expect(!gateway.allows(try request("vpn.example.com", 10443, [pinA, pinB])))
        // No approved pin: the system's trust store decides, and no pin may be added.
        let unpinned = try AllowedGateway(host: "vpn.example.com", port: 10443)
        #expect(unpinned.allows(try request("vpn.example.com", 10443)))
        #expect(!unpinned.allows(try request("vpn.example.com", 10443, [pinA])))
    }

    @Test func testGatewaysAreMergedPerHostAndPort() throws {
        let merged = AllowedGateway.merged([try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: [pinA]),
                                            try AllowedGateway(host: "other.example.com", port: 443),
                                            try AllowedGateway(host: "VPN.example.com", port: 443, trustedCerts: [pinB, pinA]),
                                            try AllowedGateway(host: "vpn.example.com", port: 8443)])
        #expect(merged.map(\.argument) == ["vpn.example.com:443,\(pinA),\(pinB)", "other.example.com:443", "vpn.example.com:8443"])
    }

    @Test func testLaunchArgumentsCarryTheGateways() throws {
        let gateways = [try AllowedGateway(host: "vpn.example.com", port: 10443), try AllowedGateway(host: "b.example.com", port: 443, trustedCerts: [pinA])]
        let arguments = try HelperLaunchArguments(allowedUID: 501, callerCheck: .signed(leafSHA1: hash), gateways: gateways)
        #expect(arguments.arguments == ["--allowed-uid", "501", "--client-req-leaf", hash,
                                        "--allowed-gateway", "vpn.example.com:10443", "--allowed-gateway", "b.example.com:443,\(pinA)"])
        #expect(try HelperLaunchArguments(parsing: arguments.arguments) == arguments)
        // None given means none approved; it is never an error and never "any".
        #expect(try HelperLaunchArguments(parsing: ["--allowed-uid", "501", "--uid-only"]).gateways.isEmpty)
    }

    @Test func testLaunchArgumentsRejectBadGateways() {
        func expectRejected(_ arguments: [String], _ fragment: String) {
            do {
                _ = try HelperLaunchArguments(parsing: arguments)
                Issue.record("accepted \(arguments)")
            } catch {
                #expect(String(describing: error).contains(fragment), "\(error)")
            }
        }
        let base = ["--allowed-uid", "501", "--uid-only"]
        expectRejected(base + ["--allowed-gateway"], "needs a value")
        expectRejected(base + ["--allowed-gateway", "vpn.example.com"], "host:port")
        expectRejected(base + ["--allowed-gateway", "VPN.example.com:443"], "canonical")
        expectRejected(base + ["--allowed-gateway", "vpn.example.com:443", "--allowed-gateway", "vpn.example.com:443,\(pinA)"], "given twice")
        expectRejected(base + (1...65).flatMap { ["--allowed-gateway", "h\($0).example.com:443"] }, "more than 64")
        #expect(throws: HelperLaunchArguments.ParseError.self) {
            let twice = [try AllowedGateway(host: "vpn.example.com", port: 443), try AllowedGateway(host: "vpn.example.com", port: 443)]
            _ = try HelperLaunchArguments(allowedUID: 501, callerCheck: .uidOnly, gateways: twice)
        }
    }

    @Test func testRequirementString() {
        #expect(CallerRequirement.string(identifier: "eu.dvad.fortivpntray", leafSHA1: hash)
                == "identifier \"eu.dvad.fortivpntray\" and certificate leaf = H\"0123456789ABCDEF0123456789ABCDEF01234567\"")
        #expect(CallerRequirement.string(identifier: "eu.dvad.fortivpntray", leafSHA1: hash.lowercased())
                == CallerRequirement.string(identifier: "eu.dvad.fortivpntray", leafSHA1: hash))
    }

    @Test func testRequirementRejectsAnythingThatCouldEscapeTheString() {
        for identifier in ["", "a\" or anchor apple or identifier \"b", "a b", "a\nb", "a\\b", "a/b", "a*", "é.example"] {
            #expect(CallerRequirement.string(identifier: identifier, leafSHA1: hash) == nil, "\(identifier)")
        }
        for value in ["", String(hash.dropLast()), hash + "0", String(hash.dropLast()) + "\"", String(hash.dropLast()) + "Z"] {
            #expect(CallerRequirement.string(identifier: "eu.dvad.fortivpntray", leafSHA1: value) == nil, "\(value)")
        }
    }

    @Test func testModeTitles() {
        #expect(CallerCheckMode.signed.title == "Signed caller check")
        #expect(CallerCheckMode.uidOnly.title == "UID-only")
        #expect(CallerCheckMode(rawValue: "uid-only") == .uidOnly)
        #expect(CallerCheckMode(rawValue: "signed") == .signed)
        #expect(CallerCheckMode(rawValue: "") == nil)
    }
}
