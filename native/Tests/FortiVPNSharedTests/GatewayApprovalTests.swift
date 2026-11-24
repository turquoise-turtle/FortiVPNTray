import Testing
import Foundation
import FortiVPNShared

/// What `approveGateways` accepts and the approvals file may hold.
struct GatewayApprovalTests {
    private let pin = String(repeating: "ab", count: 32)

    private func rejection(_ json: String) -> GatewayApproval.Rejection? {
        do {
            _ = try GatewayApproval(json: Data(json.utf8))
            return nil
        } catch {
            return error
        }
    }

    @Test func testValidApprovalDecodesAndRoundTrips() throws {
        let decoded = try GatewayApproval(json: Data(#"{"gateways":[{"host":"VPN.example.com","port":443,"trustedCerts":["\#(pin)"]},{"host":"192.0.2.7","port":10443,"trustedCerts":[]}]}"#.utf8))
        #expect(decoded.gateways == [try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: [pin]), try AllowedGateway(host: "192.0.2.7", port: 10443)])
        #expect(try GatewayApproval(json: decoded.json()) == decoded)
    }

    @Test func testUnknownMissingOrBadValuesAreMalformed() {
        for json in [#"{"gateways":[{"host":"vpn.example.com","port":443,"trustedCerts":[],"extra":1}]}"#,
                     #"{"gateways":[{"host":"vpn.example.com","port":443,"trustedCerts":[]}],"replace":true}"#,
                     #"{"gateways":[{"host":"vpn.example.com","port":443}]}"#,
                     #"{"gateways":[{"host":"vpn.example.com","trustedCerts":[]}]}"#,
                     #"{"gateways":[{"host":"-c/tmp/x","port":443,"trustedCerts":[]}]}"#,
                     #"{"gateways":[{"host":"vpn.example.com","port":0,"trustedCerts":[]}]}"#,
                     #"{"gateways":[{"host":"vpn.example.com","port":"443","trustedCerts":[]}]}"#,
                     #"{"gateways":[{"host":"vpn.example.com","port":443,"trustedCerts":["AB"]}]}"#,
                     #"{"gateways":["vpn.example.com:443"]}"#,
                     #"{"gateways":{}}"#, "{}", "[]", "not json", ""] {
            #expect(rejection(json) == .malformed, "\(json)")
        }
    }

    @Test func testEmptyDuplicateTooManyAndOversizeAreRefused() throws {
        #expect(rejection(#"{"gateways":[]}"#) == .empty)
        // The same gateway twice, also when only the letter case differs.
        #expect(rejection(#"{"gateways":[{"host":"vpn.example.com","port":443,"trustedCerts":[]},{"host":"VPN.example.com","port":443,"trustedCerts":["\#(pin)"]}]}"#) == .duplicate)
        func entries(_ count: Int) -> String {
            "{\"gateways\":[" + (0..<count).map { "{\"host\":\"vpn\($0).example.com\",\"port\":443,\"trustedCerts\":[]}" }.joined(separator: ",") + "]}"
        }
        #expect(rejection(entries(HelperLaunchArguments.maxGateways)) == nil)
        #expect(rejection(entries(HelperLaunchArguments.maxGateways + 1)) == .tooMany)
        let padded = #"{"gateways":[{"host":"vpn.example.com","port":443,"trustedCerts":[]}]"# + String(repeating: " ", count: GatewayApproval.maxEncodedSize) + "}"
        #expect(rejection(padded) == .tooLarge)
        #expect(throws: GatewayApproval.Rejection.empty) { try GatewayApproval(gateways: []) }
    }

    @Test func testTheLargestApprovalFitsTheSizeLimit() throws {
        let pins = (0..<ConnectRequest.maxTrustedCerts).map { String(format: "%064x", $0) }
        let label = String(repeating: "a", count: 63)
        let gateways = try (0..<HelperLaunchArguments.maxGateways).map {
            try AllowedGateway(host: "\(label).\(label).\(label).\(String(repeating: "b", count: 55))\(String(format: "%03d", $0)).au", port: 65535, trustedCerts: pins)
        }
        #expect(gateways[0].host.utf8.count == 253)
        #expect(try GatewayApproval(gateways: gateways).json().count <= GatewayApproval.maxEncodedSize)
    }

    @Test func testVersionsAndTheSharedRefusal() {
        #expect(HelperTransport.protocolVersion == 2, "approveGateways was added")
        #expect(HelperTransport.helperVersion == "0.5.0")
        #expect(HelperRefusal.gatewayNotApproved.hasPrefix("The helper has not been approved for this gateway or for this certificate pin."))
    }

    /// The membership API against the group list the system reports for the same user.
    @Test func testSystemAdminMembershipAgreesWithTheUsersGroups() throws {
        let entry = try #require(getpwuid(getuid()))
        var count: Int32 = 64
        var groups = [Int32](repeating: 0, count: Int(count))
        #expect(getgrouplist(entry.pointee.pw_name, Int32(bitPattern: entry.pointee.pw_gid), &groups, &count) != -1)
        let inAdmin = groups.prefix(Int(count)).contains(Int32(SystemAdminMembership.adminGroupID))
        #expect(SystemAdminMembership().isAdmin(uid: getuid()) == inAdmin)
        #expect(SystemAdminMembership().isAdmin(uid: 0), "root is in admin")
        #expect(!SystemAdminMembership().isAdmin(uid: 3_999_999_999), "a user nobody knows is in no group")
    }
}
