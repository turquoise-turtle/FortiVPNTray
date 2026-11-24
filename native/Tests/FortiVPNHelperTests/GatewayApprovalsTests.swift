import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// Gateways approved in the app after the install: who may approve, what is kept, and
/// what a new helper process reads back.
struct GatewayApprovalsTests {
    private let pin = String(repeating: "ab", count: 32)
    private let other = String(repeating: "cd", count: 32)

    private func arguments(signed: Bool = true, gateways: [AllowedGateway] = []) throws -> HelperLaunchArguments {
        try HelperLaunchArguments(allowedUID: getuid(), callerCheck: signed ? .signed(leafSHA1: String(repeating: "A", count: 40)) : .uidOnly, gateways: gateways)
    }

    private func approvals(_ temporary: TemporaryApprovalStore, signed: Bool = true, admin: Bool = true, gateways: [AllowedGateway] = []) throws -> GatewayApprovals {
        GatewayApprovals(arguments: try arguments(signed: signed, gateways: gateways), store: temporary.store, admins: FakeAdmins(admin: admin))
    }

    private func json(_ gateways: AllowedGateway...) throws -> Data {
        try GatewayApproval(gateways: gateways).json()
    }

    private func request(_ host: String = "vpn.example.com", port: Int = 443, pins: [String] = []) throws -> ConnectRequest {
        try ConnectRequest(host: host, port: port, trustedCerts: pins)
    }

    private struct AcceptingLauncher: TunnelLauncher {
        func start(_ request: ConnectRequest, sessionID: String, onEvent: @escaping @Sendable (TunnelEvent) -> Void) throws -> ProcessIdentity? { nil }
        func stop(sessionID: String) {}
    }

    private final class Box<Value: Sendable>: @unchecked Sendable {
        // @unchecked Sendable: the service replies before the call returns, on the same thread.
        var value: Value?
    }

    private func approve(_ service: HelperService, _ data: Data) -> String? {
        let box = Box<String?>()
        service.approveGateways(data) { box.value = $0 }
        return box.value ?? "no reply"
    }

    private func connect(_ service: HelperService, _ request: ConnectRequest) -> (id: String?, error: String?) {
        let box = Box<(String?, String?)>()
        service.connect(request.json()) { box.value = ($0, $1) }
        return (box.value?.0, box.value?.1 ?? (box.value == nil ? "no reply" : nil))
    }

    @Test func testUIDOnlyModeRefusesAndSaysRepair() throws {
        let temporary = try TemporaryApprovalStore()
        let approvals = try approvals(temporary, signed: false)
        #expect(throws: GatewayApprovals.uidOnlyRefusal) { try approvals.approve(try json(try AllowedGateway(host: "vpn.example.com", port: 443))) }
        #expect(GatewayApprovals.uidOnlyRefusal.description.contains("Repair / Reinstall Helper"))
        #expect(!approvals.allows(try request()))
        #expect(!temporary.exists)
    }

    @Test func testAUserWhoIsNotAnAdministratorIsRefused() throws {
        let temporary = try TemporaryApprovalStore()
        let approvals = try approvals(temporary, admin: false)
        #expect(throws: GatewayApprovals.notAdminRefusal) { try approvals.approve(try json(try AllowedGateway(host: "vpn.example.com", port: 443))) }
        #expect(!approvals.allows(try request()))
        #expect(!temporary.exists)
    }

    @Test func testTheAllowedUserIsTheOneCheckedForAdmin() throws {
        final class Recorder: AdminMembership, @unchecked Sendable {
            // @unchecked Sendable: used from the test's thread only.
            var asked: [uid_t] = []
            func isAdmin(uid: uid_t) -> Bool { asked.append(uid); return true }
        }
        let recorder = Recorder()
        let approvals = GatewayApprovals(arguments: try HelperLaunchArguments(allowedUID: 4242, callerCheck: .signed(leafSHA1: String(repeating: "A", count: 40))),
                                         store: try TemporaryApprovalStore().store, admins: recorder)
        try approvals.approve(try json(try AllowedGateway(host: "vpn.example.com", port: 443)))
        #expect(recorder.asked == [4242])
    }

    @Test func testAnApprovalIsKeptInARootOnlyFile() throws {
        let temporary = try TemporaryApprovalStore()
        let approvals = try approvals(temporary)
        #expect(!approvals.allows(try request(pins: [pin])))
        try approvals.approve(try json(try AllowedGateway(host: "VPN.example.com", port: 443, trustedCerts: [pin])))
        #expect(approvals.allows(try request(pins: [pin])))
        #expect(approvals.allows(try request()))
        #expect(!approvals.allows(try request(pins: [other])), "only the approved pin")
        #expect(!approvals.allows(try request(port: 8443)))
        #expect(!approvals.allows(try request("vpn.attacker.example")))
        var info = stat()
        #expect(lstat(temporary.store.path, &info) == 0 && info.st_mode & 0o7777 == 0o600 && info.st_mode & S_IFMT == S_IFREG)
        #expect(lstat(temporary.store.directory.path, &info) == 0 && info.st_mode & 0o7777 == 0o700)
        #expect(try FileManager.default.contentsOfDirectory(atPath: temporary.store.directory.path) == [ApprovalStore.fileName], "no temporary file left")
        #expect(try temporary.store.load() == [try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: [pin])])
    }

    /// A new helper process, as after a restart: it reads the file and connects.
    @Test func testStoredApprovalsSurviveANewHelperAndLetAConnectThrough() throws {
        let temporary = try TemporaryApprovalStore()
        let first = HelperService(mode: .signed, sessions: SessionController(launcher: AcceptingLauncher()), approvals: try approvals(temporary))
        #expect(connect(first, try request(pins: [pin])).error == HelperRefusal.gatewayNotApproved)
        #expect(!temporary.exists, "a refused connect approves nothing")
        #expect(approve(first, try json(try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: [pin]))) == nil)

        let sessions = SessionController(launcher: AcceptingLauncher())
        let second = HelperService(mode: .signed, sessions: sessions, approvals: try approvals(temporary))
        #expect(connect(second, try request("vpn.attacker.example")).error == HelperRefusal.gatewayNotApproved)
        let connected = connect(second, try request(pins: [pin]))
        #expect(connected.error == nil && connected.id != nil)
        #expect(sessions.status().sessionID == connected.id)
    }

    @Test func testPinsMergeWithStoredAndInstallTimeOnes() throws {
        let temporary = try TemporaryApprovalStore()
        let third = String(repeating: "ef", count: 32)
        let installed = [try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: [pin])]
        let approvals = try approvals(temporary, gateways: installed)
        try approvals.approve(try json(try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: [pin, other])))
        #expect(approvals.allows(try request(pins: [pin, other])))
        try approvals.approve(try json(try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: [third])))
        #expect(approvals.allows(try request(pins: [third, pin, other])), "earlier pins stay")
        #expect(try temporary.store.load() == [try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: [other, third])],
                "the install-time pin is not repeated in the file")
        // Another gateway gets an entry of its own, without the first one's pins.
        try approvals.approve(try json(try AllowedGateway(host: "vpn2.example.com", port: 10443)))
        #expect(approvals.allows(try request("vpn2.example.com", port: 10443)))
        #expect(!approvals.allows(try request("vpn2.example.com", port: 10443, pins: [pin])))
        #expect(try self.approvals(temporary, gateways: installed).allows(try request(pins: [third, pin, other])))
    }

    @Test func testAnInvalidOrUnsafeFileIsIgnored() throws {
        let gateway = try AllowedGateway(host: "vpn.example.com", port: 443)
        for damage in ["garbage", "unknown key", "readable by others", "link"] {
            let temporary = try TemporaryApprovalStore()
            try self.approvals(temporary).approve(try json(gateway))
            #expect(try self.approvals(temporary).allows(try request()), "\(damage): approved before the damage")
            let path = temporary.store.path
            switch damage {
            case "garbage": try Data("{\"gateways\": 1}".utf8).write(to: URL(fileURLWithPath: path))
            case "unknown key": try Data(#"{"gateways":[{"host":"vpn.example.com","port":443,"trustedCerts":[]}],"any":true}"#.utf8).write(to: URL(fileURLWithPath: path))
            case "readable by others": chmod(path, 0o644)
            default:
                let real = temporary.root + "/real.json"
                try FileManager.default.moveItem(atPath: path, toPath: real)
                try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: real)
            }
            let approvals = try self.approvals(temporary)
            #expect(!approvals.allows(try request()), "\(damage)")
            #expect(approvals.storedCount == 0, "\(damage)")
        }
    }

    @Test func testStoredApprovalsAreNotReadInUIDOnlyMode() throws {
        let temporary = try TemporaryApprovalStore()
        try approvals(temporary).approve(try json(try AllowedGateway(host: "vpn.example.com", port: 443)))
        #expect(try !approvals(temporary, signed: false).allows(try request()))
    }

    @Test func testBadApprovalsChangeNothing() throws {
        let temporary = try TemporaryApprovalStore()
        let approvals = try approvals(temporary)
        func refusal(_ data: Data) -> String? {
            do { try approvals.approve(data); return nil } catch { return error.description }
        }
        #expect(refusal(Data("x".utf8)) == GatewayApproval.Rejection.malformed.description)
        #expect(refusal(Data(#"{"gateways":[{"host":"vpn.example.com","port":443,"trustedCerts":[],"extra":1}]}"#.utf8)) == GatewayApproval.Rejection.malformed.description)
        #expect(refusal(Data(#"{"gateways":[]}"#.utf8)) == GatewayApproval.Rejection.empty.description)
        #expect(refusal(Data(count: GatewayApproval.maxEncodedSize + 1)) == GatewayApproval.Rejection.tooLarge.description)
        #expect(!temporary.exists)

        // More pins for one gateway than a connect request can carry: nothing of the approval is kept.
        let many = (0..<ConnectRequest.maxTrustedCerts).map { String(format: "%064x", $0) }
        try approvals.approve(try json(try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: many)))
        #expect(refusal(try json(try AllowedGateway(host: "new.example.com", port: 443), try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: [pin])))
                == GatewayApprovals.tooManyPinsRefusal.description)
        #expect(!approvals.allows(try request("new.example.com")))
        #expect(approvals.allows(try request(pins: many)))
    }

    @Test func testInstallTimeAndStoredGatewaysTogetherStayWithinTheLimit() throws {
        let temporary = try TemporaryApprovalStore()
        let installed = try (0..<HelperLaunchArguments.maxGateways - 1).map { try AllowedGateway(host: "vpn\($0).example.com", port: 443) }
        let approvals = try approvals(temporary, gateways: installed)
        #expect(throws: GatewayApprovals.tooManyGatewaysRefusal) {
            try approvals.approve(try json(try AllowedGateway(host: "a.example.com", port: 443), try AllowedGateway(host: "b.example.com", port: 443)))
        }
        #expect(!temporary.exists)
        // A pin for a gateway from the install adds no entry.
        try approvals.approve(try json(try AllowedGateway(host: "a.example.com", port: 443), try AllowedGateway(host: "vpn0.example.com", port: 443, trustedCerts: [pin])))
        #expect(approvals.allows(try request("vpn0.example.com", pins: [pin])))
        #expect(approvals.allows(try request("a.example.com")))
    }

    @Test func testAFailedSaveApprovesNothing() throws {
        let temporary = try TemporaryApprovalStore()
        let approvals = try approvals(temporary)
        try temporary.store.directory.prepare()
        chmod(temporary.store.directory.path, 0o755)
        #expect(throws: GatewayApprovals.Refusal.self) { try approvals.approve(try json(try AllowedGateway(host: "vpn.example.com", port: 443))) }
        #expect(!approvals.allows(try request()))
    }

    @Test func testProductionPath() {
        #expect(ApprovalStore.production.path == AppIdentity.helperApprovalsFile, "the installer removes this file")
        #expect(ApprovalStore.production.directory.owner == 0)
        #expect(ApprovalStore.production.directory.trust.trustedOwners == [0])
    }
}
