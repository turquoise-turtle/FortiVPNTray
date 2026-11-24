import Testing
import Foundation
import LocalAuthentication
import FortiVPNShared
@testable import FortiVPNCore

/// A helper whose answers the test sets; it records what the engine asked.
final class FakeHelperAPI: HelperAPI, @unchecked Sendable {
    // @unchecked Sendable: every field is only touched while holding `lock`.
    private let lock = NSLock()
    private var _requests: [ConnectRequest] = []
    private var _disconnects = 0
    private var _logReads: [Int] = []
    var protocolVersion = HelperTransport.protocolVersion
    var helperVersion = HelperTransport.helperVersion
    var connectError: String?
    var mode = CallerCheckMode.signed
    /// The helper refuses connects as not approved until an approval succeeds (and `approvalTakesEffect`).
    var unapproved = false
    var approvalTakesEffect = true
    var approveError: String?
    private var _approvals: [[AllowedGateway]] = []
    var currentStatus = HelperStatus()
    var log: [String] = []
    var samlURL: URL?
    let sessionID = UUID().uuidString

    var requests: [ConnectRequest] { lock.withLock { _requests } }
    var disconnects: Int { lock.withLock { _disconnects } }
    var logReads: [Int] { lock.withLock { _logReads } }
    var approvals: [[AllowedGateway]] { lock.withLock { _approvals } }

    func set(_ change: (FakeHelperAPI) -> Void) { lock.withLock { change(self) } }

    func version() throws -> HelperVersion {
        lock.withLock { HelperVersion(version: helperVersion, protocolVersion: protocolVersion, mode: mode) }
    }
    func status() throws -> HelperStatus { lock.withLock { currentStatus } }
    func connect(_ request: ConnectRequest) throws -> String {
        try lock.withLock {
            _requests.append(request)
            if let connectError { throw VPNError(connectError) }
            if unapproved { throw VPNError(HelperRefusal.gatewayNotApproved) }
            currentStatus = HelperStatus(state: .connecting, sessionID: sessionID)
            return sessionID
        }
    }
    func disconnect() throws {
        lock.withLock {
            _disconnects += 1
            currentStatus = HelperStatus()
        }
    }
    func readLog(sessionID: String, offset: Int) throws -> LogChunk {
        try lock.withLock {
            _logReads.append(offset)
            guard sessionID == self.sessionID else { throw VPNError("Unknown session.") }
            // Two lines at most per read, to exercise reading on.
            let lines = Array(log.dropFirst(offset).prefix(2))
            return LogChunk(lines: lines, nextOffset: min(log.count, offset + lines.count))
        }
    }
    func pendingSAMLURL() throws -> URL? { lock.withLock { samlURL } }
    func approveGateways(_ gateways: [AllowedGateway]) throws {
        try lock.withLock {
            _approvals.append(gateways)
            if let approveError { throw VPNError(approveError) }
            if approvalTakesEffect { unapproved = false }
        }
    }
}

/// Answers the approval prompt as the test says; no prompt is ever shown.
final class FakeAuthoriser: ApprovalAuthoriser, @unchecked Sendable {
    // @unchecked Sendable: `_reasons` is only touched while holding `lock`.
    private let lock = NSLock()
    private var _reasons: [String] = []
    let answer: ApprovalAuthorisation
    var reasons: [String] { lock.withLock { _reasons } }

    init(_ answer: ApprovalAuthorisation = .approved) { self.answer = answer }

    func authorise(reason: String) async -> ApprovalAuthorisation {
        lock.withLock { _reasons.append(reason) }
        return answer
    }
}

struct FakeAdminMembership: AdminMembership {
    var admin = true
    func isAdmin(uid: uid_t) -> Bool { admin }
}

struct VPNEngineTests {
    private func profile(realm: String? = nil) -> VPNProfile {
        var p = VPNProfile()
        p.name = "Office"; p.host = "vpn.example.com"; p.port = 10443; p.realm = realm
        p.trustedCerts = [String(repeating: "AB", count: 32)]
        return p
    }

    @Test func testStartSendsTheValidatedRequest() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        var settings = AppSettings(); settings.dnsFallback = false
        try await engine.start(profile: profile(realm: " staff "), settings: settings)
        #expect(helper.requests == [try ConnectRequest(host: "vpn.example.com", port: 10443, realm: "staff",
                                                       trustedCerts: [String(repeating: "ab", count: 32)], useSystemDNSFallback: false)])
        #expect(await engine.hasSession)
        await #expect(throws: VPNError("Disconnect the current session before reconnecting.")) {
            try await engine.start(profile: profile(), settings: AppSettings())
        }
    }

    @Test func testStartRefusesAnotherProtocolOrAFailedConnect() async throws {
        let old = FakeHelperAPI()
        old.set { $0.protocolVersion = HelperTransport.protocolVersion + 1 }
        let engine = VPNEngine(helper: old)
        await #expect(throws: VPNError.self) { try await engine.start(profile: profile(), settings: AppSettings()) }
        #expect(old.requests.isEmpty)

        let refusing = FakeHelperAPI()
        refusing.set { $0.connectError = "A session is already active." }
        let second = VPNEngine(helper: refusing)
        await #expect(throws: VPNError("A session is already active.")) { try await second.start(profile: profile(), settings: AppSettings()) }
        #expect(await !second.hasSession)
    }

    @Test func testStartAcceptsAHelperOfAnotherVersionWithTheSameProtocol() async throws {
        // Settings recommends a repair for it; connecting must keep working until then.
        let helper = FakeHelperAPI()
        helper.set { $0.helperVersion = "0.3.0" }
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        #expect(helper.requests.count == 1)
    }

    @Test func testPollReadsTheLogOnAndReportsConnectedOnce() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        helper.set { $0.log = ["INFO:   Connected to gateway.", "DEBUG:  Cookie: [redacted]", "INFO:   Tunnel is up and running."] }
        let first = try await engine.poll()
        #expect(first.lines == ["INFO:   Connected to gateway.", "DEBUG:  Cookie: [redacted]"])
        #expect(first.events.isEmpty, "the log line alone does not make the session connected")
        helper.set { $0.currentStatus = HelperStatus(state: .connected, sessionID: helper.sessionID, interface: "ppp0", vpnIP: "192.0.2.200") }
        let second = try await engine.poll()
        #expect(second.lines == ["INFO:   Tunnel is up and running."])
        #expect(second.events == [.connected("192.0.2.200")])
        #expect(try await engine.poll().events.isEmpty)
        #expect(helper.logReads == [0, 2, 3])
    }

    @Test func testSAMLURLIsOpenedOnlyIfItIsTheProfilesLoginURL() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        let good = URL(string: "https://vpn.example.com:10443/remote/saml/start?redirect=1")!
        helper.set { $0.samlURL = good }
        #expect(try await engine.poll().events == [.saml(good)])
        #expect(try await engine.poll().events.isEmpty, "opened once")

        let bad = URL(string: "https://attacker.example.net:10443/remote/saml/start?redirect=1")!
        helper.set { $0.samlURL = bad }
        let refused = try await engine.poll()
        #expect(refused.events.isEmpty)
        #expect(refused.lines == ["ERROR:  The helper offered an unexpected login URL; it was not opened."])
    }

    @Test func testSAMLLoginCheck() {
        let host = "vpn.example.com", port = 10443
        for good in ["https://vpn.example.com:10443/remote/saml/start?redirect=1",
                     "https://VPN.example.com:10443/remote/saml/start?redirect=1&realm=staff"] {
            #expect(SAMLLogin.isExpected(URL(string: good)!, host: host, port: port), "\(good)")
        }
        for bad in ["http://vpn.example.com:10443/remote/saml/start?redirect=1",
                    "https://vpn.example.com/remote/saml/start?redirect=1",
                    "https://vpn.example.com:443/remote/saml/start?redirect=1",
                    "https://vpn.example.com.attacker.example:10443/remote/saml/start",
                    "https://attacker.example@vpn.example.com:10443/remote/saml/start",
                    "https://vpn.example.com:10443/remote/saml/start/../../evil",
                    "https://vpn.example.com:10443/remote/logout",
                    "https://vpn.example.com:10443/remote/saml/start#x",
                    "file:///remote/saml/start"] {
            #expect(!SAMLLogin.isExpected(URL(string: bad)!, host: host, port: port), "\(bad)")
        }
    }

    @Test func testCertificateDigestFromTheLogBecomesAnEvent() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        let digest = String(repeating: "cd", count: 32)
        helper.set { $0.log = ["ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist.",
                               "ERROR:      --trusted-cert \(digest)"] }
        #expect(try await engine.poll().events == [.certificate(digest)])
    }

    /// The session ended in the helper: the rest of its log is read before the end is reported.
    @Test func testEndOfSessionDrainsTheLogAndReportsWhy() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        helper.set {
            $0.log = ["a", "b", "c", "d", "ERROR:  Could not authenticate to gateway."]
            $0.currentStatus = HelperStatus(lastError: "openfortivpn exited with status 1.")
        }
        let result = try await engine.poll()
        #expect(result.lines == ["a", "b", "c", "d", "ERROR:  Could not authenticate to gateway."])
        #expect(result.exitMessage == "openfortivpn exited with status 1.")
        #expect(await !engine.hasSession)
        #expect(try await engine.poll().lines.isEmpty)
    }

    @Test func testEndWithoutAnErrorAfterConnecting() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        helper.set { $0.currentStatus = HelperStatus(state: .connected, sessionID: helper.sessionID) }
        _ = try await engine.poll()
        helper.set { $0.currentStatus = HelperStatus() }
        #expect(try await engine.poll().exitMessage == "The VPN connection ended.")
    }

    @Test func testStopDisconnectsOnlyWithASession() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.stop()
        #expect(helper.disconnects == 0)
        try await engine.start(profile: profile(), settings: AppSettings())
        try await engine.stop()
        #expect(helper.disconnects == 1)
        #expect(await !engine.hasSession)
    }

    /// The app was killed or crashed while connected: the helper still runs that tunnel,
    /// and a freshly started app knows nothing about it.
    @Test func testASessionLeftBehindIsEndedBeforeANewOne() async throws {
        let helper = FakeHelperAPI()
        helper.set { $0.currentStatus = HelperStatus(state: .connected, sessionID: UUID().uuidString, interface: "ppp0") }
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        #expect(helper.disconnects == 1, "the tunnel nobody watches is ended first")
        #expect(helper.requests.count == 1)
        #expect(await engine.hasSession)
        #expect(try helper.status().sessionID == helper.sessionID)
    }

    @Test func testEndingALeftoverSessionLeavesTheAppsOwnAlone() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        // Nothing running: nothing to end.
        #expect(try await !engine.endLeftoverSession())
        #expect(helper.disconnects == 0)

        // Left behind by an earlier run of the app.
        helper.set { $0.currentStatus = HelperStatus(state: .connecting, sessionID: UUID().uuidString) }
        #expect(try await engine.endLeftoverSession())
        #expect(helper.disconnects == 1)
        #expect(try helper.status().state == .idle)

        // The app's own session is not a leftover.
        try await engine.start(profile: profile(), settings: AppSettings())
        #expect(try await !engine.endLeftoverSession())
        #expect(helper.disconnects == 1)
        #expect(await engine.hasSession)
    }

    // MARK: Approving a gateway with Touch ID

    private static let pin = String(repeating: "ab", count: 32)

    private func unapproved(_ change: (FakeHelperAPI) -> Void = { _ in }) -> FakeHelperAPI {
        let helper = FakeHelperAPI()
        helper.set { $0.unapproved = true; change($0) }
        return helper
    }

    private func failure(_ engine: VPNEngine) async -> String? {
        do {
            try await engine.start(profile: profile(), settings: AppSettings())
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    @Test func testAnUnapprovedGatewayIsApprovedWithTouchIDAndConnectedOnce() async throws {
        let helper = unapproved()
        let authoriser = FakeAuthoriser(.approved)
        let engine = VPNEngine(helper: helper, authoriser: authoriser, admins: FakeAdminMembership())
        try await engine.start(profile: profile(), settings: AppSettings())
        #expect(authoriser.reasons == ["allow its VPN helper to connect to vpn.example.com:10443 (with 1 pinned certificate)"])
        #expect(helper.approvals == [[try AllowedGateway(host: "vpn.example.com", port: 10443, trustedCerts: [Self.pin])]])
        #expect(helper.requests.count == 2, "refused once, retried once")
        #expect(helper.requests.first == helper.requests.last)
        #expect(await engine.hasSession)
    }

    @Test func testADeclinedPromptApprovesNothingAndDoesNotRetry() async throws {
        let helper = unapproved()
        let authoriser = FakeAuthoriser(.declined)
        let engine = VPNEngine(helper: helper, authoriser: authoriser, admins: FakeAdminMembership())
        #expect(await failure(engine) == "vpn.example.com:10443 was not approved for the VPN helper: the Touch ID or password prompt was cancelled. Connect again to approve it.")
        #expect(authoriser.reasons.count == 1)
        #expect(helper.approvals.isEmpty)
        #expect(helper.requests.count == 1)
        #expect(await !engine.hasSession)
    }

    @Test func testAPromptThatCannotBeShownApprovesNothing() async throws {
        let helper = unapproved()
        let engine = VPNEngine(helper: helper, authoriser: FakeAuthoriser(.unavailable("No password is set.")), admins: FakeAdminMembership())
        #expect(await failure(engine) == "vpn.example.com:10443 could not be approved for the VPN helper: No password is set. Open Settings and choose Repair / Reinstall Helper instead.")
        #expect(helper.approvals.isEmpty && helper.requests.count == 1)
    }

    @Test func testAnApprovalTheHelperRefusesIsNotRetried() async throws {
        let helper = unapproved { $0.approveError = "Only an administrator of this Mac can approve a VPN gateway." }
        let authoriser = FakeAuthoriser(.approved)
        let engine = VPNEngine(helper: helper, authoriser: authoriser, admins: FakeAdminMembership())
        #expect(await failure(engine) == "The VPN helper did not approve vpn.example.com:10443. Only an administrator of this Mac can approve a VPN gateway.")
        #expect(helper.approvals.count == 1)
        #expect(helper.requests.count == 1, "no retry")
        #expect(await !engine.hasSession)
    }

    @Test func testAnApprovedGatewayShowsNoPrompt() async throws {
        let helper = FakeHelperAPI()
        let authoriser = FakeAuthoriser(.approved)
        let engine = VPNEngine(helper: helper, authoriser: authoriser, admins: FakeAdminMembership())
        try await engine.start(profile: profile(), settings: AppSettings())
        #expect(authoriser.reasons.isEmpty)
        #expect(helper.approvals.isEmpty)
        #expect(helper.requests.count == 1)
    }

    @Test func testAnotherConnectErrorShowsNoPrompt() async throws {
        let helper = FakeHelperAPI()
        helper.set { $0.connectError = "A session is already active." }
        let authoriser = FakeAuthoriser(.approved)
        let engine = VPNEngine(helper: helper, authoriser: authoriser, admins: FakeAdminMembership())
        #expect(await failure(engine) == "A session is already active.")
        #expect(authoriser.reasons.isEmpty && helper.approvals.isEmpty && helper.requests.count == 1)
    }

    /// The helper keeps refusing after it took the approval: one prompt, one retry, then the error.
    @Test func testAConnectStillRefusedAfterApprovalNeverLoops() async throws {
        let helper = unapproved { $0.approvalTakesEffect = false }
        let authoriser = FakeAuthoriser(.approved)
        let engine = VPNEngine(helper: helper, authoriser: authoriser, admins: FakeAdminMembership())
        #expect(await failure(engine) == HelperRefusal.gatewayNotApproved)
        #expect(authoriser.reasons.count == 1 && helper.approvals.count == 1 && helper.requests.count == 2)
    }

    @Test func testAUIDOnlyHelperOrAStandardUserGetsNoPrompt() async throws {
        let uidOnly = unapproved { $0.mode = .uidOnly }
        let authoriser = FakeAuthoriser(.approved)
        #expect(await failure(VPNEngine(helper: uidOnly, authoriser: authoriser, admins: FakeAdminMembership())) == VPNEngine.approvalNeedsRepair)
        #expect(VPNEngine.approvalNeedsRepair.contains("Repair / Reinstall Helper"))
        #expect(uidOnly.approvals.isEmpty && uidOnly.requests.count == 1)

        let standard = unapproved()
        #expect(await failure(VPNEngine(helper: standard, authoriser: authoriser, admins: FakeAdminMembership(admin: false))) == VPNEngine.approvalNeedsAdministrator)
        #expect(standard.approvals.isEmpty && standard.requests.count == 1)
        #expect(authoriser.reasons.isEmpty)
    }

    @Test func testThePromptNamesEveryGatewayAndItsPins() throws {
        let gateways = [try AllowedGateway(host: "vpn.example.com", port: 443, trustedCerts: [Self.pin]),
                        try AllowedGateway(host: "192.0.2.7", port: 10443),
                        try AllowedGateway(host: "b.example.com", port: 8443, trustedCerts: [Self.pin, String(repeating: "cd", count: 32)])]
        #expect(GatewayApprovalPrompt.reason(for: gateways)
                == "allow its VPN helper to connect to vpn.example.com:443 (with 1 pinned certificate), 192.0.2.7:10443, b.example.com:8443 (with 2 pinned certificates)")
    }

    @Test func testOnlyACancelledPromptCountsAsDeclined() {
        typealias Authoriser = LocalAuthenticationAuthoriser
        #expect(Authoriser.outcome(success: true, error: nil) == .approved)
        for code in [LAError.userCancel, .appCancel, .systemCancel] {
            #expect(Authoriser.outcome(success: false, error: LAError(code)) == .declined)
        }
        for code in [LAError.authenticationFailed, .passcodeNotSet, .notInteractive] {
            guard case .unavailable = Authoriser.outcome(success: false, error: LAError(code)) else {
                Issue.record("\(code) must not count as approved or declined")
                continue
            }
        }
        #expect(Authoriser.outcome(success: false, error: nil) == .unavailable("Authentication failed."))
    }

    @Test func testInterfaceBytesOnlyForPPPNames() {
        let wifi = VPNEngine.interfaceBytes("en0")
        #expect(wifi.0 == 0 && wifi.1 == 0, "not a tunnel interface: never read")
        let none = VPNEngine.interfaceBytes("en0; rm")
        #expect(none.0 == 0 && none.1 == 0)
        let missing = VPNEngine.interfaceBytes("ppp987")
        #expect(missing.0 == 0 && missing.1 == 0)
    }
}
