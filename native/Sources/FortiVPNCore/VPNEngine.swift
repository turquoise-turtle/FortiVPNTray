import Foundation
import Darwin
import FortiVPNShared

public struct PollResult: Sendable {
    public var lines: [String] = []
    public var events: [LogEvent] = []
    public var exitMessage: String?
    public var received: UInt64 = 0
    public var sent: UInt64 = 0
}

/// The SAML login URL the app is willing to open (PLAN.md 3.1). The helper builds
/// it from the validated request, but the app checks it again before handing it to
/// the browser: https, the profile's host and port, and the login path only.
public enum SAMLLogin {
    public static let path = "/remote/saml/start"

    public static func isExpected(_ url: URL, host: String, port: Int) -> Bool {
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return false }
        return parts.scheme == "https" && parts.host?.lowercased() == host.lowercased() && parts.port == port
            && parts.path == path && parts.user == nil && parts.password == nil && parts.fragment == nil
    }
}

/// The app's side of a VPN session: a client of the helper (PLAN.md phase 3). The
/// helper starts openfortivpn, applies and undoes routes and DNS, and keeps the
/// redacted log; this actor turns its status and log into what the UI shows.
public actor VPNEngine {
    private struct Session {
        let id: String
        let host: String
        let port: Int
        var offset = 0
        var parser = LogParser()
        var connected = false
        var seenSAMLURLs: Set<URL> = []
    }

    static let approvalNeedsRepair = "The VPN helper has not been approved for this gateway or certificate pin, and a helper in UID-only mode takes approvals only at installation. " +
        "Open Settings and choose Repair / Reinstall Helper."
    static let approvalNeedsAdministrator = "The VPN helper has not been approved for this gateway or certificate pin, and only an administrator of this Mac can approve it. " +
        "Ask an administrator to open Settings and choose Repair / Reinstall Helper."

    private let helper: any HelperAPI
    private let authoriser: any ApprovalAuthoriser
    private let admins: any AdminMembership
    private var session: Session?

    public var hasSession: Bool { session != nil }

    public init(helper: any HelperAPI = HelperXPCClient(), authoriser: any ApprovalAuthoriser = LocalAuthenticationAuthoriser(),
                admins: any AdminMembership = SystemAdminMembership()) {
        self.helper = helper
        self.authoriser = authoriser
        self.admins = admins
    }

    public func start(profile: VPNProfile, settings: AppSettings) async throws {
        guard session == nil else { throw VPNError("Disconnect the current session before reconnecting.") }
        let version = try helper.version()
        guard version.protocolVersion == HelperTransport.protocolVersion else {
            throw VPNError("The helper speaks protocol \(version.protocolVersion); this app requires protocol \(HelperTransport.protocolVersion). Repair the helper in Settings.")
        }
        let profile = try profile.validated()
        try Task.checkCancellation()
        try endLeftoverSession()
        let request: ConnectRequest
        do {
            request = try ConnectRequest(host: profile.host, port: profile.port, realm: profile.realm, trustedCerts: profile.trustedCerts,
                                         useSystemDNSFallback: settings.dnsFallback)
        } catch {
            throw VPNError(error.description)
        }
        let id: String
        do {
            id = try helper.connect(request)
        } catch let refusal as VPNError where refusal.message == HelperRefusal.gatewayNotApproved {
            try await approve(profile, mode: version.mode)
            try Task.checkCancellation()
            // Once: a helper that still refuses is an error, not another prompt.
            id = try helper.connect(request)
        }
        session = Session(id: id, host: profile.host, port: profile.port)
    }

    /// Asks the user to approve the profile's gateway and pins for the helper, and tells the
    /// helper. Throws unless the helper took the approval. The helper makes its own checks;
    /// the ones here only spare the user a prompt that cannot succeed.
    private func approve(_ profile: VPNProfile, mode: CallerCheckMode) async throws {
        guard mode == .signed else { throw VPNError(Self.approvalNeedsRepair) }
        guard admins.isAdmin(uid: getuid()) else { throw VPNError(Self.approvalNeedsAdministrator) }
        let gateway: AllowedGateway
        do {
            gateway = try AllowedGateway(host: profile.host, port: profile.port, trustedCerts: profile.trustedCerts)
        } catch {
            throw VPNError("This profile's gateway cannot be approved: it is \(error).")
        }
        let name = "\(gateway.host):\(gateway.port)"
        switch await authoriser.authorise(reason: GatewayApprovalPrompt.reason(for: [gateway])) {
        case .approved: break
        case .declined:
            throw VPNError("\(name) was not approved for the VPN helper: the Touch ID or password prompt was cancelled. Connect again to approve it.")
        case .unavailable(let reason):
            throw VPNError("\(name) could not be approved for the VPN helper: \(reason) Open Settings and choose Repair / Reinstall Helper instead.")
        }
        try Task.checkCancellation()
        do {
            try helper.approveGateways([gateway])
        } catch let refusal as VPNError {
            throw VPNError("The VPN helper did not approve \(name). \(refusal.message)")
        }
    }

    /// Ends a session the helper still runs but this app did not start: one left behind
    /// by an app that was killed or crashed while connected. Returns whether there was
    /// one. Does nothing while this app has a session of its own.
    @discardableResult
    public func endLeftoverSession() throws -> Bool {
        guard session == nil, try helper.status().state != .idle else { return false }
        try helper.disconnect()
        return true
    }

    public func poll() throws -> PollResult {
        guard var current = session else { return PollResult() }
        var result = PollResult()
        // The log first, so a session's last lines are shown before its end.
        read(into: &result, session: &current, chunk: try helper.readLog(sessionID: current.id, offset: current.offset))
        let status = try helper.status()
        guard status.sessionID == current.id else {
            // The session is over: the child exited, or someone else disconnected it.
            // Its log is kept by the helper; collect what is left.
            for _ in 0..<20 {
                guard let chunk = try? helper.readLog(sessionID: current.id, offset: current.offset), !chunk.lines.isEmpty else { break }
                read(into: &result, session: &current, chunk: chunk)
            }
            result.exitMessage = status.lastError ?? (current.connected ? "The VPN connection ended." : "openfortivpn exited before the tunnel was established.")
            session = nil
            return result
        }
        if status.state == .connected && !current.connected {
            current.connected = true
            result.events.append(.connected(status.vpnIP ?? "unknown"))
        }
        if !current.connected, let url = try helper.pendingSAMLURL(), current.seenSAMLURLs.insert(url).inserted {
            if SAMLLogin.isExpected(url, host: current.host, port: current.port) {
                result.events.append(.saml(url))
            } else {
                result.lines.append("ERROR:  The helper offered an unexpected login URL; it was not opened.")
            }
        }
        if current.connected, let interface = status.interface {
            (result.received, result.sent) = Self.interfaceBytes(interface)
        }
        session = current
        return result
    }

    public func stop() throws {
        guard session != nil else { return }
        try helper.disconnect()
        session = nil
    }

    /// Lines are already redacted by the helper. The parser only looks for the
    /// gateway certificate digest; connection state comes from the helper's status.
    private func read(into result: inout PollResult, session: inout Session, chunk: LogChunk) {
        session.offset = max(session.offset, chunk.nextOffset)
        for line in chunk.lines {
            result.lines.append(line)
            for event in session.parser.consume(line) {
                if case .certificate = event { result.events.append(event) }
            }
        }
    }

    /// Bytes in and out of the tunnel interface (`ppp0` etc.), read unprivileged.
    static func interfaceBytes(_ interface: String) -> (UInt64, UInt64) {
        guard interface.range(of: #"^ppp[0-9]+$"#, options: .regularExpression) != nil else { return (0, 0) }
        var start: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&start) == 0, let first = start else { return (0, 0) }
        defer { freeifaddrs(first) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let pointer = cursor {
            let info = pointer.pointee
            if String(cString: info.ifa_name) == interface, let address = info.ifa_addr,
               Int32(address.pointee.sa_family) == AF_LINK, let data = info.ifa_data {
                let stats = data.assumingMemoryBound(to: if_data.self).pointee
                return (UInt64(stats.ifi_ibytes), UInt64(stats.ifi_obytes))
            }
            cursor = info.ifa_next
        }
        return (0, 0)
    }
}
