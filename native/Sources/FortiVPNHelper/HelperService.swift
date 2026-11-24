import Foundation
import FortiVPNShared
import os

/// The object exported to each accepted connection. Every argument comes from a
/// caller that may be hostile and is validated here; the shared
/// `SessionController` holds the state.
final class HelperService: NSObject, HelperXPCProtocol {
    /// Said to a caller whose gateway, or certificate pin for it, is not on the helper's list.
    static let gatewayNotApproved = HelperRefusal.gatewayNotApproved

    private let mode: CallerCheckMode
    private let sessions: SessionController
    private let approvals: GatewayApprovals
    private let log = Logger(subsystem: AppIdentity.helperLabel, category: "service")

    init(mode: CallerCheckMode, sessions: SessionController, approvals: GatewayApprovals) {
        self.mode = mode
        self.sessions = sessions
        self.approvals = approvals
    }

    func version(reply: @escaping @Sendable (String, Int, String) -> Void) {
        reply(HelperTransport.helperVersion, HelperTransport.protocolVersion, mode.rawValue)
    }

    func connect(_ request: Data, reply: @escaping @Sendable (String?, String?) -> Void) {
        let parsed: ConnectRequest
        do {
            parsed = try ConnectRequest(json: request)
        } catch {
            // The description never contains the rejected value.
            log.notice("Refused connect: \(error.description, privacy: .public)")
            reply(nil, error.description)
            return
        }
        // A valid request is still only the caller's wish. Where root connects, and which
        // certificate it accepts there, was decided at install time or approved since.
        guard approvals.allows(parsed) else {
            log.notice("Refused connect: the gateway or a certificate pin is not approved")
            reply(nil, Self.gatewayNotApproved)
            return
        }
        do {
            reply(try sessions.connect(parsed), nil)
        } catch {
            log.notice("Connect failed: \(String(describing: error), privacy: .public)")
            reply(nil, String(describing: error))
        }
    }

    func approveGateways(_ gateways: Data, reply: @escaping @Sendable (String?) -> Void) {
        do {
            try approvals.approve(gateways)
            reply(nil)
        } catch {
            log.notice("Refused a gateway approval: \(error.description, privacy: .public)")
            reply(error.description)
        }
    }

    func disconnect(reply: @escaping @Sendable (String?) -> Void) {
        sessions.disconnect()
        reply(nil)
    }

    func status(reply: @escaping @Sendable (Data) -> Void) {
        reply(HelperWire.encode(sessions.status()))
    }

    func readLog(sessionID: String, offset: Int, reply: @escaping @Sendable (Data?, String?) -> Void) {
        do {
            reply(HelperWire.encode(try sessions.readLog(sessionID: sessionID, offset: offset)), nil)
        } catch {
            reply(nil, String(describing: error))
        }
    }

    func pendingSAMLURL(reply: @escaping @Sendable (String?) -> Void) {
        reply(sessions.pendingSAMLURL()?.absoluteString)
    }
}
