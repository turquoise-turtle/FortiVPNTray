import Foundation
import FortiVPNShared
import LocalAuthentication

/// How the user answered when asked to approve a gateway for the helper.
public enum ApprovalAuthorisation: Equatable, Sendable {
    case approved
    /// The user cancelled, or the prompt was taken away.
    case declined
    /// No prompt could be shown or completed; the reason is the system's.
    case unavailable(String)
}

/// Asks the user to confirm with Touch ID or the login password. Behind a protocol so
/// tests never show a prompt.
public protocol ApprovalAuthoriser: Sendable {
    /// `reason` completes the system's sentence "<app> is trying to …".
    func authorise(reason: String) async -> ApprovalAuthorisation
}

public enum GatewayApprovalPrompt {
    /// Names every gateway and how many pins it carries: the profile file they come from
    /// is user-writable, so the user must see what is approved.
    public static func reason(for gateways: [AllowedGateway]) -> String {
        "allow its VPN helper to connect to \(HelperInstaller.gatewayList(gateways))"
    }
}

/// LocalAuthentication's device-owner policy: Touch ID, or the login password where
/// Touch ID is unavailable. Needs no entitlement.
public struct LocalAuthenticationAuthoriser: ApprovalAuthoriser {
    public init() {}

    public func authorise(reason: String) async -> ApprovalAuthorisation {
        let context = Context()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                context.value.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                    continuation.resume(returning: Self.outcome(success: success, error: error))
                }
            }
        } onCancel: {
            // Disconnecting while the prompt is up takes it away instead of waiting for an answer.
            context.value.invalidate()
        }
    }

    static func outcome(success: Bool, error: (any Error)?) -> ApprovalAuthorisation {
        if success { return .approved }
        guard let error = error as? LAError else {
            return .unavailable(error?.localizedDescription ?? "Authentication failed.")
        }
        switch error.code {
        case .userCancel, .appCancel, .systemCancel: return .declined
        default: return .unavailable(error.localizedDescription)
        }
    }

    /// `LAContext` is documented as usable from any thread; `invalidate` exists to be called from another one.
    private final class Context: @unchecked Sendable {
        let value = LAContext()
    }
}
