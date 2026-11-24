import Foundation
import FortiVPNShared
import os

/// The approvals file in the helper's root-owned `0700` directory: gateways an administrator
/// approved in the app since the last install. Written like the state file; the installer removes it.
struct ApprovalStore: Sendable {
    static let fileName = "approved-gateways.json"
    static let temporaryName = "approved-gateways.json.new"

    let directory: RunDirectory

    static let production = ApprovalStore(directory: RunDirectory(path: AppIdentity.helperSupportDirectory, trust: .root, owner: 0))

    var path: String { directory.path + "/" + Self.fileName }

    /// The stored gateways, none if there is no file. Throws if the file is unreadable or invalid.
    func load() throws -> [AllowedGateway] {
        try directory.prepare()
        guard let data = try directory.read(Self.fileName, maxSize: GatewayApproval.maxEncodedSize) else { return [] }
        return try GatewayApproval(json: data).gateways
    }

    func save(_ gateways: [AllowedGateway]) throws {
        try directory.prepare()
        try directory.replace(Self.fileName, temporaryName: Self.temporaryName, contents: try GatewayApproval(gateways: gateways).json())
    }
}

/// Where the helper may connect: the launch arguments' gateways, fixed behind the admin
/// prompt, plus those approved since through `approve`. Shared by every connection.
/// Nothing is added except by `approve`, after its checks.
final class GatewayApprovals: @unchecked Sendable {
    struct Refusal: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    static let uidOnlyRefusal = Refusal(description: "The helper runs in UID-only mode, where any process running as you could ask for an approval, so it takes none this way. " +
        "Open Settings and choose Repair / Reinstall Helper: that approves the gateways and pins of your saved profiles.")
    static let notAdminRefusal = Refusal(description: "Only an administrator of this Mac can approve a VPN gateway. " +
        "Ask an administrator to open Settings and choose Repair / Reinstall Helper.")
    static let tooManyPinsRefusal = Refusal(description: "More than \(ConnectRequest.maxTrustedCerts) certificate pins would be approved for one gateway. " +
        "Remove pins you no longer need from the profile, then choose Repair / Reinstall Helper in Settings.")
    static let tooManyGatewaysRefusal = Refusal(description: "More than \(HelperLaunchArguments.maxGateways) gateways would be approved. " +
        "Choose Repair / Reinstall Helper in Settings: that keeps only the gateways of your saved profiles.")

    private let launch: [AllowedGateway]
    private let mode: CallerCheckMode
    private let allowedUID: uid_t
    private let store: ApprovalStore
    private let admins: any AdminMembership
    private let log = Logger(subsystem: AppIdentity.helperLabel, category: "approvals")
    // @unchecked Sendable: `stored` is only touched while holding `lock`.
    private let lock = NSLock()
    /// Never holds a pin the launch arguments already approve for the same gateway.
    private var stored: [AllowedGateway] = []

    init(arguments: HelperLaunchArguments, store: ApprovalStore, admins: any AdminMembership) {
        launch = arguments.gateways
        mode = arguments.callerCheck.mode
        allowedUID = arguments.allowedUID
        self.store = store
        self.admins = admins
        // UID-only mode takes no approvals, so a file there is not one this helper wrote.
        guard mode == .signed else { return }
        do {
            stored = try Self.adding(try store.load(), to: [], launch: launch)
        } catch {
            log.error("Ignoring the approvals file: \(String(describing: error), privacy: .public)")
        }
    }

    private static func same(_ a: AllowedGateway, _ b: AllowedGateway) -> Bool { a.host == b.host && a.port == b.port }

    /// `stored` with `gateways` added, without the pins `launch` already holds for the same
    /// gateway. Refused if one gateway would end up with more pins, or the list with more
    /// gateways, than the limits allow.
    private static func adding(_ gateways: [AllowedGateway], to stored: [AllowedGateway], launch: [AllowedGateway]) throws(Refusal) -> [AllowedGateway] {
        var result = stored
        for gateway in gateways {
            let fixed = launch.first { same($0, gateway) }?.trustedCerts ?? []
            let index = result.firstIndex { same($0, gateway) }
            var pins = index.map { result[$0].trustedCerts } ?? []
            for pin in gateway.trustedCerts where !fixed.contains(pin) && !pins.contains(pin) { pins.append(pin) }
            guard fixed.count + pins.count <= ConnectRequest.maxTrustedCerts,
                  let entry = try? AllowedGateway(host: gateway.host, port: gateway.port, trustedCerts: pins) else { throw tooManyPinsRefusal }
            if let index { result[index] = entry } else { result.append(entry) }
        }
        guard AllowedGateway.merged(launch + result).count <= HelperLaunchArguments.maxGateways else { throw tooManyGatewaysRefusal }
        return result
    }

    var storedCount: Int { lock.withLock { stored.count } }

    func allows(_ request: ConnectRequest) -> Bool {
        let stored = lock.withLock { self.stored }
        return AllowedGateway.merged(launch + stored).contains { $0.allows(request) }
    }

    /// Adds what `data`, a `GatewayApproval` as JSON, names. All of it or nothing.
    func approve(_ data: Data) throws(Refusal) {
        // Any process of the user passes the UID-only check; the prompt in the app would mean nothing.
        guard mode == .signed else { throw Self.uidOnlyRefusal }
        // Root decides this itself: the caller is the allowed user, whoever asked in the app.
        guard admins.isAdmin(uid: allowedUID) else { throw Self.notAdminRefusal }
        let approval: GatewayApproval
        do { approval = try GatewayApproval(json: data) } catch { throw Refusal(description: error.description) }
        lock.lock()
        defer { lock.unlock() }
        let next = try Self.adding(approval.gateways, to: stored, launch: launch)
        // Saved first: an approval that would not survive a restart is not given.
        do { try store.save(next) } catch { throw Refusal(description: "The approval could not be saved: \(error)") }
        stored = next
        let names = approval.gateways.map { "\($0.host):\($0.port) (\($0.trustedCerts.count) pins)" }.joined(separator: ", ")
        log.notice("Approved for uid \(self.allowedUID, privacy: .public): \(names, privacy: .public)")
    }
}
