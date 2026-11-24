import Darwin
import Darwin.membership

/// Whether a user is an administrator of this Mac. Behind a protocol so tests decide the answer.
public protocol AdminMembership: Sendable {
    func isAdmin(uid: uid_t) -> Bool
}

/// Asks the system's membership API, which also knows nested and directory groups.
public struct SystemAdminMembership: AdminMembership {
    /// macOS's `admin` group.
    public static let adminGroupID: gid_t = 80

    public init() {}

    public func isAdmin(uid: uid_t) -> Bool {
        var user = [UInt8](repeating: 0, count: 16)
        var group = [UInt8](repeating: 0, count: 16)
        var member: Int32 = 0
        // Any failure means no.
        guard mbr_uid_to_uuid(uid, &user) == 0, mbr_gid_to_uuid(Self.adminGroupID, &group) == 0,
              mbr_check_membership(&user, &group, &member) == 0 else { return false }
        return member == 1
    }
}
