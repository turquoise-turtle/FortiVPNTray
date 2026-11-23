import Foundation
import Security

/// Apple's pppd, which openfortivpn starts for the tunnel (its compiled-in `PPP_PATH`).
/// Root ends up running it, so before each connect it must be there, in a place only
/// root can change, and Apple's own. If a later macOS drops it, the user is told so.
struct PPPDaemon: Sendable {
    struct Failure: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    let path: String
    let trust: FileTrust
    let requirement: String

    static let production = PPPDaemon(path: TunnelCleanup.pppdPath, trust: .root,
                                      requirement: "identifier \"com.apple.pppd\" and anchor apple")

    func check() throws {
        var info = stat()
        guard lstat(path, &info) == 0 else {
            throw Failure(description: "macOS no longer provides \(path). openfortivpn needs Apple's pppd for the tunnel, so the helper cannot connect on this system.")
        }
        do { try trust.check(path, is: .file) } catch let failure as FileTrust.Failure {
            throw Failure(description: "Refusing to use pppd: \(failure.description).")
        }
        var code: SecStaticCode?
        var wanted: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, SecCSFlags(), &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(requirement as CFString, SecCSFlags(), &wanted) == errSecSuccess, let wanted else {
            throw Failure(description: "Refusing to use pppd: the code signature of \(path) cannot be read.")
        }
        let status = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), wanted)
        guard status == errSecSuccess else {
            throw Failure(description: "Refusing to use pppd: \(path) is not Apple's pppd (code signature check failed with \(status)).")
        }
    }
}
