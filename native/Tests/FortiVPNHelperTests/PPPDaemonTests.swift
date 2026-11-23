import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// The check on Apple's pppd before each connect. The real `/usr/sbin/pppd` of the
/// machine running the tests is used for the accepting case.
struct PPPDaemonTests {
    private func failure(_ body: () throws -> Void) -> String? {
        do { try body(); return nil } catch { return String(describing: error) }
    }

    private func signAdHoc(_ path: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = ["--force", "--sign", "-", "--identifier", "com.apple.pppd", path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        try #require(process.terminationStatus == 0)
    }

    @Test func testTheSystemsPPPDIsAccepted() throws {
        #expect(PPPDaemon.production.path == "/usr/sbin/pppd")
        #expect(PPPDaemon.production.path == TunnelCleanup.pppdPath)
        try PPPDaemon.production.check()
    }

    @Test func testAMissingPPPDIsReportedAsSuch() throws {
        let fake = try FakeInstall()
        let missing = PPPDaemon(path: fake.root + "/pppd", trust: FakeInstall.trust, requirement: PPPDaemon.production.requirement)
        let reason = try #require(failure { try missing.check() })
        #expect(reason.contains("no longer provides") && reason.contains("pppd"))
    }

    @Test func testAProgramThatIsNotApplesIsRefused() throws {
        let fake = try FakeInstall()
        let path = fake.root + "/pppd"
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: path)
        // Signed by nobody, but under pppd's own identifier: the identifier alone must not do.
        try signAdHoc(path)
        let impostor = PPPDaemon(path: path, trust: FakeInstall.trust, requirement: PPPDaemon.production.requirement)
        #expect(failure { try impostor.check() }?.contains("is not Apple's pppd") == true)

        // A file that is no program at all.
        try fake.write("#!/bin/sh\n", to: path + ".sh", mode: 0o755)
        let script = PPPDaemon(path: path + ".sh", trust: FakeInstall.trust, requirement: PPPDaemon.production.requirement)
        #expect(failure { try script.check() } != nil)
    }

    @Test func testPPPDInAPlaceOthersCanChangeIsRefused() throws {
        let fake = try FakeInstall()
        let path = fake.root + "/pppd"
        try FileManager.default.copyItem(atPath: "/usr/sbin/pppd", toPath: path)
        // Apple's own file, but owned by the test user: root-only trust does not accept it.
        let copy = PPPDaemon(path: path, trust: .root, requirement: PPPDaemon.production.requirement)
        #expect(failure { try copy.check() }?.contains("is owned by uid") == true)
        let link = fake.root + "/pppd-link"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: "/usr/sbin/pppd")
        let linked = PPPDaemon(path: link, trust: FakeInstall.trust, requirement: PPPDaemon.production.requirement)
        #expect(failure { try linked.check() }?.contains("is a symlink") == true)
    }

    @Test func testNothingIsStartedWithoutPPPD() throws {
        let fake = try FakeInstall()
        let missing = PPPDaemon(path: fake.root + "/pppd", trust: FakeInstall.trust, requirement: PPPDaemon.production.requirement)
        let launcher = OpenFortiVPNLauncher(install: fake.install, runDirectory: fake.runDirectory, pppd: missing)
        let id = UUID().uuidString
        let reason = failure { try launcher.start(try ConnectRequest(host: "vpn.example.com", port: 443), sessionID: id) { _ in } }
        #expect(reason?.contains("no longer provides") == true)
        #expect(fake.waitForReport(timeout: 0.5) == nil, "the fake openfortivpn was started")
        #expect(fake.configFiles().isEmpty)
    }
}
