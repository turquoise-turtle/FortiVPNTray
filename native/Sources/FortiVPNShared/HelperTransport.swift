import Foundation

/// The XPC transport between the app and the Swift root helper.
public enum HelperTransport {
    /// Mach service the helper's launchd job registers. Same as its label.
    public static let machServiceName = AppIdentity.helperLabel
    /// Bumped whenever the XPC interface changes incompatibly.
    public static let protocolVersion = 1
    /// Version of the Swift helper itself.
    public static let helperVersion = "0.3.0"
}

/// How the helper decides which callers it talks to. The raw value crosses XPC.
public enum CallerCheckMode: String, Sendable, Equatable {
    /// Allowed UID and a code-signing requirement on the app's identifier and certificate.
    case signed
    /// Allowed UID only: any process of that user is accepted. Used when the app is ad-hoc signed.
    case uidOnly = "uid-only"

    public var title: String { self == .signed ? "Signed caller check" : "UID-only" }
}

/// What the helper exposes over XPC (PLAN.md 2.2). Structured values travel as
/// `HelperWire` JSON. Calls that can fail reply with an error message, which is
/// nil on success. Everything a caller passes is validated by the helper.
@objc public protocol HelperXPCProtocol {
    /// Replies with the helper version, the protocol version and the `CallerCheckMode` raw value.
    func version(reply: @escaping @Sendable (String, Int, String) -> Void)
    /// `request` is a `ConnectRequest` as JSON. Replies with the new session id, or with an error.
    /// Only one session runs at a time.
    func connect(_ request: Data, reply: @escaping @Sendable (String?, String?) -> Void)
    /// Ends the current session, if any. Replies with an error or nil.
    func disconnect(reply: @escaping @Sendable (String?) -> Void)
    /// Replies with a `HelperStatus` as JSON.
    func status(reply: @escaping @Sendable (Data) -> Void)
    /// Replies with a `LogChunk` as JSON for the current or last session, or with an error.
    func readLog(sessionID: String, offset: Int, reply: @escaping @Sendable (Data?, String?) -> Void)
    /// Replies with the SAML login URL the helper parsed from openfortivpn's output, if one is pending.
    func pendingSAMLURL(reply: @escaping @Sendable (String?) -> Void)
}

/// A gateway the helper may connect to, with the certificate pins it may use there.
/// The list is fixed in the launch arguments, behind the admin prompt: the app takes
/// host and pins from a profile file any process of the user can rewrite.
public struct AllowedGateway: Equatable, Sendable {
    public struct Invalid: Error, Equatable, CustomStringConvertible {
        public let description: String
        init(_ description: String) { self.description = description }
    }

    /// Lowercase: host names are compared without regard to case.
    public let host: String
    public let port: Int
    /// The SHA-256 fingerprints the helper may hand to openfortivpn for this gateway.
    public let trustedCerts: [String]

    public init(host: String, port: Int, trustedCerts: [String] = []) throws {
        guard Validation.host(host) else { throw Invalid("not a hostname or IPv4 address") }
        guard ConnectRequest.ports.contains(port) else { throw Invalid("not a port") }
        guard trustedCerts.count <= ConnectRequest.maxTrustedCerts, trustedCerts.allSatisfy(Validation.digest) else {
            throw Invalid("not a list of at most \(ConnectRequest.maxTrustedCerts) certificate fingerprints")
        }
        self.host = host.lowercased()
        self.port = port
        var unique: [String] = []
        for cert in trustedCerts where !unique.contains(cert) { unique.append(cert) }
        self.trustedCerts = unique
    }

    /// `host:port`, then `,<fingerprint>` for each pin. None of the parts can contain ':' or ','.
    public var argument: String {
        (["\(host):\(port)"] + trustedCerts).joined(separator: ",")
    }

    public init(parsing argument: String) throws {
        let parts = argument.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        let address = parts[0].split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard address.count == 2, !address[1].isEmpty, address[1].utf8.allSatisfy({ (48...57).contains($0) }),
              address[1].utf8.first != 48, let port = Int(address[1]) else {
            throw Invalid("not of the form host:port[,fingerprint…]")
        }
        try self.init(host: address[0], port: port, trustedCerts: Array(parts.dropFirst()))
        // One spelling only, so what the installer wrote is what the helper reads.
        guard self.argument == argument else { throw Invalid("not in its canonical form") }
    }

    /// Whether `request` goes to this gateway and asks for no pin beyond the approved ones.
    public func allows(_ request: ConnectRequest) -> Bool {
        request.host.lowercased() == host && request.port == port && request.trustedCerts.allSatisfy(trustedCerts.contains)
    }

    /// One entry per `host:port`, pins merged, in first-seen order: the list for a set of profiles.
    public static func merged(_ gateways: [AllowedGateway]) -> [AllowedGateway] {
        var result: [AllowedGateway] = []
        for gateway in gateways {
            if let index = result.firstIndex(where: { $0.host == gateway.host && $0.port == gateway.port }) {
                // Only too many pins together can fail; the first entry then stays.
                if let both = try? AllowedGateway(host: gateway.host, port: gateway.port, trustedCerts: result[index].trustedCerts + gateway.trustedCerts) {
                    result[index] = both
                }
            } else {
                result.append(gateway)
            }
        }
        return result
    }
}

/// The helper's launch arguments. They are written into the launchd plist at
/// install time, behind the admin prompt, and are the only source of the allowed
/// UID and the pinned certificate. The installer builds them with `arguments`
/// and the helper reads them with `init(parsing:)`, so the two cannot drift.
public struct HelperLaunchArguments: Equatable, Sendable {
    public enum CallerCheck: Equatable, Sendable {
        /// SHA-1 of the app's leaf signing certificate, 40 uppercase hex digits.
        case signed(leafSHA1: String)
        case uidOnly

        public var mode: CallerCheckMode {
            switch self {
            case .signed: return .signed
            case .uidOnly: return .uidOnly
            }
        }
    }

    public struct ParseError: Error, Equatable, CustomStringConvertible {
        public let description: String
        init(_ description: String) { self.description = description }
    }

    public static let allowedUIDFlag = "--allowed-uid"
    public static let leafFlag = "--client-req-leaf"
    public static let uidOnlyFlag = "--uid-only"
    /// Once per gateway the helper may connect to; see `AllowedGateway.argument`.
    public static let gatewayFlag = "--allowed-gateway"
    public static let maxGateways = 64
    /// Not a launch argument: the installer runs the helper with only this flag to check
    /// the openfortivpn copy as root, and the helper exits after the check (PLAN.md 2.6).
    public static let verifyInstallFlag = "--verify-install"

    public let allowedUID: uid_t
    public let callerCheck: CallerCheck
    /// The only gateways `connect` is accepted for. Empty means none: nothing is defaulted.
    public let gateways: [AllowedGateway]

    /// - Throws: `ParseError` if `allowedUID` is 0, `leafSHA1` is not 40 hex digits, or there
    ///   are too many gateways or two entries for one `host:port`.
    public init(allowedUID: uid_t, callerCheck: CallerCheck, gateways: [AllowedGateway] = []) throws {
        self.allowedUID = try Self.checkedUID(allowedUID)
        if case .signed(let hash) = callerCheck {
            self.callerCheck = .signed(leafSHA1: try Self.normalizedHash(hash))
        } else {
            self.callerCheck = callerCheck
        }
        self.gateways = try Self.checkedGateways(gateways)
    }

    /// Arguments after the executable path, as they go into `ProgramArguments`.
    public var arguments: [String] {
        var result = [Self.allowedUIDFlag, String(allowedUID)]
        switch callerCheck {
        case .signed(let hash): result += [Self.leafFlag, hash]
        case .uidOnly: result += [Self.uidOnlyFlag]
        }
        for gateway in gateways { result += [Self.gatewayFlag, gateway.argument] }
        return result
    }

    /// Parses the arguments after the executable path. Everything is required and
    /// nothing is defaulted: a missing UID, a missing mode, both modes, a repeated
    /// or unknown argument are all errors, so a damaged plist cannot quietly
    /// weaken the check.
    public init(parsing arguments: [String]) throws {
        var uid: uid_t?
        var hash: String?
        var uidOnly = false
        var gateways: [AllowedGateway] = []
        var index = 0
        func value(for flag: String) throws -> String {
            guard index + 1 < arguments.count else { throw ParseError("\(flag) needs a value") }
            index += 1
            return arguments[index]
        }
        while index < arguments.count {
            let flag = arguments[index]
            switch flag {
            case Self.allowedUIDFlag:
                guard uid == nil else { throw ParseError("\(flag) given twice") }
                let text = try value(for: flag)
                // Digits only: `uid_t("+501")` and similar would otherwise be accepted.
                guard !text.isEmpty, text.utf8.allSatisfy({ (48...57).contains($0) }), let parsed = uid_t(text) else {
                    throw ParseError("\(flag) is not a user id: \(text)")
                }
                uid = try Self.checkedUID(parsed)
            case Self.leafFlag:
                guard hash == nil else { throw ParseError("\(flag) given twice") }
                hash = try Self.normalizedHash(try value(for: flag))
            case Self.uidOnlyFlag:
                guard !uidOnly else { throw ParseError("\(flag) given twice") }
                uidOnly = true
            case Self.gatewayFlag:
                let text = try value(for: flag)
                do { gateways.append(try AllowedGateway(parsing: text)) } catch {
                    throw ParseError("\(flag) is \(error): \(text)")
                }
            default:
                throw ParseError("unknown argument: \(flag)")
            }
            index += 1
        }
        guard let uid else { throw ParseError("\(Self.allowedUIDFlag) is required") }
        switch (hash, uidOnly) {
        case (let hash?, false): self.callerCheck = .signed(leafSHA1: hash)
        case (nil, true): self.callerCheck = .uidOnly
        case (nil, false): throw ParseError("one of \(Self.leafFlag) or \(Self.uidOnlyFlag) is required")
        case (_?, true): throw ParseError("\(Self.leafFlag) and \(Self.uidOnlyFlag) exclude each other")
        }
        self.allowedUID = uid
        self.gateways = try Self.checkedGateways(gateways)
    }

    private static func checkedGateways(_ gateways: [AllowedGateway]) throws -> [AllowedGateway] {
        guard gateways.count <= maxGateways else { throw ParseError("more than \(maxGateways) \(gatewayFlag) arguments") }
        for (index, gateway) in gateways.enumerated() {
            guard !gateways[..<index].contains(where: { $0.host == gateway.host && $0.port == gateway.port }) else {
                throw ParseError("\(gatewayFlag) given twice for \(gateway.host):\(gateway.port)")
            }
        }
        return gateways
    }

    /// The helper serves one logged-in user. Root never needs it, and a 0 here
    /// most likely means the installer read the UID of `sudo` instead of the user's.
    private static func checkedUID(_ uid: uid_t) throws -> uid_t {
        guard uid != 0 else { throw ParseError("\(allowedUIDFlag) must not be 0 (root)") }
        return uid
    }

    private static func normalizedHash(_ text: String) throws -> String {
        guard text.utf8.count == 40, text.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else {
            throw ParseError("\(leafFlag) is not a 40-digit SHA-1")
        }
        return text.uppercased()
    }
}

/// The code-signing requirement the helper sets on every incoming connection in signed mode.
public enum CallerRequirement {
    /// The lowest `CFBundleVersion` of the app the helper still accepts. Identifier and
    /// certificate alone accept everything ever signed with them, also builds that take
    /// `DYLD_INSERT_LIBRARIES`; the build number is sealed by the signature. Raise it
    /// together with `CFBundleVersion` in `native/Resources/Info.plist` to retire builds.
    public static let minimumClientBuild = 6

    /// `identifier "<id>" and certificate leaf = H"<sha1>" and info[CFBundleVersion] >= "<build>"`.
    /// Returns nil unless the identifier is a plain reverse-DNS name, the hash is 40 hex digits
    /// and the build is positive: all three are placed inside a requirement string, so none may
    /// contain a quote or anything else.
    public static func string(identifier: String, leafSHA1: String, minimumBuild: Int = minimumClientBuild) -> String? {
        let identifierOK = !identifier.isEmpty && identifier.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46
        }
        let hashOK = leafSHA1.utf8.count == 40 && leafSHA1.utf8.allSatisfy {
            (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
        }
        guard identifierOK, hashOK, minimumBuild > 0 else { return nil }
        // The comparison is numeric, so build 10 is above 6.
        return "identifier \"\(identifier)\" and certificate leaf = H\"\(leafSHA1.uppercased())\" and info[CFBundleVersion] >= \"\(minimumBuild)\""
    }
}
