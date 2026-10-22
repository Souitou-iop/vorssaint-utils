// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Vorssaint

import Foundation
import Security
import CommonCrypto

enum FanControlIdentifiers {
    static let teamID = "3D485NHW29"

    #if VORSSAINT_DEVELOPMENT
    static let appBundleID = "com.vorssaint.utils.dev"
    #else
    static let appBundleID = "com.vorssaint.utils"
    #endif

    static let helperID = "\(appBundleID).fan-control"
    static let plistName = "\(helperID).plist"

    static let appCodeRequirement = codeRequirement(identifier: appBundleID)
    static let helperCodeRequirement = codeRequirement(identifier: helperID)

    /// The official build is Developer ID signed by `teamID` and keeps that requirement. A local build signed with a
    /// self-signed identity (Tools/setup-signing.sh) can never meet it, so the app and the helper, both signed with
    /// that one certificate, require each other to carry exactly that leaf certificate instead.
    private static func codeRequirement(identifier: String) -> String {
        if let leaf = selfSignedLeafSHA1() {
            return "identifier \"\(identifier)\" and certificate leaf = H\"\(leaf)\""
        }
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"\(identifier)\""
    }

    /// SHA-1 of this process's own leaf certificate when it is not signed by `teamID`; nil for the official build
    /// and for ad-hoc signatures (no certificate), which keep the official requirement.
    private static func selfSignedLeafSHA1() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        if let team = dict[kSecCodeInfoTeamIdentifier as String] as? String, team == teamID { return nil }
        guard let certificates = dict[kSecCodeInfoCertificates as String] as? [SecCertificate],
              let leaf = certificates.first else { return nil }
        let der = SecCertificateCopyData(leaf) as Data
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        der.withUnsafeBytes { _ = CC_SHA1($0.baseAddress, CC_LONG(der.count), &digest) }
        return digest.map { String(format: "%02X", $0) }.joined()
    }
}

@objc protocol FanControlXPCProtocol {
    func status(withReply reply: @escaping (Data) -> Void)
    func startMaximumCooling(withReply reply: @escaping (Data) -> Void)
    func applyConfiguration(_ configuration: Data, withReply reply: @escaping (Data) -> Void)
    func heartbeat(withReply reply: @escaping (Data) -> Void)
    func restoreAutomatic(withReply reply: @escaping (Data) -> Void)
}

enum FanControlIPC {
    static func encode(_ response: FanControlResponse) -> Data {
        // Every value in this closed response model is JSON encodable. Keeping
        // one deterministic fallback avoids ever violating the XPC reply shape.
        (try? JSONEncoder().encode(response))
            ?? Data(#"{"succeeded":false,"snapshot":{"fans":[],"isCooling":false},"error":"controlFailed"}"#.utf8)
    }

    static func decode(_ data: Data) -> FanControlResponse? {
        try? JSONDecoder().decode(FanControlResponse.self, from: data)
    }

    static func encode(_ configuration: FanControlConfiguration) -> Data? {
        try? JSONEncoder().encode(configuration)
    }

    static func decodeConfiguration(_ data: Data) -> FanControlConfiguration? {
        guard let configuration = try? JSONDecoder().decode(FanControlConfiguration.self,
                                                              from: data),
              FanControlPolicy.validConfiguration(configuration) else { return nil }
        return configuration
    }
}
