import CryptoKit
import Foundation
import Security

public enum EnclaveError: Error, CustomStringConvertible {
    case unavailable
    case noKey
    case accessControl

    public var description: String {
        switch self {
        case .unavailable: return "This Mac has no Secure Enclave."
        case .noKey: return "No Secure Enclave key for that identity yet."
        case .accessControl: return "Could not create the biometric access policy."
        }
    }
}

/// A P-256 signing key held in this Mac's **Secure Enclave**, one per identity
/// (`id` = the role name: "Supervisor" / "Admin" / "Operator" / "Observer").
///
/// The private key never leaves the enclave; every signature requires user
/// presence (Touch ID / password). Each identity's opaque, enclave-bound
/// reference blob is kept in the Keychain under its own account, so a Mac can
/// hold several identities and pick between them.
public final class EnclaveSigner: CommandSigner, @unchecked Sendable {
    public let id: String
    private let key: SecureEnclave.P256.Signing.PrivateKey

    /// Load the enclave key for `id`, or create one when `createIfMissing`.
    public init(id: String, createIfMissing: Bool = false) throws {
        guard SecureEnclave.isAvailable else { throw EnclaveError.unavailable }
        self.id = id
        if let blob = Self.loadBlob(id: id) {
            key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        } else if createIfMissing {
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence],
                nil
            ) else { throw EnclaveError.accessControl }
            key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
            Self.saveBlob(key.dataRepresentation, id: id)
        } else {
            throw EnclaveError.noKey
        }
    }

    /// 33-byte compressed P-256 public key as hex (66 chars).
    public var publicKeyHex: String {
        key.publicKey.compressedRepresentation.hexString
    }

    /// ECDSA over SHA-256(message) inside the enclave — prompts for Touch ID.
    public func sign(_ message: Data) throws -> Data {
        try key.signature(for: message).rawRepresentation
    }

    // MARK: - Identity management

    /// The ids (role names) that have an enclave key on this Mac.
    public static func existingIds() -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let items = out as? [[String: Any]] else { return [] }
        return items
            .compactMap { $0[kSecAttrAccount as String] as? String }
            .filter { $0.hasPrefix(accountPrefix) }
            .map { String($0.dropFirst(accountPrefix.count)) }
    }

    /// Public key hex for an existing identity, without keeping the signer.
    public static func publicKeyHex(id: String) -> String? {
        (try? EnclaveSigner(id: id))?.publicKeyHex
    }

    /// Forget one identity's key.
    public static func reset(id: String) {
        SecItemDelete(baseQuery(id: id) as CFDictionary)
    }

    // MARK: - Keychain persistence (per id). The blob is useless without *this*
    // machine's Secure Enclave, so a normal Keychain item is fine.

    private static let service = "criticalinfra"
    private static let accountPrefix = "enclave.p256."

    private static func baseQuery(id: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: accountPrefix + id
        ]
    }

    private static func loadBlob(id: String) -> Data? {
        var query = baseQuery(id: id)
        query[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    private static func saveBlob(_ data: Data, id: String) {
        SecItemDelete(baseQuery(id: id) as CFDictionary)
        var add = baseQuery(id: id)
        add[kSecValueData as String] = data
        SecItemAdd(add as CFDictionary, nil)
    }
}
