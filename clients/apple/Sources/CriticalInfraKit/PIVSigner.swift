import CryptoKit
import Foundation
import Security

public enum PIVError: Error, CustomStringConvertible {
    case noKey
    case signFailed(String)

    public var description: String {
        switch self {
        case .noKey:
            return "No P-256 smart-card key found. Insert a PIV key with an ECC P-256 key + cert in slot 9c."
        case .signFailed(let m):
            return "Hardware signature failed: \(m)"
        }
    }
}

/// A P-256 signing key on an inserted **PIV smart card / hardware security key**
/// (e.g. slot 9c), reached through macOS CryptoTokenKit. Signs raw ECDSA P-256 —
/// the *same* signature the Secure Enclave produces, so the firmware can't tell
/// them apart. Every signature prompts the card's **PIN** (and touch, if the key
/// enforces it). Implements the same `CommandSigner` protocol as `EnclaveSigner`.
///
/// The key must be **ECC P-256** and paired with a certificate in the slot (macOS
/// only surfaces a card key to the keychain when a matching cert is present).
public final class PIVSigner: CommandSigner, @unchecked Sendable {
    private let privateKey: SecKey
    private let compressedPublicKey: Data

    public init() throws {
        guard let found = Self.findKey() else { throw PIVError.noKey }
        privateKey = found.0
        compressedPublicKey = found.1
    }

    /// 33-byte compressed P-256 public key as hex (66 chars) — provision this.
    public var publicKeyHex: String { compressedPublicKey.hexString }

    /// ECDSA over SHA-256(message) on the card — prompts for the PIV PIN. macOS
    /// returns a DER signature; CryptoKit reshapes it to the raw 64-byte r‖s the
    /// firmware's p256 verifier expects.
    public func sign(_ message: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) as Data? else {
            throw PIVError.signFailed(error?.takeRetainedValue().localizedDescription ?? "unknown")
        }
        do {
            return try P256.Signing.ECDSASignature(derRepresentation: der).rawRepresentation
        } catch {
            throw PIVError.signFailed("unexpected signature encoding")
        }
    }

    /// Compressed P-256 pubkey hex of an inserted smart-card key, or nil if none.
    /// Silent — reading the public key does not prompt for a PIN.
    public static func detect() -> String? { findKey()?.1.hexString }

    /// Human-readable name of the inserted token's P-256 key, from the subject of
    /// the certificate paired with it in the slot (e.g. "CriticalInfra Supervisor").
    /// Used to prefill the role's key label when provisioning a hardware key.
    public static func tokenKeyName() -> String? {
        guard let (privateKey, _) = findKey(),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let keyX963 = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrAccessGroup as String: kSecAttrAccessGroupToken,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let certs = out as? [SecCertificate] else { return nil }
        for cert in certs {
            guard let certKey = SecCertificateCopyKey(cert),
                  let certX963 = SecKeyCopyExternalRepresentation(certKey, nil) as Data?,
                  certX963 == keyX963 else { continue }
            return SecCertificateCopySubjectSummary(cert) as String?
        }
        return nil
    }

    /// Find the first ECC P-256 private key exposed by a smart-card token.
    private static func findKey() -> (SecKey, Data)? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrAccessGroup as String: kSecAttrAccessGroupToken, // smart-card token keychain
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let keys = out as? [SecKey] else { return nil }

        for key in keys {
            guard let publicKey = SecKeyCopyPublicKey(key),
                  let x963 = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
                  let cryptoKitKey = try? P256.Signing.PublicKey(x963Representation: x963) else {
                continue
            }
            return (key, cryptoKitKey.compressedRepresentation)
        }
        return nil
    }
}
