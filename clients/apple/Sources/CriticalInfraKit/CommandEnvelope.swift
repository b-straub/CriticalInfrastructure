import CryptoKit
import Foundation

/// A built request envelope plus the ephemeral private key kept to decrypt the
/// device's forward-secret reply.
public struct CommandEnvelope {
    public let payload: String
    public let ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey
}

public enum EnvelopeError: Error, Equatable, CustomStringConvertible {
    case badDeviceKey
    case badResponseFormat
    case decryptFailed
    case notUtf8
    case signatureInvalid
    case staleTimestamp

    public var description: String {
        switch self {
        case .badDeviceKey: return "Invalid device ROM public key"
        case .badResponseFormat: return "Invalid encrypted response envelope"
        case .decryptFailed: return "Failed to decrypt device response"
        case .notUtf8: return "Device response not UTF-8"
        case .signatureInvalid: return "Response signature INVALID (possible MITM)"
        case .staleTimestamp: return "Stale device response (timestamp mismatch)"
        }
    }
}

/// The command-envelope crypto, byte-compatible with the firmware (`crypto.rs`,
/// `protocol.rs`):
///
///  request  = `eph_pub;iv;ciphertext+tag` (hex), inner `ts;cmd;ed25519_sig`
///  response = `eph_pub;iv;ciphertext+tag` (hex), inner `ts;message;ed25519_sig`
///
/// Key = `SHA-256( X25519(eph, peer_static) )` (raw DH bytes, **not** HKDF),
/// AES-256-GCM with empty AAD. The client signs `"ts|cmd"` (P-256 on the UDP
/// flavor); the device signs its reply `"resp|ts|msg"` with Ed25519.
public enum Envelope {

    /// Raw 32-byte X25519 output (matches x25519-dalek's `shared.as_bytes()`).
    private static func rawShared(_ s: SharedSecret) -> Data {
        Data(s.withUnsafeBytes { Array($0) })
    }

    private static func aesKey(_ shared: SharedSecret) -> SymmetricKey {
        SymmetricKey(data: Data(SHA256.hash(data: rawShared(shared))))
    }

    /// Build the wire payload and the ephemeral key. `sign` produces the 64-byte
    /// raw signature over `"<ts>|<cmd>"` (P-256 from the Secure Enclave / a
    /// hardware key on the UDP flavor).
    public static func encrypt(
        command: String,
        espX25519PubHex: String,
        timestamp: UInt64,
        sign: (Data) throws -> Data
    ) throws -> CommandEnvelope {
        guard let espPubBytes = Data(hex: espX25519PubHex), espPubBytes.count == 32,
              let espPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: espPubBytes)
        else { throw EnvelopeError.badDeviceKey }

        // Sign "<ts>|<cmd>" with the client key (the caller supplies the signer).
        let signature = try sign(Data("\(timestamp)|\(command)".utf8))
        let plaintext = "\(timestamp);\(command);\(signature.hexString)"

        // Ephemeral X25519 -> DH against the device static key -> AES-256-GCM.
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: espPub)
        let key = aesKey(shared)

        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(Data(plaintext.utf8), using: key, nonce: nonce)
        let iv = Data(nonce.withUnsafeBytes { Array($0) })
        let ctPlusTag = sealed.ciphertext + sealed.tag

        let payload = "\(ephemeral.publicKey.rawRepresentation.hexString);\(iv.hexString);\(ctPlusTag.hexString)"
        return CommandEnvelope(payload: payload, ephemeralPrivateKey: ephemeral)
    }

    /// Decrypt + verify a device reply. Returns the message, or throws a typed
    /// rejection. Decryption alone is not trust: the Ed25519 signature over
    /// `"resp|ts|message"` must verify AND the echoed timestamp must match.
    public static func verifyResponse(
        _ text: String,
        ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        espSigPubHex: String,
        timestamp: UInt64
    ) throws -> String {
        let parts = text.split(separator: ";", omittingEmptySubsequences: false)
        guard parts.count >= 3,
              let ephPubBytes = Data(hex: String(parts[0])), ephPubBytes.count == 32,
              let iv = Data(hex: String(parts[1])), iv.count == 12,
              let ctPlusTag = Data(hex: String(parts[2])), ctPlusTag.count >= 16,
              let respPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPubBytes)
        else { throw EnvelopeError.badResponseFormat }

        let shared = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: respPub)
        let key = aesKey(shared)

        let ciphertext = ctPlusTag.prefix(ctPlusTag.count - 16)
        let tag = ctPlusTag.suffix(16)
        let plaintextData: Data
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: iv),
                ciphertext: ciphertext,
                tag: tag
            )
            plaintextData = try AES.GCM.open(box, using: key)
        } catch {
            throw EnvelopeError.decryptFailed
        }
        guard let plaintext = String(data: plaintextData, encoding: .utf8) else {
            throw EnvelopeError.notUtf8
        }

        // Inner plaintext is "<ts>;<message>;<sig_hex>" (message has no ';').
        let comps = plaintext.split(separator: ";", maxSplits: 2, omittingEmptySubsequences: false)
        guard comps.count == 3 else { throw EnvelopeError.badResponseFormat }
        let rts = String(comps[0])
        let rmsg = String(comps[1])
        let rsigHex = String(comps[2])

        guard let sigPubBytes = Data(hex: espSigPubHex), sigPubBytes.count == 32,
              let sigBytes = Data(hex: rsigHex), sigBytes.count == 64,
              let sigPub = try? Curve25519.Signing.PublicKey(rawRepresentation: sigPubBytes)
        else { throw EnvelopeError.signatureInvalid }

        let signed = Data("resp|\(rts)|\(rmsg)".utf8)
        guard sigPub.isValidSignature(sigBytes, for: signed) else {
            throw EnvelopeError.signatureInvalid
        }
        guard rts == String(timestamp) else { throw EnvelopeError.staleTimestamp }
        return rmsg
    }
}
