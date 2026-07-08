import CryptoKit
import XCTest
@testable import CriticalInfraKit

/// Proves the Swift envelope is byte-compatible with the UDP-flavor firmware by
/// replicating the device side with CryptoKit: the client signs `"ts|cmd"` with
/// **P-256** (as the Secure Enclave does), the device verifies P-256, then signs
/// its reply with Ed25519 and the client verifies that.
final class EnvelopeTests: XCTestCase {

    private func rawShared(_ s: SharedSecret) -> Data { Data(s.withUnsafeBytes { Array($0) }) }
    private func key(_ s: SharedSecret) -> SymmetricKey { SymmetricKey(data: Data(SHA256.hash(data: rawShared(s)))) }

    func testRequestAndResponseRoundTrip() throws {
        // --- device identity ---
        let deviceX = Curve25519.KeyAgreement.PrivateKey()      // envelope DH
        let deviceSig = Curve25519.Signing.PrivateKey()         // response signing (Ed25519)
        let devicePubHex = deviceX.publicKey.rawRepresentation.hexString
        let deviceSigPubHex = deviceSig.publicKey.rawRepresentation.hexString

        // --- client identity: P-256 (Secure Enclave stand-in) + a command ---
        let clientKey = P256.Signing.PrivateKey()
        let ts: UInt64 = 1_700_000_000_000
        let cmd = Command.whoami

        // 1. Client builds the request envelope, signing "ts|cmd" with P-256.
        let env = try Envelope.encrypt(command: cmd, espX25519PubHex: devicePubHex, timestamp: ts) { msg in
            try clientKey.signature(for: msg).rawRepresentation
        }

        // 2. Device decrypts + verifies the P-256 signature (mirrors clientauth.rs).
        let parts = env.payload.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(parts.count, 3)
        let ephPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: XCTUnwrap(Data(hex: parts[0])))
        let iv = try XCTUnwrap(Data(hex: parts[1]))
        let ctTag = try XCTUnwrap(Data(hex: parts[2]))
        let reqKey = key(try deviceX.sharedSecretFromKeyAgreement(with: ephPub))
        let reqBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: iv),
            ciphertext: ctTag.prefix(ctTag.count - 16),
            tag: ctTag.suffix(16)
        )
        let inner = try XCTUnwrap(String(data: AES.GCM.open(reqBox, using: reqKey), encoding: .utf8))
        let ic = inner.split(separator: ";", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(ic[0], String(ts))
        XCTAssertEqual(ic[1], cmd)
        let clientSig = try P256.Signing.ECDSASignature(rawRepresentation: XCTUnwrap(Data(hex: ic[2])))
        XCTAssertTrue(clientKey.publicKey.isValidSignature(clientSig, for: Data("\(ts)|\(cmd)".utf8)),
                      "device must accept the client's P-256 signature over \"ts|cmd\"")

        // 3. Device builds the signed, forward-secret response (mirrors crypto.rs).
        let message = "Supervisor"
        let rsig = try deviceSig.signature(for: Data("resp|\(ts)|\(message)".utf8))
        let respPlain = "\(ts);\(message);\(rsig.hexString)"
        let respEph = Curve25519.KeyAgreement.PrivateKey()
        let respKey = key(try respEph.sharedSecretFromKeyAgreement(with: ephPub))
        let respNonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(Data(respPlain.utf8), using: respKey, nonce: respNonce)
        let respPayload = [
            respEph.publicKey.rawRepresentation.hexString,
            Data(respNonce.withUnsafeBytes { Array($0) }).hexString,
            (sealed.ciphertext + sealed.tag).hexString
        ].joined(separator: ";")

        // 4. Client verifies the response.
        let msg = try Envelope.verifyResponse(
            respPayload,
            ephemeralPrivateKey: env.ephemeralPrivateKey,
            espSigPubHex: deviceSigPubHex,
            timestamp: ts
        )
        XCTAssertEqual(msg, message)
    }

    func testForgedResponseSignatureRejected() throws {
        let deviceX = Curve25519.KeyAgreement.PrivateKey()
        let realSig = Curve25519.Signing.PrivateKey()
        let attackerSig = Curve25519.Signing.PrivateKey() // signs, but wrong key
        let clientKey = P256.Signing.PrivateKey()
        let ts: UInt64 = 1_700_000_000_001

        let env = try Envelope.encrypt(command: Command.readSensor,
                                       espX25519PubHex: deviceX.publicKey.rawRepresentation.hexString,
                                       timestamp: ts) { try clientKey.signature(for: $0).rawRepresentation }
        let reqEph = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: XCTUnwrap(Data(hex: env.payload.split(separator: ";").map(String.init)[0])))

        // Attacker can derive the ephemeral response key (MITM) but not forge the
        // device's Ed25519 signature.
        let message = "Temp: 20.0C, RH: 50.0%"
        let rsig = try attackerSig.signature(for: Data("resp|\(ts)|\(message)".utf8))
        let respEph = Curve25519.KeyAgreement.PrivateKey()
        let respKey = key(try respEph.sharedSecretFromKeyAgreement(with: reqEph))
        let respNonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(Data("\(ts);\(message);\(rsig.hexString)".utf8), using: respKey, nonce: respNonce)
        let respPayload = [
            respEph.publicKey.rawRepresentation.hexString,
            Data(respNonce.withUnsafeBytes { Array($0) }).hexString,
            (sealed.ciphertext + sealed.tag).hexString
        ].joined(separator: ";")

        XCTAssertThrowsError(try Envelope.verifyResponse(
            respPayload, ephemeralPrivateKey: env.ephemeralPrivateKey,
            espSigPubHex: realSig.publicKey.rawRepresentation.hexString, timestamp: ts
        )) { error in
            XCTAssertEqual(error as? EnvelopeError, .signatureInvalid)
        }
    }

    func testStaleTimestampRejected() throws {
        let deviceX = Curve25519.KeyAgreement.PrivateKey()
        let deviceSig = Curve25519.Signing.PrivateKey()
        let clientKey = P256.Signing.PrivateKey()
        let ts: UInt64 = 1_700_000_000_002

        let env = try Envelope.encrypt(command: Command.whoami,
                                       espX25519PubHex: deviceX.publicKey.rawRepresentation.hexString,
                                       timestamp: ts) { try clientKey.signature(for: $0).rawRepresentation }
        let reqEph = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: XCTUnwrap(Data(hex: env.payload.split(separator: ";").map(String.init)[0])))

        // Device signs correctly, but echoes a DIFFERENT timestamp.
        let wrongTs = ts - 1
        let message = "Supervisor"
        let rsig = try deviceSig.signature(for: Data("resp|\(wrongTs)|\(message)".utf8))
        let respEph = Curve25519.KeyAgreement.PrivateKey()
        let respKey = key(try respEph.sharedSecretFromKeyAgreement(with: reqEph))
        let respNonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(Data("\(wrongTs);\(message);\(rsig.hexString)".utf8), using: respKey, nonce: respNonce)
        let respPayload = [
            respEph.publicKey.rawRepresentation.hexString,
            Data(respNonce.withUnsafeBytes { Array($0) }).hexString,
            (sealed.ciphertext + sealed.tag).hexString
        ].joined(separator: ";")

        XCTAssertThrowsError(try Envelope.verifyResponse(
            respPayload, ephemeralPrivateKey: env.ephemeralPrivateKey,
            espSigPubHex: deviceSig.publicKey.rawRepresentation.hexString, timestamp: ts
        )) { error in
            XCTAssertEqual(error as? EnvelopeError, .staleTimestamp)
        }
    }
}
