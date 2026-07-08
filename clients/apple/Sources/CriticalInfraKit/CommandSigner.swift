import Foundation

/// Produces the client's command signature. The UDP flavor authenticates with
/// P-256 (Secure Enclave now, a hardware security key later) — the returned
/// signature is 64 raw bytes (r||s) and the public key is the 33-byte compressed
/// point as hex, matching the firmware's `clientauth` P-256 verification.
public protocol CommandSigner: Sendable {
    /// Compressed public key, hex (66 chars for P-256). Provision this on the
    /// device: bake it as `SUPERVISOR_PUBKEY`, or `ADD_ROLE` it.
    var publicKeyHex: String { get }

    /// Sign `message`, returning a 64-byte raw signature.
    func sign(_ message: Data) throws -> Data
}
