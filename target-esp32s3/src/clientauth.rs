//! Client-signature verification.
//!
//! Native clients (the macOS app's Secure Enclave, or a PIV hardware security key)
//! authenticate with **P-256 ECDSA**. Only this module is curve-aware; the rest of
//! the firmware handles opaque public-key and 64-byte signature bytes. The device
//! response is still signed with the device's Ed25519 key (see `crypto.rs`) and the
//! envelope is still X25519 — this is only the client→device auth signature.

/// Expected client public-key length on the wire, in hex chars.
pub const CLIENT_PK_HEX_LEN: usize = 66; // P-256 compressed SEC1 point (33 bytes)

/// Verify a 64-byte client signature over `msg` against `pubkey`.
/// Returns false on any parse or verification failure.
pub fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8; 64]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(sig) else {
        return false;
    };
    // P-256 ECDSA over SHA-256(msg) -- matches CryptoKit's
    // P256.Signing `.signature(for:)` (which hashes with SHA-256).
    verifying_key.verify(msg, &signature).is_ok()
}
