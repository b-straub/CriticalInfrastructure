//! Client-signature verification, abstracted over the auth curve so the two ROM
//! flavors can differ:
//!
//! - **HTTP / web flavor** authenticates clients with **Ed25519** (the WebAuthn
//!   passkey-PRF keys the browser dashboard uses).
//! - **UDP flavor** authenticates clients with **P-256 ECDSA** — the keys a Mac's
//!   Secure Enclave or a hardware security key (PIV) can hold and sign with.
//!
//! Only this module is curve-aware; the rest of the firmware handles opaque
//! public-key and 64-byte signature bytes. Signatures are 64 bytes for both
//! curves (Ed25519 R||s, or P-256 raw r||s), so nothing else changes. The device
//! response is still signed with the device's Ed25519 key (see `crypto.rs`) and
//! the envelope is still X25519 — this is only the client→device auth signature.

/// Expected client public-key length on the wire, in hex chars.
#[cfg(feature = "udp-transport")]
pub const CLIENT_PK_HEX_LEN: usize = 66; // P-256 compressed SEC1 point (33 bytes)
#[cfg(not(feature = "udp-transport"))]
pub const CLIENT_PK_HEX_LEN: usize = 64; // Ed25519 (32 bytes)

/// Verify a 64-byte client signature over `msg` against `pubkey`.
/// Returns false on any parse or verification failure.
pub fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8; 64]) -> bool {
    #[cfg(feature = "udp-transport")]
    {
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
    #[cfg(not(feature = "udp-transport"))]
    {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Ok(pk_array) = <[u8; 32]>::try_from(pubkey) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_array) else {
            return false;
        };
        verifying_key.verify(msg, &Signature::from_bytes(sig)).is_ok()
    }
}
