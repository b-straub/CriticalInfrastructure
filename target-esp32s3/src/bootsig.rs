//! Verify an incoming OTA image's **Secure Boot v2 (RSA-3072-PSS)** signature at *receive*
//! time — before the slot is activated — so an unsigned or garbage push is never booted (no
//! reboot churn). This is the same signature the bootloader checks on boot; verifying it here
//! too just moves the rejection earlier, using the same trust anchor (no separate key).
//!
//! Layout of the appended signature-block sector (proven against a real signed image):
//!   `0x000` magic `0xe7` · `0x001` version `0x02` (RSA)
//!   `0x004..0x024` image digest — SHA-256 of the image body (everything before this sector)
//!   `0x024..0x1a4` RSA modulus n (little-endian) · `0x1a4..0x1a8` exponent e (LE)
//!   `0x024..0x32c` public-key section — SHA-256 of it is the burned `SECURE_BOOT_DIGEST`
//!   `0x32c..0x4ac` RSA-PSS signature (little-endian) over the image digest
//!
//! Trusted digests are baked at build time from the enrolled keys (`SECURE_BOOT_DIGESTS`), so
//! this is a fast, self-contained pre-check; Secure Boot in the bootloader remains the ultimate
//! on-boot enforcer.

use rsa::pss::{Signature, VerifyingKey};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::{BigUint, RsaPublicKey};

/// Trusted `SECURE_BOOT_DIGEST` values (SHA-256 of each signing key's public section), baked
/// from the enrolled keys by `provision/3` as a comma-separated hex list. Empty (no env) means
/// "trust nothing" — every push is rejected, which is the safe default.
fn trusted_digests() -> heapless::Vec<[u8; 32], 4> {
    let mut out = heapless::Vec::new();
    let Some(list) = option_env!("SECURE_BOOT_DIGESTS") else {
        return out;
    };
    for tok in list.split(',') {
        let tok = tok.trim();
        if tok.len() != 64 {
            continue;
        }
        let mut d = [0u8; 32];
        let mut ok = true;
        for (i, b) in d.iter_mut().enumerate() {
            match u8::from_str_radix(&tok[i * 2..i * 2 + 2], 16) {
                Ok(v) => *b = v,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            let _ = out.push(d);
        }
    }
    out
}

/// Verify the signature block against the already-computed `body_digest` (SHA-256 of the image
/// body, everything before the signature sector). Returns Ok only if the block is a well-formed
/// v2 RSA block, its embedded key is trusted, and the PSS signature over `body_digest` checks.
pub fn verify(body_digest: &[u8; 32], sig_block: &[u8]) -> Result<(), &'static str> {
    if sig_block.len() < 1196 {
        return Err("sig block too short");
    }
    if sig_block[0] != 0xe7 {
        return Err("sig block magic");
    }
    if sig_block[1] != 0x02 {
        return Err("sig block version (want RSA)");
    }
    // 1. the received image really is the one this block claims was signed
    if &sig_block[4..36] != body_digest {
        return Err("image digest mismatch");
    }
    // 2. the embedded public key is one we trust (its digest is a burned SECURE_BOOT_DIGEST)
    let pk_digest = Sha256::digest(&sig_block[36..812]);
    let trusted = trusted_digests();
    if !trusted.iter().any(|t| t[..] == pk_digest[..]) {
        return Err("untrusted signing key");
    }
    // 3. reconstruct the RSA-3072 public key (modulus + exponent are little-endian in the block)
    let mut n = [0u8; 384];
    n.copy_from_slice(&sig_block[36..420]);
    n.reverse();
    let n = BigUint::from_bytes_be(&n);
    let e = BigUint::from(u32::from_le_bytes([
        sig_block[420],
        sig_block[421],
        sig_block[422],
        sig_block[423],
    ]));
    let key = RsaPublicKey::new(n, e).map_err(|_| "bad public key")?;
    // 4. RSA-PSS verify the (little-endian) signature over the image digest
    let mut sig = [0u8; 384];
    sig.copy_from_slice(&sig_block[812..1196]);
    sig.reverse();
    let signature = Signature::try_from(sig.as_slice()).map_err(|_| "bad signature bytes")?;
    VerifyingKey::<Sha256>::new(key)
        .verify_prehash(body_digest, &signature)
        .map_err(|_| "PSS verify failed")
}
