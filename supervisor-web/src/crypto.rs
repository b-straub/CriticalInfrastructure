//! Command-envelope crypto: encrypt an outgoing command and verify the ESP's
//! signed, forward-secret response. Keeps the raw crypto out of the UI loop.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Encrypt a command to the ESP. Returns the wire payload
/// `eph_pub;iv;ciphertext` (hex) and the ephemeral secret needed to later
/// decrypt the response.
pub fn encrypt_command(
    seed: &[u8],
    cmd: &str,
    esp_pub_bytes: &[u8; 32],
    timestamp: u64,
) -> (String, StaticSecret) {
    // Sign "<ts>|<cmd>" with the role's Ed25519 key derived from the PRF seed.
    let signing_key = SigningKey::from_bytes(seed.try_into().unwrap());
    let signature = signing_key.sign(format!("{}|{}", timestamp, cmd).as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());
    let plaintext = format!("{};{};{}", timestamp, cmd, sig_hex);

    // Ephemeral X25519 -> DH against the ESP static pubkey -> AES-256-GCM.
    let mut eph_seed = [0u8; 32];
    OsRng.fill_bytes(&mut eph_seed);
    let ephemeral_secret = StaticSecret::from(eph_seed);
    let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);

    let esp_pub = X25519PublicKey::from(*esp_pub_bytes);
    let shared_secret = ephemeral_secret.diffie_hellman(&esp_pub);
    let tx_key_hash = Sha256::digest(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&tx_key_hash));

    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let mut ciphertext = plaintext.into_bytes();
    let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut ciphertext).unwrap();
    ciphertext.extend_from_slice(&tag);

    let payload = format!(
        "{};{};{}",
        hex::encode(ephemeral_pub.as_bytes()),
        hex::encode(iv),
        hex::encode(ciphertext)
    );
    (payload, ephemeral_secret)
}

/// Decrypt and verify an ESP response `<resp_eph_pub>;<iv>;<ct>`. Returns the
/// message on success, or a user-facing rejection reason.
///
/// Decryption alone is NOT trust: an active MITM can derive the ephemeral
/// response key. The response is accepted only if the ESP's Ed25519 signature
/// over "resp|<ts>|<message>" verifies against the provisioned signing pubkey
/// AND the timestamp matches our request.
pub fn verify_response(
    text: &str,
    ephemeral_secret: &StaticSecret,
    sig_pub_hex: &str,
    timestamp: u64,
) -> Result<String, String> {
    let mut parts = text.split(';');
    let resp_eph_pub_hex = parts.next().unwrap_or("");
    let resp_iv_hex = parts.next().unwrap_or("");
    let resp_cipher_hex = parts.next().unwrap_or("");

    let resp_eph_pub_bytes =
        <[u8; 32]>::try_from(hex::decode(resp_eph_pub_hex).unwrap_or_default().as_slice()).ok();
    let resp_iv = <[u8; 12]>::try_from(hex::decode(resp_iv_hex).unwrap_or_default().as_slice()).ok();
    let mut resp_cipher = hex::decode(resp_cipher_hex).unwrap_or_default();

    let (resp_eph_pub_bytes, resp_iv) = match (resp_eph_pub_bytes, resp_iv) {
        (Some(p), Some(iv)) if resp_cipher.len() >= 16 => (p, iv),
        _ => return Err("Invalid encrypted response envelope!".to_string()),
    };

    let resp_eph_pub = X25519PublicKey::from(resp_eph_pub_bytes);
    let dec_shared_secret = ephemeral_secret.diffie_hellman(&resp_eph_pub);
    let rx_key_hash = Sha256::digest(dec_shared_secret.as_bytes());
    let dec_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&rx_key_hash));

    let len = resp_cipher.len();
    let (msg, tag_bytes) = resp_cipher.split_at_mut(len - 16);
    let resp_tag = aes_gcm::Tag::from_slice(tag_bytes);
    let resp_nonce = Nonce::from_slice(&resp_iv);

    if dec_cipher.decrypt_in_place_detached(resp_nonce, b"", msg, resp_tag).is_err() {
        return Err("Failed to decrypt ESP32 response!".to_string());
    }
    let plaintext = core::str::from_utf8(msg).map_err(|_| "Response not UTF-8".to_string())?;

    // Plaintext is "<ts>;<message>;<sig_hex>".
    let mut rp = plaintext.splitn(3, ';');
    let rts = rp.next().unwrap_or("");
    let rmsg = rp.next().unwrap_or("");
    let rsig_hex = rp.next().unwrap_or("");

    let esp_sig_pub_bytes =
        <[u8; 32]>::try_from(hex::decode(sig_pub_hex).unwrap_or_default().as_slice()).ok();
    let sig_bytes = <[u8; 64]>::try_from(hex::decode(rsig_hex).unwrap_or_default().as_slice()).ok();

    let verified = match (esp_sig_pub_bytes, sig_bytes) {
        (Some(pk_bytes), Some(sb)) => match VerifyingKey::from_bytes(&pk_bytes) {
            Ok(vk) => vk
                .verify(
                    format!("resp|{}|{}", rts, rmsg).as_bytes(),
                    &Signature::from_bytes(&sb),
                )
                .is_ok(),
            Err(_) => false,
        },
        _ => false,
    };

    if verified && timestamp.to_string() == rts {
        Ok(rmsg.to_string())
    } else if verified {
        Err("Rejected: stale ESP32 response (timestamp mismatch)".to_string())
    } else {
        Err("Rejected: ESP32 response signature INVALID (possible MITM)".to_string())
    }
}
