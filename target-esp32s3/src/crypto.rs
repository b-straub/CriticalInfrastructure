//! Response crypto: build the signed, forward-secret, AES-GCM-encrypted reply.

use ed25519_dalek::{Signer, SigningKey};
use esp_hal::rng::Rng;

/// Produce the wire response `<resp_eph_pub>;<iv>;<ciphertext+tag>` (all hex).
///
/// The payload is `ts;message;sig`, where `sig` is the ESP's Ed25519 signature
/// over `resp|ts|message` (verified by the WebApp against the ESP's provisioned
/// pubkey — this is what makes the response unforgeable; the AES-GCM tag alone
/// only proves knowledge of a key an active MITM can also derive). The AES key
/// comes from an ephemeral x ephemeral X25519 DH (perfect forward secrecy), with
/// the ephemeral key and GCM nonce drawn from the hardware TRNG.
pub fn build_signed_response(
    resp_ts: &str,
    message: &str,
    esp_signing_key: &SigningKey,
    client_ephemeral_pub: &[u8; 32],
    rng: &mut Rng,
) -> heapless::String<2560> {
    use core::fmt::Write as _;
    #[allow(deprecated)]
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    #[allow(deprecated)]
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use sha2::Digest as _;

    let mut final_response = heapless::String::<2560>::new();

    // Sign "resp|<ts>|<message>": binds the response to this request and proves
    // it originated from this device's signing key.
    let mut resp_signed = heapless::String::<560>::new();
    let _ = write!(&mut resp_signed, "resp|{}|{}", resp_ts, message);
    let resp_signature = esp_signing_key.sign(resp_signed.as_bytes());
    let mut resp_sig_hex = heapless::String::<128>::new();
    for b in resp_signature.to_bytes() {
        let _ = write!(&mut resp_sig_hex, "{:02x}", b);
    }

    // Inner plaintext that gets AES-GCM encrypted below: ts;message;sig
    let mut plaintext = heapless::String::<768>::new();
    let _ = write!(&mut plaintext, "{};{};{}", resp_ts, message, resp_sig_hex);

    // Fresh ephemeral X25519 keypair from the hardware TRNG. Deriving it from a
    // timer would make the private key low-entropy / reconstructable from the
    // public IV and risk (key, nonce) reuse. The RNG is a true RNG here because
    // the Wi-Fi radio is enabled.
    let mut resp_ephemeral_seed = [0u8; 32];
    rng.read(&mut resp_ephemeral_seed);
    let resp_ephemeral_secret = x25519_dalek::StaticSecret::from(resp_ephemeral_seed);
    let resp_ephemeral_pub = x25519_dalek::PublicKey::from(&resp_ephemeral_secret);

    // DH against the client's request ephemeral pubkey -> fresh per-response key.
    let ephemeral_pub = x25519_dalek::PublicKey::from(*client_ephemeral_pub);
    let resp_shared_secret = resp_ephemeral_secret.diffie_hellman(&ephemeral_pub);
    let tx_key_hash = sha2::Sha256::digest(resp_shared_secret.as_bytes());

    #[allow(deprecated)]
    let key = Key::<Aes256Gcm>::from_slice(&tx_key_hash);
    let cipher = Aes256Gcm::new(key);

    // Fresh random 96-bit GCM nonce from the TRNG.
    let mut iv = [0u8; 12];
    rng.read(&mut iv);
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&iv);

    let mut ciphertext = heapless::Vec::<u8, 1024>::new();
    let _ = ciphertext.extend_from_slice(plaintext.as_bytes());

    #[allow(deprecated)]
    if let Ok(tag) = cipher.encrypt_in_place_detached(nonce, b"", &mut ciphertext) {
        let _ = ciphertext.extend_from_slice(&tag);

        let mut iv_hex_out = heapless::String::<24>::new();
        for b in iv {
            let _ = write!(&mut iv_hex_out, "{:02x}", b);
        }

        let mut cipher_hex_out = heapless::String::<2048>::new();
        for b in ciphertext.as_slice() {
            let _ = write!(&mut cipher_hex_out, "{:02x}", b);
        }

        let mut resp_eph_pub_hex = heapless::String::<64>::new();
        for b in resp_ephemeral_pub.as_bytes() {
            let _ = write!(&mut resp_eph_pub_hex, "{:02x}", b);
        }

        let _ = write!(&mut final_response, "{};{};{}", resp_eph_pub_hex, iv_hex_out, cipher_hex_out);
    } else {
        let _ = write!(&mut final_response, "Encryption Error");
    }

    final_response
}
