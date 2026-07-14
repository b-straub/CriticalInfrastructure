//! Device cryptographic identity.
//!
//! Two provisioning paths, selected by the `efuse-hmac-identity` feature:
//! - production: seeds derived from a read-protected eFuse key via the hardware
//!   HMAC-SHA256 peripheral (the key never leaves hardware);
//! - dev/default: seed stored in / generated to plain flash, with a loud
//!   NOT-PRODUCTION-SAFE banner.
//!
//! Returns the ready X25519 (command envelope) and Ed25519 (response signing)
//! keys, logging both public keys for provisioning into the WebApp.

use ed25519_dalek::SigningKey;
use log::info;
use x25519_dalek::{PublicKey, StaticSecret};

fn finalize(x25519_seed: [u8; 32], ed25519_seed: [u8; 32]) -> (StaticSecret, SigningKey) {
    use core::fmt::Write as _;

    let esp_x25519_secret = StaticSecret::from(x25519_seed);
    let esp_signing_key = SigningKey::from_bytes(&ed25519_seed);

    let mut esp_sig_pub_hex = heapless::String::<64>::new();
    for b in esp_signing_key.verifying_key().to_bytes() {
        let _ = write!(&mut esp_sig_pub_hex, "{:02x}", b);
    }
    info!("ESP32 Ed25519 Response-Signing PubKey: {}", esp_sig_pub_hex);

    let esp_x25519_pub = PublicKey::from(&esp_x25519_secret);
    let mut hex_x25519 = heapless::String::<64>::new();
    for b in esp_x25519_pub.as_bytes() {
        let _ = write!(&mut hex_x25519, "{:02x}", b);
    }
    info!("ESP32 X25519 PubKey: {}", hex_x25519);

    (esp_x25519_secret, esp_signing_key)
}

/// PRODUCTION: derive both seeds from a read-protected eFuse key via the
/// hardware HMAC-SHA256 peripheral. The key is read by the HMAC engine directly
/// from eFuse and is NEVER exposed to software -- the entire point of
/// read-protection. Burn a 256-bit HMAC_UP key into eFuse block 0.
#[cfg(feature = "efuse-hmac-identity")]
pub fn derive_identity(
    sha: esp_hal::peripherals::SHA<'_>,
    hmac_periph: esp_hal::peripherals::HMAC<'_>,
) -> (StaticSecret, SigningKey) {
    use esp_hal::hmac::{Hmac, HmacPurpose, KeyId};
    info!("Deriving device identity from read-protected eFuse HMAC key (hardware-only root).");
    // The HMAC core is driven by the SHA core; hold the SHA peripheral so its
    // clock stays enabled for the duration of the derivation.
    let _sha_clock = esp_hal::sha::Sha::new(sha);
    let mut hmac = Hmac::new(hmac_periph);
    fn kdf(hmac: &mut Hmac, label: &[u8]) -> [u8; 32] {
        hmac.init();
        if hmac.configure(HmacPurpose::ToUser, KeyId::Key0).is_err() {
            // No fallback: a production build with no provisioned eFuse key must
            // fail loudly rather than silently derive a software key.
            panic!("eFuse HMAC key (block 0, purpose HMAC_UP) not provisioned");
        }
        let mut rem: &[u8] = label;
        while !rem.is_empty() {
            if let Ok(r) = hmac.update(rem) {
                rem = r;
            }
        }
        let mut out = [0u8; 32];
        while hmac.finalize(&mut out).is_err() {}
        out
    }
    let x = kdf(&mut hmac, b"esp-x25519-identity-v1");
    let e = kdf(&mut hmac, b"esp-ed25519-signing-v1");
    finalize(x, e)
}

/// DEV/PROVISIONING (default): seed from flash, or generate + persist to PLAIN
/// flash on first boot (with a NOT-PRODUCTION-SAFE banner).
#[cfg(not(feature = "efuse-hmac-identity"))]
pub fn derive_identity(rng: &mut esp_hal::rng::Rng) -> (StaticSecret, SigningKey) {
    use embedded_storage::{ReadStorage, Storage};
    use esp_storage::FlashStorage;

    let mut flash = FlashStorage::new(unsafe { esp_hal::peripherals::FLASH::steal() });
    let mut seed_buf = [0u8; 4096];
    let mut esp_seed = [0u8; 32];
    let mut has_seed = false;

    if flash.read(0x210000, &mut seed_buf).is_ok() {
        let is_empty = seed_buf[0..32].iter().all(|&b| b == 0xFF || b == 0x00);
        if !is_empty {
            esp_seed.copy_from_slice(&seed_buf[0..32]);
            has_seed = true;
        }
    }

    if !has_seed {
        for chunk in esp_seed.chunks_mut(4) {
            let rand_val = rng.random();
            chunk.copy_from_slice(&rand_val.to_le_bytes());
        }
        let mut write_buf = [0u8; 4096];
        write_buf[0..32].copy_from_slice(&esp_seed);
        let _ = flash.write(0x210000, &write_buf);

        log::error!("");
        log::error!("\x1b[1;97;41m ================================================================ \x1b[0m");
        log::error!("\x1b[1;97;41m  !!  NOT PRODUCTION SAFE  --  STATIC KEY STORED IN PLAIN FLASH  !! \x1b[0m");
        log::error!("\x1b[1;97;41m ================================================================ \x1b[0m");
        log::error!("\x1b[1;91m  The long-term X25519 ROM secret was written UNENCRYPTED to flash\x1b[0m");
        log::error!("\x1b[1;91m  at 0x210000. Anyone with physical access can read or replace it.\x1b[0m");
        log::error!("\x1b[1;91m  Build with --features efuse-hmac-identity and burn an eFuse HMAC\x1b[0m");
        log::error!("\x1b[1;91m  key for production (docs/formal/EFUSE-HARDENING.md).\x1b[0m");
        log::error!("\x1b[1;97;41m ================================================================ \x1b[0m");
        log::error!("");
    }

    // Domain-separate the Ed25519 signing seed from the X25519 seed.
    let ed25519_seed = {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(esp_seed);
        hasher.update(b"esp-ed25519-signing-v1");
        let digest = hasher.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&digest);
        s
    };
    finalize(esp_seed, ed25519_seed)
}
