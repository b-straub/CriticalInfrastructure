//! Command processing.
//!
//! Decrypt the envelope, verify the client's P-256 signature (via `clientauth`)
//! against the supervisor key or a provisioned role, run the authorized command,
//! and build the signed, encrypted response. This is the single source of truth
//! for the security-critical path: the UDP serve loop calls `process_envelope`,
//! so the crypto lives in exactly one place.

use ed25519_dalek::SigningKey;
use esp_hal::rng::Rng;
use log::info;
use shared::terminology::*;
use smart_leds::{colors, RGB8};
use x25519_dalek::StaticSecret;

use crate::clientauth;
use crate::commands;
use crate::crypto;
use crate::state::*;

/// The outcome of processing one envelope: the wire response to send back, plus
/// the display decisions for the caller to apply. Keeping the LCD/LED writes out
/// of here lets this module stay free of the concrete driver types.
pub struct ProcessResult {
    /// `<eph_pub>;<iv>;<ciphertext+tag>` (hex) -- send this back to the peer.
    pub response: heapless::String<2560>,
    /// LED ring color to show now (Some only when a command was authorized).
    pub led: Option<[RGB8; 8]>,
    /// LCD line-2 status text (None when the envelope failed before dispatch).
    pub status_line: Option<heapless::String<16>>,
}

/// Decrypt + verify + dispatch one command envelope. `payload` is the raw
/// `<eph_pub>;<iv>;<ciphertext>` string with no transport framing.
pub fn process_envelope(
    payload: &str,
    esp_x25519_secret: &StaticSecret,
    esp_signing_key: &SigningKey,
    rng: &mut Rng,
) -> ProcessResult {
    use core::fmt::Write as _;

    // Compile-time supervisor trust anchor (P-256 compressed, 33 bytes --
    // length from clientauth::CLIENT_PK_HEX_LEN).
    let mut supervisor_key = heapless::Vec::<u8, 33>::new();
    if let Some(raw_hex_str) = option_env!("SUPERVISOR_PUBKEY") {
        let hex_str = raw_hex_str.trim();
        if hex_str.len() == clientauth::CLIENT_PK_HEX_LEN {
            for i in 0..(clientauth::CLIENT_PK_HEX_LEN / 2) {
                if let Ok(b) = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16) {
                    let _ = supervisor_key.push(b);
                }
            }
        }
    }

    let mut parts = payload.split(';');
    let ephemeral_pub_hex = parts.next().unwrap_or("");
    let iv_hex = parts.next().unwrap_or("");
    let ciphertext_hex = parts.next().unwrap_or("");

    let mut valid_crypto = true;
    let mut ephemeral_pub_bytes = [0u8; 32];
    if ephemeral_pub_hex.len() == 64 {
        for i in 0..32 {
            if let Ok(b) = u8::from_str_radix(&ephemeral_pub_hex[i * 2..i * 2 + 2], 16) {
                ephemeral_pub_bytes[i] = b;
            } else {
                valid_crypto = false;
            }
        }
    } else {
        valid_crypto = false;
    }

    let mut iv = [0u8; 12];
    if iv_hex.len() == 24 {
        for i in 0..12 {
            if let Ok(b) = u8::from_str_radix(&iv_hex[i * 2..i * 2 + 2], 16) {
                iv[i] = b;
            } else {
                valid_crypto = false;
            }
        }
    } else {
        valid_crypto = false;
    }

    let mut ciphertext = heapless::Vec::<u8, 1024>::new();
    if ciphertext_hex.len() % 2 == 0 && ciphertext_hex.len() <= 2048 {
        for i in 0..(ciphertext_hex.len() / 2) {
            if let Ok(b) = u8::from_str_radix(&ciphertext_hex[i * 2..i * 2 + 2], 16) {
                let _ = ciphertext.push(b);
            } else {
                valid_crypto = false;
            }
        }
    } else {
        valid_crypto = false;
    }

    let mut response_msg = "Invalid Crypto Envelope";
    let mut dynamic_msg = heapless::String::<512>::new();
    // Timestamp of the incoming command, echoed and signed into the response so
    // the client can bind the response to its request.
    let mut resp_ts = heapless::String::<24>::new();
    let mut led: Option<[RGB8; 8]> = None;
    let mut status_line: Option<heapless::String<16>> = None;

    if valid_crypto {
        #[allow(deprecated)]
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        #[allow(deprecated)]
        use aes_gcm::aead::{AeadInPlace, KeyInit};
        use sha2::{Digest, Sha256};

        let ephemeral_pub = x25519_dalek::PublicKey::from(ephemeral_pub_bytes);
        let shared_secret = esp_x25519_secret.diffie_hellman(&ephemeral_pub);
        let tx_key_hash = Sha256::digest(shared_secret.as_bytes());

        #[allow(deprecated)]
        let key = Key::<Aes256Gcm>::from_slice(&tx_key_hash);
        let cipher = Aes256Gcm::new(key);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&iv);

        let len = ciphertext.len();
        if len >= 16 {
            let (msg, tag_bytes) = ciphertext.split_at_mut(len - 16);
            #[allow(deprecated)]
            let tag = aes_gcm::Tag::from_slice(tag_bytes);

            #[allow(deprecated)]
            if cipher.decrypt_in_place_detached(nonce, b"", msg, tag).is_ok() {
                if let Ok(plaintext) = core::str::from_utf8(msg) {
                    let mut inner_parts = plaintext.split(';');
                    let timestamp_str = inner_parts.next().unwrap_or("");
                    let _ = write!(&mut resp_ts, "{}", timestamp_str);
                    let cmd = inner_parts.next().unwrap_or("");
                    let sig_hex = inner_parts.next().unwrap_or("");

                    let incoming_ts = timestamp_str.parse::<u64>().unwrap_or(0);
                    let is_replay = unsafe { incoming_ts <= LAST_TIMESTAMP };

                    if !is_replay {
                        let mut sig_bytes = [0u8; 64];
                        let mut valid_sig_format = true;
                        if sig_hex.len() == 128 {
                            for i in 0..64 {
                                if let Ok(b) = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16) {
                                    sig_bytes[i] = b;
                                } else {
                                    valid_sig_format = false;
                                }
                            }
                        } else {
                            valid_sig_format = false;
                        }

                        if valid_sig_format {
                            let mut role_authorized = false;
                            let mut is_supervisor = false;
                            let mut authenticated_role = heapless::String::<32>::new();

                            let mut signed_payload = heapless::String::<512>::new();
                            let _ = write!(&mut signed_payload, "{}|{}", timestamp_str, cmd);

                            // 1. Try the compile-time supervisor key.
                            if clientauth::verify(&supervisor_key, signed_payload.as_bytes(), &sig_bytes)
                            {
                                role_authorized = true;
                                is_supervisor = true;
                                let _ = authenticated_role.push_str("Supervisor");
                            } else {
                                // 2. Try each provisioned dynamic role, re-verifying
                                //    its supervisor certificate to catch RAM tampering.
                                for entry in unsafe { &*core::ptr::addr_of!(ROLES) }.iter() {
                                    if clientauth::verify(
                                        &entry.pubkey,
                                        signed_payload.as_bytes(),
                                        &sig_bytes,
                                    ) {
                                        let mut cert_msg = heapless::String::<128>::new();
                                        let mut pk_hex = heapless::String::<66>::new();
                                        for b in &entry.pubkey {
                                            let _ = write!(&mut pk_hex, "{:02x}", b);
                                        }
                                        let _ = write!(
                                            &mut cert_msg,
                                            "ROLE:{};PUBKEY:{}",
                                            entry.name, pk_hex
                                        );

                                        let mut cert_sig = [0u8; 64];
                                        cert_sig.copy_from_slice(&entry.cert_sig);

                                        if clientauth::verify(
                                            &supervisor_key,
                                            cert_msg.as_bytes(),
                                            &cert_sig,
                                        ) {
                                            role_authorized = true;
                                            let _ =
                                                write!(&mut authenticated_role, "{}", entry.name);
                                            break;
                                        } else {
                                            info!("RAM Tampering Detected for role {}!", entry.name);
                                        }
                                    }
                                }
                            }

                            if role_authorized {
                                let role = &authenticated_role;
                                info!("Authenticated Command: {} (Role: {})", cmd, role);

                                let outcome =
                                    commands::dispatch(cmd, role, is_supervisor, &mut dynamic_msg);
                                let allowed = outcome.allowed;
                                let color_name = outcome.color_name;
                                response_msg = outcome.response_msg;

                                let mut status_str = heapless::String::<16>::new();
                                if allowed {
                                    unsafe {
                                        LAST_TIMESTAMP = incoming_ts;
                                    }
                                    if response_msg == "Invalid Crypto Envelope" {
                                        response_msg =
                                            "Command Executed. (Sensors visible on local display)";
                                    }
                                    let _ = write!(&mut status_str, "{:<6} Pass   ", color_name);

                                    let data = if cmd.starts_with(CMD_COLOR_RED)
                                        || cmd.starts_with(CMD_CLEAR_ALARM)
                                    {
                                        [colors::RED; 8]
                                    } else if cmd.starts_with(CMD_COLOR_YELLOW)
                                        || cmd.starts_with(CMD_SET_THRESHOLD)
                                    {
                                        [colors::YELLOW; 8]
                                    } else if cmd.starts_with(CMD_COLOR_GREEN)
                                        || cmd.starts_with(CMD_READ_SENSOR)
                                    {
                                        [colors::GREEN; 8]
                                    } else if cmd.starts_with(CMD_ADD_ROLE)
                                        || cmd.starts_with(CMD_REVOKE_ROLE)
                                        || cmd.starts_with(CMD_LIST_ROLES)
                                        || cmd.starts_with(CMD_WHOAMI)
                                    {
                                        [colors::BLUE; 8]
                                    } else {
                                        [colors::WHITE; 8]
                                    };
                                    unsafe {
                                        COMMAND_OVERRIDE_COLOR = data;
                                        COMMAND_OVERRIDE_UNTIL = embassy_time::Instant::now()
                                            .as_millis()
                                            + COMMAND_LED_TIMEOUT_MS;
                                    }
                                    led = Some(data);
                                } else {
                                    if response_msg == "Invalid Crypto Envelope" {
                                        response_msg = "Permission Denied";
                                    }
                                    let _ = write!(&mut status_str, "{:<6} Reject ", color_name);
                                }
                                status_line = Some(status_str);
                            } else {
                                response_msg = "Signature verification failed or Unknown Role";
                            }
                        } else {
                            response_msg = "Invalid Signature Format";
                        }
                    } else {
                        response_msg = "Replay Attack Detected";
                    }
                } else {
                    response_msg = "Invalid UTF-8 in payload";
                }
            } else {
                response_msg = "Decryption Failed";
            }
        } else {
            response_msg = "Payload too short";
        }
    }

    // Build, sign, and encrypt the response (see crypto.rs). Even rejections are
    // returned as a signed envelope so the client sees a consistent reply.
    let mut resp_message = heapless::String::<512>::new();
    if !dynamic_msg.is_empty() {
        let _ = write!(&mut resp_message, "{}", dynamic_msg);
    } else {
        let _ = write!(&mut resp_message, "{}", response_msg);
    }

    let response = crypto::build_signed_response(
        &resp_ts,
        &resp_message,
        esp_signing_key,
        &ephemeral_pub_bytes,
        rng,
    );

    ProcessResult {
        response,
        led,
        status_line,
    }
}
