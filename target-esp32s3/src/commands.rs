//! Authenticated command dispatch. Maps a verified (command, role) pair to an
//! action + response, mutating device state and persisting via `storage`.
//!
//! Purely logic: it does not touch the LCD or LED ring — the caller drives the
//! local display from the returned `Outcome`.

use crate::state::*;
use crate::storage;
use log::info;
use shared::terminology::*;

/// Result of dispatching one authenticated command.
pub struct Outcome {
    pub allowed: bool,
    pub color_name: &'static str,
    pub response_msg: &'static str,
}

/// `dynamic_msg` receives any command-specific response text.
pub fn dispatch(
    cmd: &str,
    role: &str,
    is_supervisor: bool,
    dynamic_msg: &mut heapless::String<1024>,
) -> Outcome {
    use core::fmt::Write as _;

    let mut allowed = false;
    let mut color_name = "Unknown";
    let mut response_msg = "Invalid Crypto Envelope";

    if cmd.starts_with(CMD_ADD_ROLE) && is_supervisor {
        let mut cmd_parts = cmd.split_whitespace();
        cmd_parts.next(); // skip ADD_ROLE
        if let (Some(new_role), Some(new_pk_hex), Some(new_cert_hex)) =
            (cmd_parts.next(), cmd_parts.next(), cmd_parts.next())
        {
            let mut new_pk = heapless::Vec::<u8, 33>::new();
            let mut new_cert = heapless::Vec::<u8, 64>::new();
            let mut valid_parse = true;

            if new_pk_hex.len() == crate::clientauth::CLIENT_PK_HEX_LEN && new_cert_hex.len() == 128 {
                for i in 0..(crate::clientauth::CLIENT_PK_HEX_LEN / 2) {
                    if let Ok(b) = u8::from_str_radix(&new_pk_hex[i * 2..i * 2 + 2], 16) {
                        let _ = new_pk.push(b);
                    } else {
                        valid_parse = false;
                    }
                }
                for i in 0..64 {
                    if let Ok(b) = u8::from_str_radix(&new_cert_hex[i * 2..i * 2 + 2], 16) {
                        let _ = new_cert.push(b);
                    } else {
                        valid_parse = false;
                    }
                }
            } else {
                valid_parse = false;
            }

            // Optional 4th arg: device label ("iPad-01") so the same role can be
            // granted to several devices and LIST/REVOKE can tell them apart. Charset
            // is restricted (no whitespace/';') so it survives the envelope framing.
            let device = cmd_parts.next().unwrap_or("");
            let device_ok = device.len() <= 16
                && device
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));

            if valid_parse && device_ok {
                let mut name_str = heapless::String::<16>::new();
                let _ = name_str.push_str(new_role);
                let mut device_str = heapless::String::<16>::new();
                let _ = device_str.push_str(device);
                let entry = RoleEntry {
                    name: name_str,
                    pubkey: new_pk,
                    cert_sig: new_cert,
                    device: device_str,
                };
                // Entry identity = pubkey OR device label (both stay unique): re-granting
                // a key replaces its entry, re-using a label replaces that device's entry.
                // Different devices with the same role coexist as separate entries.
                let roles = unsafe { &mut *core::ptr::addr_of_mut!(ROLES) };
                roles.retain(|e| {
                    e.pubkey != entry.pubkey
                        && (entry.device.is_empty() || e.device != entry.device)
                });
                let _ = roles.push(entry);

                storage::save_roles(unsafe { &*core::ptr::addr_of!(ROLES) });
                info!("Saved roles to flash");
                response_msg = "Role Added Securely";
                allowed = true;
                color_name = "System";
            } else {
                response_msg = "Invalid Role Data Format";
            }
        } else {
            response_msg = "Malformed ADD_ROLE command";
        }
    } else if cmd.starts_with(CMD_REVOKE_ROLE) {
        if role == ROLE_SUPERVISOR {
            // The revoke target lives inside the decrypted, signed command
            // (e.g. "REVOKE_ROLE Operator") -- parse it here, not from an outer
            // transport field.
            let mut cmd_parts = cmd.split_whitespace();
            cmd_parts.next(); // skip REVOKE_ROLE
            if let Some(target) = cmd_parts.next() {
                // The target is a device label first (revokes exactly that device's
                // entry), else a role name (revokes ALL entries holding that role —
                // deterministic when several devices share it).
                let roles = unsafe { &mut *core::ptr::addr_of_mut!(ROLES) };
                let before = roles.len();
                if roles.iter().any(|r| !r.device.is_empty() && r.device == target) {
                    roles.retain(|r| r.device != target);
                    let _ = write!(dynamic_msg, "Device {} revoked", target);
                } else {
                    roles.retain(|r| r.name != target);
                    if roles.len() < before {
                        let _ = write!(
                            dynamic_msg,
                            "Role {} revoked ({} entries)",
                            target,
                            before - roles.len()
                        );
                    } else {
                        let _ = write!(dynamic_msg, "Role {} not found", target);
                    }
                }
                if roles.len() < before {
                    storage::save_roles(unsafe { &*core::ptr::addr_of!(ROLES) });
                }
                allowed = true;
                color_name = "System";
            }
        }
    } else if cmd.starts_with(CMD_LIST_ROLES) {
        if role == ROLE_SUPERVISOR {
            let roles_ref = unsafe { &*core::ptr::addr_of!(ROLES) };
            if roles_ref.is_empty() {
                let _ = write!(dynamic_msg, "No roles found");
            } else {
                let _ = write!(dynamic_msg, "ROLES:");
                for r in roles_ref.iter() {
                    let mut pk_hex = heapless::String::<66>::new();
                    for b in &r.pubkey {
                        let _ = write!(&mut pk_hex, "{:02x}", b);
                    }
                    // `name@device:pk` when labeled; legacy entries keep `name:pk`.
                    if r.device.is_empty() {
                        let _ = write!(dynamic_msg, "{}:{},", r.name, pk_hex);
                    } else {
                        let _ = write!(dynamic_msg, "{}@{}:{},", r.name, r.device, pk_hex);
                    }
                }
            }
            allowed = true;
            color_name = "System";
        }
    } else if cmd.starts_with(CMD_READ_SENSOR) {
        // Supervisor is the role authority only (ADD/LIST/REVOKE) -- it does not
        // operate the device, so it is intentionally NOT in the operational lists.
        if role == ROLE_OBSERVER || role == ROLE_OPERATOR || role == ROLE_ADMIN {
            allowed = true;
            color_name = "Green";
            if unsafe { ALARM_ACTIVE } {
                let _ = write!(dynamic_msg, "Temp: {:.1}C, RH: {:.1}% (ALARM!)", unsafe { LAST_TEMP }, unsafe { LAST_RH });
            } else {
                let _ = write!(dynamic_msg, "Temp: {:.1}C, RH: {:.1}%", unsafe { LAST_TEMP }, unsafe { LAST_RH });
            }
        }
    } else if cmd.starts_with(CMD_SET_THRESHOLD) {
        if role == ROLE_OPERATOR || role == ROLE_ADMIN {
            let mut cmd_parts = cmd.split_whitespace();
            cmd_parts.next();
            if let Some(val_str) = cmd_parts.next() {
                if let Ok(val) = val_str.parse::<f32>() {
                    unsafe {
                        THRESHOLD = val;
                        ALARM_ACTIVE = false;
                    }
                    // Persist so the threshold survives reboot (like keys and roles).
                    storage::save_threshold(val);
                    let _ = write!(dynamic_msg, "Threshold set to {:.1}C", val);
                    allowed = true;
                    color_name = "Yellow";
                }
            }
        }
    } else if cmd.starts_with(CMD_CLEAR_ALARM) {
        if role == ROLE_ADMIN {
            unsafe {
                ALARM_ACTIVE = false;
            }
            let _ = write!(dynamic_msg, "Alarm Cleared");
            allowed = true;
            color_name = "Red";
        }
    } else if cmd.starts_with(CMD_WHOAMI) {
        allowed = true;
        color_name = "Blue";
        let _ = write!(dynamic_msg, "{}", role);
    } else if cmd.starts_with(CMD_COLOR_GREEN) {
        if role == ROLE_OBSERVER || role == ROLE_OPERATOR || role == ROLE_ADMIN {
            allowed = true;
        }
        color_name = "Green";
    } else if cmd.starts_with(CMD_COLOR_YELLOW) {
        if role == ROLE_OPERATOR || role == ROLE_ADMIN {
            allowed = true;
        }
        color_name = "Yellow";
    } else if cmd.starts_with(CMD_COLOR_RED) {
        if role == ROLE_ADMIN {
            allowed = true;
            unsafe {
                ALARM_ACTIVE = true;
            }
            let _ = write!(dynamic_msg, "Alarm Test Triggered");
        }
        color_name = "Red";
    }

    Outcome {
        allowed,
        color_name,
        response_msg,
    }
}
