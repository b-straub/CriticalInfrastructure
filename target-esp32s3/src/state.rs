//! Shared device state.
//!
//! These live as `static mut` because they are touched from the single-threaded
//! embassy main loop (command handling and the idle sensor/LED path). Access is
//! always via `unsafe` at the use sites, as before.

use serde::{Deserialize, Serialize};
use smart_leds::{colors, RGB8};

/// A supervisor-issued dynamic role, persisted to flash.
#[derive(Clone, Serialize, Deserialize)]
pub struct RoleEntry {
    pub name: heapless::String<16>,
    /// Client public key: 33 bytes (P-256 compressed). A `Vec` for wire flexibility.
    pub pubkey: heapless::Vec<u8, 33>,
    pub cert_sig: heapless::Vec<u8, 64>,
    /// Device label (e.g. "Bernis-iPad") — differentiates same-role entries from
    /// different devices in LIST_ROLES and is the primary REVOKE_ROLE target.
    /// Metadata only: NOT part of the supervisor certificate (the supervisor-signed
    /// ADD_ROLE command authenticates it). Empty on legacy/unlabeled entries.
    pub device: heapless::String<16>,
}

/// Monotonic replay guard: highest command timestamp accepted so far.
pub static mut LAST_TIMESTAMP: u64 = 0;

/// Dynamic roles (supervisor-signed), persisted at flash 0x200000.
pub static mut ROLES: heapless::Vec<RoleEntry, 10> = heapless::Vec::new();

pub static mut LAST_TEMP: f32 = 0.0;
pub static mut LAST_RH: f32 = 0.0;

/// Alarm threshold (deg C), persisted at flash 0x220000.
pub static mut THRESHOLD: f32 = 25.0;
pub static mut ALARM_ACTIVE: bool = false;

/// Transient command-driven LED override.
pub static mut COMMAND_OVERRIDE_UNTIL: u64 = 0; // ms
pub static mut COMMAND_OVERRIDE_COLOR: [RGB8; 8] = [colors::BLACK; 8];
