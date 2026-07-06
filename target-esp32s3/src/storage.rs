//! Flash persistence for roles (0x200000) and the alarm threshold (0x220000).

use crate::state::RoleEntry;
use embedded_storage::{ReadStorage, Storage};
use esp_storage::FlashStorage;

const ROLES_ADDR: u32 = 0x200000;
const THRESHOLD_ADDR: u32 = 0x220000;

/// Load the persisted, supervisor-signed roles (postcard-encoded).
pub fn load_roles() -> Option<heapless::Vec<RoleEntry, 10>> {
    let mut flash = FlashStorage::new();
    let mut buf = [0u8; 4096];
    if flash.read(ROLES_ADDR, &mut buf).is_ok() {
        postcard::from_bytes::<heapless::Vec<RoleEntry, 10>>(&buf).ok()
    } else {
        None
    }
}

/// Persist the current role set.
pub fn save_roles(roles: &heapless::Vec<RoleEntry, 10>) {
    if let Ok(bytes) = postcard::to_vec::<_, 4096>(roles) {
        let mut flash = FlashStorage::new();
        let mut write_buf = [0u8; 4096];
        write_buf[..bytes.len()].copy_from_slice(&bytes);
        let _ = flash.write(ROLES_ADDR, &write_buf);
    }
}

/// Load the persisted alarm threshold, if a sane value was stored.
pub fn load_threshold() -> Option<f32> {
    let mut flash = FlashStorage::new();
    let mut buf = [0u8; 4096];
    if flash.read(THRESHOLD_ADDR, &mut buf).is_ok() {
        let stored = f32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if stored.is_finite() && stored > -50.0 && stored < 200.0 {
            return Some(stored);
        }
    }
    None
}

/// Persist the alarm threshold so it survives reboot.
pub fn save_threshold(val: f32) {
    let mut buf = [0u8; 4096];
    buf[0..4].copy_from_slice(&val.to_le_bytes());
    let mut flash = FlashStorage::new();
    let _ = flash.write(THRESHOLD_ADDR, &buf);
}
