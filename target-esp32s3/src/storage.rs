//! Flash persistence for roles and the alarm threshold.
//!
//! Both live in the `storage` data partition, located at runtime from the partition
//! table (see docs/formal/OTA.md 4.4) rather than a hardcoded flash address — so the
//! layout can change (e.g. an A/B OTA table) without editing this file. Offsets are
//! relative to the partition, and unchanged from the old absolute layout, so data
//! already on flash is read back correctly. If the table has no `storage` partition we
//! log and disable persistence — we never guess an address.

use crate::state::RoleEntry;
use embedded_storage::{ReadStorage, Storage};
use esp_bootloader_esp_idf::partitions;
use esp_storage::FlashStorage;
use log::error;

// Offsets within the `storage` partition (0x30000 = 192 KiB).
const ROLES_OFF: u32 = 0x0;
const THRESHOLD_OFF: u32 = 0x20000;

/// Absolute flash offset of the `storage` partition, from the partition table.
/// `None` (with an error logged) if it is absent — callers then skip persistence.
fn storage_base() -> Option<u32> {
    let mut flash = FlashStorage::new();
    let mut buf = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let table = partitions::read_partition_table(&mut flash, &mut buf).ok()?;
    for p in table.iter() {
        if p.label_as_str().trim_end_matches('\0') == "storage" {
            return Some(p.offset());
        }
    }
    error!("storage: no `storage` partition in the table — persistence disabled");
    None
}

/// Load the persisted, supervisor-signed roles (postcard-encoded).
pub fn load_roles() -> Option<heapless::Vec<RoleEntry, 10>> {
    let base = storage_base()?;
    let mut flash = FlashStorage::new();
    let mut buf = [0u8; 4096];
    if flash.read(base + ROLES_OFF, &mut buf).is_ok() {
        postcard::from_bytes::<heapless::Vec<RoleEntry, 10>>(&buf).ok()
    } else {
        None
    }
}

/// Persist the current role set.
pub fn save_roles(roles: &heapless::Vec<RoleEntry, 10>) {
    let Some(base) = storage_base() else { return };
    if let Ok(bytes) = postcard::to_vec::<_, 4096>(roles) {
        let mut flash = FlashStorage::new();
        let mut write_buf = [0u8; 4096];
        write_buf[..bytes.len()].copy_from_slice(&bytes);
        let _ = flash.write(base + ROLES_OFF, &write_buf);
    }
}

/// Load the persisted alarm threshold, if a sane value was stored.
pub fn load_threshold() -> Option<f32> {
    let base = storage_base()?;
    let mut flash = FlashStorage::new();
    let mut buf = [0u8; 4096];
    if flash.read(base + THRESHOLD_OFF, &mut buf).is_ok() {
        let stored = f32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if stored.is_finite() && stored > -50.0 && stored < 200.0 {
            return Some(stored);
        }
    }
    None
}

/// Persist the alarm threshold so it survives reboot.
pub fn save_threshold(val: f32) {
    let Some(base) = storage_base() else { return };
    let mut buf = [0u8; 4096];
    buf[0..4].copy_from_slice(&val.to_le_bytes());
    let mut flash = FlashStorage::new();
    let _ = flash.write(base + THRESHOLD_OFF, &buf);
}
