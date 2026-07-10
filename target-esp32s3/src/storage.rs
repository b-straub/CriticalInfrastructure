//! Flash persistence for roles, the alarm threshold, and the OTA journal — all in the
//! plaintext `storage` partition.
//!
//! We call the ROM SPI-flash functions directly instead of `esp_storage::FlashStorage`,
//! because `FlashStorage::new()` probes the chip size by reading the bootloader header at
//! `0x0` — which is *encrypted* under flash encryption — so it reads ciphertext, mis-sizes
//! the chip, and every read/write then fails a bounds check. We only ever touch the fixed,
//! in-bounds `storage` partition, so no capacity probe is needed. Writes run from RAM
//! (`.rwtext`, like esp-storage's own writes) so they survive the flash-XIP stall.

use crate::state::RoleEntry;

const STORAGE_BASE: u32 = 0x200000; // must match secure-boot/partitions.csv (SSOT)
const ROLES_OFF: u32 = 0x0;
const OTA_STATE_OFF: u32 = 0x10000;
const THRESHOLD_OFF: u32 = 0x20000;
const SECTOR: usize = 4096;

/// Word-aligned sector buffer (the ROM flash functions take `*u32`).
#[repr(align(4))]
struct Page([u8; SECTOR]);

// Linked from the ESP32-S3 ROM via esp-rom-sys's rom.ld.
extern "C" {
    fn esp_rom_spiflash_read(src: u32, dst: *mut u32, len: u32) -> i32;
    fn esp_rom_spiflash_unlock() -> i32;
    fn esp_rom_spiflash_erase_sector(sector: u32) -> i32;
    fn esp_rom_spiflash_write(dst: u32, src: *const u32, len: u32) -> i32;
}

#[cfg_attr(not(target_os = "macos"), unsafe(link_section = ".rwtext"))]
unsafe fn read_inner(addr: u32, dst: *mut u32) -> bool {
    esp_rom_spiflash_read(addr, dst, SECTOR as u32) == 0
}

#[cfg_attr(not(target_os = "macos"), unsafe(link_section = ".rwtext"))]
unsafe fn write_inner(addr: u32, src: *const u32) -> bool {
    if esp_rom_spiflash_unlock() != 0 {
        return false;
    }
    if esp_rom_spiflash_erase_sector(addr / SECTOR as u32) != 0 {
        return false;
    }
    esp_rom_spiflash_write(addr, src, SECTOR as u32) == 0
}

fn read_page(off: u32, page: &mut Page) -> bool {
    critical_section::with(|_| unsafe { read_inner(STORAGE_BASE + off, page.0.as_mut_ptr() as *mut u32) })
}

fn write_page(off: u32, page: &Page) -> bool {
    critical_section::with(|_| unsafe { write_inner(STORAGE_BASE + off, page.0.as_ptr() as *const u32) })
}

/// Load the persisted, supervisor-signed roles (postcard-encoded).
pub fn load_roles() -> Option<heapless::Vec<RoleEntry, 10>> {
    let mut page = Page([0u8; SECTOR]);
    if !read_page(ROLES_OFF, &mut page) {
        return None;
    }
    postcard::from_bytes::<heapless::Vec<RoleEntry, 10>>(&page.0).ok()
}

/// Persist the current role set.
pub fn save_roles(roles: &heapless::Vec<RoleEntry, 10>) {
    if let Ok(bytes) = postcard::to_vec::<_, 4096>(roles) {
        let mut page = Page([0xFFu8; SECTOR]);
        page.0[..bytes.len()].copy_from_slice(&bytes);
        let _ = write_page(ROLES_OFF, &page);
    }
}

/// Load the persisted alarm threshold, if a sane value was stored.
pub fn load_threshold() -> Option<f32> {
    let mut page = Page([0u8; SECTOR]);
    if read_page(THRESHOLD_OFF, &mut page) {
        let v = f32::from_le_bytes([page.0[0], page.0[1], page.0[2], page.0[3]]);
        if v.is_finite() && v > -50.0 && v < 200.0 {
            return Some(v);
        }
    }
    None
}

/// Persist the alarm threshold so it survives reboot.
pub fn save_threshold(val: f32) {
    let mut page = Page([0xFFu8; SECTOR]);
    page.0[0..4].copy_from_slice(&val.to_le_bytes());
    let _ = write_page(THRESHOLD_OFF, &page);
}

/// Read the 32-byte OTA-state journal (format owned by `ota.rs`).
pub(crate) fn ota_state_read(buf: &mut [u8; 32]) -> bool {
    let mut page = Page([0u8; SECTOR]);
    if !read_page(OTA_STATE_OFF, &mut page) {
        return false;
    }
    buf.copy_from_slice(&page.0[..32]);
    true
}

/// Write the 32-byte OTA-state journal (the record sits in the first 32 bytes).
pub(crate) fn ota_state_write(buf: &[u8; 32]) {
    let mut page = Page([0xFFu8; SECTOR]);
    page.0[..32].copy_from_slice(buf);
    let _ = write_page(OTA_STATE_OFF, &page);
}
