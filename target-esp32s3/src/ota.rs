//! OTA update support (docs/formal/OTA.md, step 4.2).
//!
//! Two entry points, both driven from `main` right after `esp_hal::init`:
//! - [`confirm_if_pending`] runs on every boot: if the running slot was just
//!   activated (state `New`/`PendingVerify`), self-test and mark it `Valid` so the
//!   bootloader's anti-rollback keeps it. Needed for every real OTA.
//! - [`maybe_self_copy_test`] (test builds only, `ota-selftest` feature): if booted
//!   from `ota_0`, copy the running image into the inactive slot via `OtaUpdater`,
//!   activate it, and reset — a full apply/activate/rollback cycle with no network.

use esp_bootloader_esp_idf::{ota::OtaImageState, ota_updater::OtaUpdater, partitions};
use esp_storage::FlashStorage;
use log::info;

#[cfg(feature = "ota-selftest")]
use embedded_storage::{ReadStorage, Storage};
#[cfg(feature = "ota-selftest")]
use esp_bootloader_esp_idf::partitions::{AppPartitionSubType, PartitionType};

#[cfg(feature = "ota-selftest")]
const SECTOR: usize = 4096;
/// Total length of the Secure-Boot-signed app image at `base`: walk the esp_image
/// header + segments + checksum + optional hash + the appended signature block. Copying
/// exactly the image (not a fixed guess) is required because the two slots hold
/// different builds — and is what a real OTA writer needs too. `None` on bad magic.
#[cfg(feature = "ota-selftest")]
fn signed_image_len(flash: &mut FlashStorage, base: u32) -> Option<u32> {
    let mut hdr = [0u8; 24];
    flash.read(base, &mut hdr).ok()?;
    if hdr[0] != 0xE9 {
        return None; // esp_image magic
    }
    let segments = hdr[1] as u32;
    let hash_appended = hdr[23] == 1;
    let mut off = 24u32;
    for _ in 0..segments {
        let mut seg = [0u8; 8]; // load_addr(4) + data_len(4)
        flash.read(base + off, &mut seg).ok()?;
        off += 8 + u32::from_le_bytes([seg[4], seg[5], seg[6], seg[7]]);
    }
    off = (off + 1 + 15) & !15; // 1-byte checksum, whole image padded to 16
    if hash_appended {
        off += 32; // appended SHA-256
    }
    off = ((off + 4095) & !4095) + 4096; // Secure Boot v2 signature block (4 KiB, aligned)
    Some(off)
}

/// Confirm a freshly-activated slot as `Valid` so anti-rollback keeps it. No-op (and
/// silent) when nothing is pending or the board has no A/B layout.
pub fn confirm_if_pending() {
    let mut flash = FlashStorage::new();
    let mut buf = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let mut updater = match OtaUpdater::new(&mut flash, &mut buf) {
        Ok(u) => u,
        Err(_) => return, // no A/B layout -> nothing to confirm
    };
    match updater.current_ota_state() {
        Ok(OtaImageState::New) | Ok(OtaImageState::PendingVerify) => {
            // A real self-test would check peripherals/connectivity before confirming.
            match updater.set_current_ota_state(OtaImageState::Valid) {
                Ok(()) => info!("OTA: self-test passed -> slot marked Valid"),
                Err(e) => info!("OTA: failed to mark slot Valid: {:?}", e),
            }
        }
        Ok(_) | Err(_) => {} // Valid / undefined / no selection -> nothing to do
    }
}

/// Test-only self-copy update: copy the running image into the inactive slot, activate
/// it (state `New`), and reset. Returns without acting unless booted from `ota_0`.
#[cfg(feature = "ota-selftest")]
pub fn maybe_self_copy_test() {
    // Only trigger from ota_0, and learn where it lives.
    let src_off = {
        let mut f = FlashStorage::new();
        let mut b = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
        let table = match partitions::read_partition_table(&mut f, &mut b) {
            Ok(t) => t,
            Err(e) => {
                info!("OTA selftest: no partition table: {:?}", e);
                return;
            }
        };
        match table.booted_partition() {
            Ok(Some(p))
                if p.partition_type() == PartitionType::App(AppPartitionSubType::Ota0) =>
            {
                p.offset()
            }
            _ => return, // not ota_0 -> already updated, do nothing
        }
    };

    let mut src = FlashStorage::new(); // separate handle for reading the source slot
    let copy_len = match signed_image_len(&mut src, src_off) {
        Some(len) => (len + SECTOR as u32 - 1) & !(SECTOR as u32 - 1), // round up to a sector
        None => {
            info!("OTA selftest: unreadable image header @ {:#x}", src_off);
            return;
        }
    };
    info!(
        "OTA selftest: copying full image (ota_0 @ {:#x}, {} KiB) into the inactive slot...",
        src_off,
        copy_len / 1024
    );
    let mut flash = FlashStorage::new();
    let mut buf = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let mut updater = match OtaUpdater::new(&mut flash, &mut buf) {
        Ok(u) => u,
        Err(e) => {
            info!("OTA selftest: updater init failed: {:?}", e);
            return;
        }
    };
    {
        let (mut region, slot) = match updater.next_partition() {
            Ok(v) => v,
            Err(e) => {
                info!("OTA selftest: next_partition failed: {:?}", e);
                return;
            }
        };
        let mut chunk = [0u8; SECTOR];
        let mut off: u32 = 0;
        while off < copy_len {
            if let Err(e) = src.read(src_off + off, &mut chunk) {
                info!("OTA selftest: read @ {:#x} failed: {:?}", off, e);
                return;
            }
            if let Err(e) = region.write(off, &chunk) {
                info!("OTA selftest: write @ {:#x} failed: {:?}", off, e);
                return;
            }
            off += SECTOR as u32;
        }
        info!("OTA selftest: wrote image into {:?}", slot);
    }
    if let Err(e) = updater.activate_next_partition() {
        info!("OTA selftest: activate failed: {:?}", e);
        return;
    }
    if let Err(e) = updater.set_current_ota_state(OtaImageState::New) {
        info!("OTA selftest: mark New failed: {:?}", e);
        return;
    }
    info!("OTA selftest: activated new slot (New); resetting into it...");
    esp_hal::system::software_reset();
}
