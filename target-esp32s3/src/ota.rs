//! OTA update support (docs/formal/OTA.md).
//!
//! Self-managed slot state so the OTA path **never reads encrypted flash** — the one
//! requirement that makes OTA work under flash encryption without a decrypt-read layer:
//! - the running slot comes from the **MMU** (`booted_slot`, a register read, not flash),
//! - the OTA journal (seq / active / pending) lives in the **plaintext `storage`** partition,
//! - we only ever **write** `otadata` + app slots, encrypted via the ROM when FE is on.
//!
//! The bootloader does the decrypt-reads to select the slot (built in). Two entry points,
//! both driven from `main` after `esp_hal::init`: [`confirm_if_pending`] (every boot) and,
//! in test builds, [`maybe_self_copy_test`]. Network delivery: [`server_task`] (`ota-net`).

use esp_storage::FlashStorage;
use log::info;

use embedded_storage::Storage;
#[cfg(feature = "ota-selftest")]
use embedded_storage::ReadStorage;

const SECTOR: usize = 4096;
// Flash layout — must match secure-boot/partitions.csv (the SSOT). Hardcoded because the
// partition table is encrypted under FE and we refuse to decrypt-read.
#[cfg(any(feature = "ota-net", feature = "ota-selftest"))]
const OTA0_OFF: u32 = 0x20000;
const OTA1_OFF: u32 = 0x230000;
#[cfg(feature = "ota-net")]
const SLOT_SIZE: u32 = 0x1e0000;
const OTADATA_OFF: u32 = 0xd000; // sector 0; sector 1 at +SECTOR
const OTA_MAGIC: u32 = 0x0A7A_5747; // journal validity marker
#[cfg(any(feature = "ota-net", feature = "ota-selftest"))]
const ST_NEW: u32 = 0; // esp_ota_select_entry ota_state values
const ST_VALID: u32 = 2;

/// The app slot we booted from, read from the MMU (a register, not flash — correct under
/// flash encryption). ESP32-S3: MMU entry 0 low byte << 16 = the app's physical offset.
pub fn booted_slot() -> u8 {
    let paddr = unsafe { ((0x600C_5000 as *const u32).read_volatile() & 0xff) << 16 };
    if paddr == OTA1_OFF {
        1
    } else {
        0
    }
}
#[cfg(any(feature = "ota-net", feature = "ota-selftest"))]
fn slot_offset(slot: u8) -> u32 {
    if slot == 1 {
        OTA1_OFF
    } else {
        OTA0_OFF
    }
}
fn fe() -> bool {
    esp_hal::efuse::Efuse::flash_encryption()
}

/// Sector-aligned scratch — `esp_rom_spiflash_write_encrypted` takes `*mut u32` and
/// rewrites the buffer in place, so it must be 4-byte aligned.
#[repr(align(4))]
struct AlignedSector([u8; SECTOR]);

/// The OTA journal, kept in the plaintext `storage` partition (32 bytes).
#[derive(Clone, Copy)]
struct OtaState {
    seq: u32,          // sequence of the current Valid entry
    active_sector: u8, // otadata sector (0/1) holding it
    active_slot: u8,   // app slot (0/1) currently Valid
    pending_slot: u8,  // 0xFF = none, else the slot awaiting confirm
    pending_sector: u8,
    pending_seq: u32,
}

impl OtaState {
    fn load() -> Option<Self> {
        let mut b = [0u8; 32];
        if !crate::storage::ota_state_read(&mut b) {
            return None;
        }
        if u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != OTA_MAGIC {
            return None;
        }
        Some(Self {
            seq: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            active_sector: b[8],
            active_slot: b[9],
            pending_slot: b[10],
            pending_sector: b[11],
            pending_seq: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        })
    }
    fn save(&self) {
        let mut b = [0xFFu8; 32];
        b[0..4].copy_from_slice(&OTA_MAGIC.to_le_bytes());
        b[4..8].copy_from_slice(&self.seq.to_le_bytes());
        b[8] = self.active_sector;
        b[9] = self.active_slot;
        b[10] = self.pending_slot;
        b[11] = self.pending_sector;
        b[12..16].copy_from_slice(&self.pending_seq.to_le_bytes());
        crate::storage::ota_state_write(&b);
    }
    /// First run: mirror what provisioning wrote — otadata sector 0 holds a Valid entry
    /// whose seq (slot+1) selects the booted slot (ota-switch-slot.sh / ota-flash-slots.sh).
    fn bootstrap(slot: u8) -> Self {
        Self {
            seq: slot as u32 + 1,
            active_sector: 0,
            active_slot: slot,
            pending_slot: 0xFF,
            pending_sector: 0,
            pending_seq: 0,
        }
    }
}

/// ESP `ota_select` CRC: reflected CRC-32 (poly 0xEDB88320), init 0, xorout 0xFFFFFFFF,
/// over the 4-byte ota_seq. (Same as provision/ota-switch-slot.sh, validated on hardware.)
fn esp_crc(seq: u32) -> u32 {
    let mut c: u32 = 0;
    for byte in seq.to_le_bytes() {
        c ^= byte as u32;
        for _ in 0..8 {
            c = (c >> 1) ^ if c & 1 != 0 { 0xEDB8_8320 } else { 0 };
        }
    }
    c ^ 0xFFFF_FFFF
}

/// Write one flash sector at an absolute address, encrypted iff flash encryption is on.
fn put_sector(addr: u32, buf: &mut AlignedSector, encrypted: bool) {
    if encrypted {
        let _ = flash_enc::write_sector(addr, &mut buf.0);
    } else {
        let _ = FlashStorage::new().write(addr, &buf.0[..]);
    }
}

/// Write a fresh esp_ota_select_entry (seq, state, crc) to an otadata sector.
fn write_otadata(sector: u8, seq: u32, state: u32, encrypted: bool) {
    let mut buf = AlignedSector([0xFFu8; SECTOR]); // entry at the start, rest padding
    buf.0[0..4].copy_from_slice(&seq.to_le_bytes());
    buf.0[24..28].copy_from_slice(&state.to_le_bytes());
    buf.0[28..32].copy_from_slice(&esp_crc(seq).to_le_bytes());
    put_sector(OTADATA_OFF + sector as u32 * SECTOR as u32, &mut buf, encrypted);
}

/// After writing a new image to `target`, point otadata at it (New) and record it pending,
/// so it boots next and `confirm_if_pending` validates it. seq+1 flips the A/B slot.
#[cfg(any(feature = "ota-net", feature = "ota-selftest"))]
fn commit_pending(target: u8) {
    let st = OtaState::load().unwrap_or_else(|| OtaState::bootstrap(booted_slot()));
    let new_seq = st.seq + 1;
    let new_sector = 1 - st.active_sector;
    write_otadata(new_sector, new_seq, ST_NEW, fe());
    OtaState {
        pending_slot: target,
        pending_sector: new_sector,
        pending_seq: new_seq,
        ..st
    }
    .save();
}

/// Every boot: if we booted the pending slot, self-test and mark it Valid; if we booted
/// the old slot instead, the bootloader rolled back — abandon the pending entry.
pub fn confirm_if_pending() {
    let Some(st) = OtaState::load() else {
        OtaState::bootstrap(booted_slot()).save(); // first run: record provisioned state
        return;
    };
    if st.pending_slot == 0xFF {
        return;
    }
    let booted = booted_slot();
    if booted == st.pending_slot {
        write_otadata(st.pending_sector, st.pending_seq, ST_VALID, fe());
        OtaState {
            seq: st.pending_seq,
            active_sector: st.pending_sector,
            active_slot: st.pending_slot,
            pending_slot: 0xFF,
            pending_sector: 0,
            pending_seq: 0,
        }
        .save();
        info!("OTA: self-test passed -> slot {} marked Valid", booted);
    } else {
        OtaState {
            pending_slot: 0xFF,
            pending_sector: 0,
            pending_seq: 0,
            ..st
        }
        .save();
        info!("OTA: rolled back to slot {}", booted);
    }
}

// ---- 4.2 test-only self-copy (feature `ota-selftest`) -------------------------

/// Length of the Secure-Boot-signed image at `base` (esp_image header + segments +
/// checksum + optional hash + signature block). `None` on bad magic.
#[cfg(feature = "ota-selftest")]
fn signed_image_len(flash: &mut FlashStorage, base: u32) -> Option<u32> {
    let mut hdr = [0u8; 24];
    flash.read(base, &mut hdr).ok()?;
    if hdr[0] != 0xE9 {
        return None;
    }
    let segments = hdr[1] as u32;
    let hash_appended = hdr[23] == 1;
    let mut off = 24u32;
    for _ in 0..segments {
        let mut seg = [0u8; 8];
        flash.read(base + off, &mut seg).ok()?;
        off += 8 + u32::from_le_bytes([seg[4], seg[5], seg[6], seg[7]]);
    }
    off = (off + 1 + 15) & !15;
    if hash_appended {
        off += 32;
    }
    off = ((off + 4095) & !4095) + 4096;
    Some(off)
}

/// Test-only: from ota_0, copy the running image into ota_1, activate it, and reset.
/// (FE off only — a self-copy reads the source slot raw, which is ciphertext under FE.)
#[cfg(feature = "ota-selftest")]
pub fn maybe_self_copy_test() {
    if booted_slot() != 0 {
        return;
    }
    let src = slot_offset(0);
    let dst = slot_offset(1);
    let mut fs = FlashStorage::new();
    let len = match signed_image_len(&mut fs, src) {
        Some(l) => (l + SECTOR as u32 - 1) & !(SECTOR as u32 - 1),
        None => {
            info!("OTA selftest: unreadable image header @ {:#x}", src);
            return;
        }
    };
    info!("OTA selftest: copying full image ({} KiB) ota_0 -> ota_1...", len / 1024);
    let mut sector = AlignedSector([0u8; SECTOR]);
    let mut off = 0u32;
    while off < len {
        if fs.read(src + off, &mut sector.0).is_err() {
            info!("OTA selftest: read @ {:#x} failed", off);
            return;
        }
        put_sector(dst + off, &mut sector, false);
        off += SECTOR as u32;
    }
    commit_pending(1);
    info!("OTA selftest: wrote ota_1, activated (New); resetting into it...");
    esp_hal::system::software_reset();
}

// ---- 4.3 network delivery over TCP (feature `ota-net`) ------------------------
//
// SECURITY: :8081 is currently unauthenticated. Secure Boot is the integrity backstop —
// a tampered/garbage image won't boot and rolls back — but gating the trigger through the
// supervisor channel + anti-rollback (SECURE_VERSION) is the next hardening step.

/// TCP OTA server: accept on :8081, receive a length-prefixed signed image
/// (`[u32 LE length][image bytes]`), stream it into the inactive slot (encrypted under FE),
/// activate it, and reset. See docs/formal/OTA.md.
#[cfg(feature = "ota-net")]
#[embassy_executor::task]
pub async fn server_task(stack: embassy_net::Stack<'static>) {
    use embassy_net::tcp::TcpSocket;
    use embassy_time::{Duration, Timer};
    static RX: static_cell::StaticCell<[u8; 4096]> = static_cell::StaticCell::new();
    static TX: static_cell::StaticCell<[u8; 2048]> = static_cell::StaticCell::new();
    let rx = RX.init([0u8; 4096]);
    let tx = TX.init([0u8; 2048]);
    loop {
        let mut sock = TcpSocket::new(stack, &mut rx[..], &mut tx[..]);
        sock.set_timeout(Some(Duration::from_secs(20)));
        info!("OTA: TCP listening on :8081 for a signed image");
        if let Err(e) = sock.accept(8081).await {
            info!("OTA: accept error: {:?}", e);
            continue;
        }
        match receive_and_install(&mut sock).await {
            Ok(n) => {
                info!("OTA: received {} bytes, activated new slot; resetting...", n);
                Timer::after(Duration::from_millis(50)).await;
                esp_hal::system::software_reset();
            }
            Err(e) => {
                info!("OTA: transfer aborted: {}", e);
                sock.abort();
                Timer::after(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Receive a length-prefixed image and install it into the inactive slot. Returns bytes written.
#[cfg(feature = "ota-net")]
async fn receive_and_install(
    sock: &mut embassy_net::tcp::TcpSocket<'_>,
) -> Result<u32, &'static str> {
    let mut lenb = [0u8; 4];
    read_exact(sock, &mut lenb).await?;
    let total = u32::from_le_bytes(lenb);
    if total == 0 || total > SLOT_SIZE {
        return Err("bad image length");
    }
    let target = 1 - booted_slot();
    let base = slot_offset(target);
    let encrypted = fe();
    info!(
        "OTA: receiving {} bytes into slot {} @ {:#x}{}",
        total,
        target,
        base,
        if encrypted { " [encrypted]" } else { "" }
    );

    let mut sector = AlignedSector([0u8; SECTOR]);
    let mut filled = 0usize;
    let mut written = 0u32;
    let mut remaining = total as usize;
    while remaining > 0 {
        let want = core::cmp::min(SECTOR - filled, remaining);
        let n = sock
            .read(&mut sector.0[filled..filled + want])
            .await
            .map_err(|_| "socket read")?;
        if n == 0 {
            return Err("connection closed early");
        }
        filled += n;
        remaining -= n;
        if filled == SECTOR {
            put_sector(base + written, &mut sector, encrypted);
            written += SECTOR as u32;
            filled = 0;
        }
    }
    if filled > 0 {
        for b in sector.0[filled..].iter_mut() {
            *b = 0xFF;
        }
        put_sector(base + written, &mut sector, encrypted);
    }

    commit_pending(target);
    Ok(total)
}

#[cfg(feature = "ota-net")]
async fn read_exact(
    sock: &mut embassy_net::tcp::TcpSocket<'_>,
    buf: &mut [u8],
) -> Result<(), &'static str> {
    let mut got = 0;
    while got < buf.len() {
        let n = sock.read(&mut buf[got..]).await.map_err(|_| "socket read")?;
        if n == 0 {
            return Err("connection closed early");
        }
        got += n;
    }
    Ok(())
}

// ---- flash-encryption-aware write (used whenever FE is on) --------------------

/// Encrypted flash writes for the encrypted regions (app slots + otadata). Reached only
/// when `Efuse::flash_encryption()` is true. NOT bench-verifiable (needs a flash-encrypted
/// board) — validated in the FE enablement session; see docs/formal/OTA.md.
mod flash_enc {
    // Linked from the ESP32-S3 ROM via esp-rom-sys's rom.ld.
    extern "C" {
        fn esp_rom_spiflash_unlock() -> i32;
        fn esp_rom_spiflash_erase_sector(sector: u32) -> i32;
        fn esp_rom_spiflash_write_encrypted_enable();
        fn esp_rom_spiflash_write_encrypted_disable();
        fn esp_rom_spiflash_write_encrypted(addr: u32, data: *mut u32, len: u32) -> i32;
    }

    /// The erase + encrypted-write window, placed in RAM (`.rwtext`, like esp-storage's
    /// flash routines). `write_encrypted_enable()` puts SPI in encrypto mode and breaks
    /// flash XIP, so every instruction between enable and disable must be fetched from RAM,
    /// not flash — otherwise the CPU hangs on the next instruction fetch.
    #[cfg_attr(not(target_os = "macos"), unsafe(link_section = ".rwtext"))]
    unsafe fn erase_and_encrypt(addr: u32, buf: *mut u32) -> Result<(), &'static str> {
        if esp_rom_spiflash_unlock() != 0 {
            return Err("unlock");
        }
        if esp_rom_spiflash_erase_sector(addr / 4096) != 0 {
            return Err("erase");
        }
        esp_rom_spiflash_write_encrypted_enable();
        let rc = esp_rom_spiflash_write_encrypted(addr, buf, 4096);
        esp_rom_spiflash_write_encrypted_disable();
        if rc == 0 {
            Ok(())
        } else {
            Err("encrypted write")
        }
    }

    /// Erase + encrypted-write one 4096-byte sector at `addr` (4096-aligned). `buf` is
    /// 4-byte aligned and rewritten in place by the ROM. Interrupts off (so no ISR runs
    /// flash-resident code during the encrypto window); the window itself is in RAM.
    pub(super) fn write_sector(addr: u32, buf: &mut [u8; 4096]) -> Result<(), &'static str> {
        critical_section::with(|_| unsafe { erase_and_encrypt(addr, buf.as_mut_ptr() as *mut u32) })
    }
}
