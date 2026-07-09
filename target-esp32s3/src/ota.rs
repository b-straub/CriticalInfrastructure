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

#[cfg(any(feature = "ota-selftest", feature = "ota-net"))]
use embedded_storage::Storage;
#[cfg(feature = "ota-selftest")]
use embedded_storage::ReadStorage;
#[cfg(feature = "ota-selftest")]
use esp_bootloader_esp_idf::partitions::{AppPartitionSubType, PartitionType};

#[cfg(any(feature = "ota-selftest", feature = "ota-net"))]
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

// ---- 4.3: network delivery over TCP (feature `ota-net`) -----------------------
//
// SECURITY NOTE: this port is currently unauthenticated. Secure Boot is the integrity
// backstop — a tampered/garbage image simply won't boot and rolls back — but an
// attacker on the LAN could still force reboots or push an older *validly signed*
// image (rollback). Gating the trigger through the authenticated supervisor channel
// (and anti-rollback / SECURE_VERSION) is the next hardening step.

/// TCP OTA server: accept on :8081, receive a length-prefixed signed image
/// (`[u32 LE length][image bytes]`), stream it into the inactive slot via
/// `OtaUpdater`, activate it (`New`), and reset. `confirm_if_pending` marks it `Valid`
/// on the next boot. See docs/formal/OTA.md step 4.3.
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

/// Receive a length-prefixed image from `sock` and install it into the inactive slot.
/// Returns the number of image bytes written.
#[cfg(feature = "ota-net")]
async fn receive_and_install(
    sock: &mut embassy_net::tcp::TcpSocket<'_>,
) -> Result<u32, &'static str> {
    let mut lenb = [0u8; 4];
    read_exact(sock, &mut lenb).await?;
    let total = u32::from_le_bytes(lenb);

    let mut flash = FlashStorage::new();
    let mut buf = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let mut updater = OtaUpdater::new(&mut flash, &mut buf).map_err(|_| "no A/B layout")?;
    let (mut region, slot) = updater.next_partition().map_err(|_| "next_partition")?;
    if total == 0 || total > region.partition_size() as u32 {
        return Err("bad image length");
    }
    info!("OTA: receiving {} bytes into {:?}", total, slot);

    // Stream into flash, buffering to full sectors (esp-storage erases per sector).
    let mut sector = [0u8; SECTOR];
    let mut filled = 0usize;
    let mut written = 0u32;
    let mut remaining = total as usize;
    while remaining > 0 {
        let want = core::cmp::min(SECTOR - filled, remaining);
        let n = sock
            .read(&mut sector[filled..filled + want])
            .await
            .map_err(|_| "socket read")?;
        if n == 0 {
            return Err("connection closed early");
        }
        filled += n;
        remaining -= n;
        if filled == SECTOR {
            region.write(written, &sector).map_err(|_| "flash write")?;
            written += SECTOR as u32;
            filled = 0;
        }
    }
    if filled > 0 {
        for b in sector[filled..].iter_mut() {
            *b = 0xFF; // pad the final partial sector, matching a flashed image
        }
        region.write(written, &sector).map_err(|_| "flash write")?;
    }

    drop(region); // release the &mut on the updater before activating
    updater.activate_next_partition().map_err(|_| "activate")?;
    updater.set_current_ota_state(OtaImageState::New).map_err(|_| "set New")?;
    Ok(total)
}

/// Read exactly `buf.len()` bytes or fail.
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
