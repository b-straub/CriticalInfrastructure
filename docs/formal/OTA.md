# OTA Updates — Runbook (ESP32-S3, esp-hal + Secure Boot v2)

Over-the-air update is the realistic field-update path, and it is the **prerequisite
for Release-mode flash encryption** (Release disables plaintext serial flashing, so
updates must arrive via OTA — see [`SECURE-BOOT-V2.md`](./SECURE-BOOT-V2.md) Phase C).

## How it composes with Secure Boot (what's free)

The IDF second-stage bootloader we already build (`secure-boot/`) does the hard,
dangerous half itself:

- **slot selection** — reads `otadata` and picks the active app slot (`ota_0`/`ota_1`);
- **per-slot signature check** — with Secure Boot enabled, it verifies the *selected*
  slot's RSA-3072 signature before jumping to it, so an unsigned/tampered OTA image
  simply won't boot;
- **anti-brick rollback** (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`) — if a freshly
  activated slot doesn't confirm itself `Valid` on first boot, it reverts.

Because Secure Boot is the integrity backstop, **the OTA transport doesn't have to be
trusted for code integrity** — only *authorized* (so randoms can't force reboots/DoS,
which the existing supervisor auth already covers). Our stage-3/5 HSM signing already
produces exactly the signed image OTA needs.

The app-side mechanics (otadata `ota_seq`/CRC, the `New→PendingVerify→Valid` rollback
protocol, partition-table reads) are provided by **`esp-bootloader-esp-idf`** — a
first-party crate already in the firmware's dependency tree (`Ota`, `OtaUpdater`,
`partitions`). We do **not** hand-roll the format.

## Partition layout (`secure-boot/partitions.csv`)

Assumes **≥ 8 MB flash**. Table at `0xc000`; fully contiguous.

| Name     | Type | SubType | Offset    | Size      | Purpose |
|----------|------|---------|-----------|-----------|---------|
| otadata  | data | ota     | `0xd000`  | `0x2000`  | which slot is active + rollback state |
| phy_init | data | phy     | `0xf000`  | `0x1000`  | RF cal (conventional; unused by esp-wifi) |
| nvs      | data | nvs     | `0x10000` | `0x10000` | reserved for future NVS |
| **ota_0**| app  | ota_0   | `0x20000` | `0x1e0000`| app slot A (keeps the single-slot offset) |
| storage  | data | 0x40    | `0x200000`| `0x30000` | covers legacy `storage.rs` writes (roles `0x200000`, threshold `0x220000`) |
| **ota_1**| app  | ota_1   | `0x230000`| `0x1e0000`| app slot B |

The app reads this table at runtime; bootloader and app **must agree on the table
offset** (`0xc000`) — set in `secure-boot/sdkconfig.defaults`
(`CONFIG_PARTITION_TABLE_OFFSET`) and in `target-esp32s3/.cargo/config.toml`
(`ESP_BOOTLOADER_ESP_IDF_CONFIG_PARTITION_TABLE_OFFSET = 49152`).

## Phased plan

1. **A/B boot proof** *(this doc's runbook — spare board)* — prove the secure-boot
   bootloader boots an esp-hal image from an A/B table and honors `otadata` slot
   selection. **No network code.**
2. **Apply path in-app** — wire `OtaUpdater`: `next_partition()` → write image →
   `activate_next_partition()` → set `New` → reboot → self-test → `set_current_ota_state(Valid)`.
3. **Transport** — stream the ~0.9 MB signed image over TCP (`embassy-net`, `tcp`
   already enabled); authorize + trigger + expected SHA-256 on the existing channel.
4. **Move persistent state** — switch `storage.rs` (and the non-eFuse `identity.rs`
   seed) from absolute offsets to partition-table lookup, freeing the `storage` region.
5. **Flash encryption** — dev mode on a spare, validate encrypted OTA writes, then
   Release. Closes [`SECURE-BOOT-V2.md`](./SECURE-BOOT-V2.md) Phase C.

---

## Phase 1 runbook — A/B boot proof (spare board)

> Do this on a **spare** board: the partition layout change repartitions flash. The
> working demo unit is untouched.

**What Phase 1 proves:** the IDF secure-boot bootloader boots our esp-hal app from an
A/B table, and switching `otadata` switches which slot runs. **What it does *not* yet
prove** (later phases): per-slot signature *rejection* needs Secure Boot burned on the
spare (`provision/4`, irreversible); failed-self-check *rollback* needs the Phase 2
app path (`mark valid`). Keep the scope honest.

**Step 1 · `provision/ota-flash-slots.sh` — set up the A/B board.** Checks flash ≥ 8 MB,
builds + signs the chain (custom table emitted automatically), flashes the same signed
app into `ota_0` **and** `ota_1`, and blanks `otadata` (→ boots `ota_0`):
```sh
provision/ota-flash-slots.sh --port <PORT> --ssid <SSID> --pass <PASS> --supervisor <KEY> --keys token2
```
Reset and watch serial — expect the bootloader to enumerate both slots and load `ota_0`:
```
I (115) boot:  3 ota_0   OTA app   00 10 00020000 001e0000
I (128) boot:  5 ota_1   OTA app   00 11 00230000 001e0000
I (334) boot: Loaded app from partition at offset 0x20000
INFO - OTA: booted from App(Ota0) @ 0x020000 (1920 KiB)
```
> ✅ **Verified on hardware** (ESP32-S3, Secure Boot enabled, MAC `…55:18`): captured
> exactly the above; identity/roles/Wi-Fi all up. `otadata` uses `write-flash` (not
> `erase-region`, which esptool blocks on secure boards).

**Step 2 · `provision/ota-switch-slot.sh --slot 1` — prove slot selection.** Flips the
active slot via `otadata`, then power-cycle → serial should print
`OTA: booted from App(Ota1) @ 0x230000`. Switch back with `--slot 0`.

**Later (per-slot signature enforcement):** flash a **tampered** image (flip a byte,
don't re-sign) into the inactive slot, switch to it → the bootloader must refuse it and
fall back. Needs Secure Boot enrolled with our keys (already true on the current board).

## Open items to confirm on hardware

1. `booted_partition()` reports the right slot on S3 (MMU read) — validated by step 4/5.
2. `otatool.py` writes `otadata` cleanly on a secure-download board (should; it's a
   plain partition write). If secure-download blocks it, flip slots from the Phase 2
   app path instead.
3. Flash size on the spare (step 1) — the layout assumes ≥ 8 MB.
