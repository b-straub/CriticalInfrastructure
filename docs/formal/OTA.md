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

1. **A/B boot proof** — ✅ done. The secure-boot bootloader boots an esp-hal image from
   an A/B table and honors `otadata` slot selection. **No network code.**
2. **Apply path in-app** — ✅ done. `OtaUpdater`: `next_partition()` → write image →
   `activate_next_partition()` → set `New` → reboot → self-test → `set_current_ota_state(Valid)`.
3. **Transport** — ✅ done. Stream the signed image over TCP (`embassy-net`) into the
   inactive slot; Secure Boot verifies it on boot. (Authorization via the supervisor
   channel + anti-rollback are the remaining hardening — see below.)
4. **Move persistent state** — ✅ done. Roles/threshold/OTA-journal live in the plaintext
   `storage` partition, accessed via the ROM flash functions at a fixed offset (the
   partition table is encrypted under FE, so it can't be looked up — and esp-storage's
   capacity probe reads the encrypted `0x0` and fails). Verified over OTA, encrypted and not.
5. **Flash encryption** — ✅ done through Development mode + verified on hardware: Secure
   Boot + FE both enforced, and a **network OTA under encryption** installs, decrypts,
   boots the new slot, and confirms Valid. **Release** mode is the remaining final seal.
   Closes [`SECURE-BOOT-V2.md`](./SECURE-BOOT-V2.md) Phase C.

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

**Step 2 · `provision/ota-switch-slot.sh --slot <0|1>` — prove slot selection.** Writes a
fresh `otadata` selecting the slot (seq = slot+1, state `Valid`, correct ESP CRC-32) and
resets. **Write-only** — no flash read, no `erase-region` — so it works on this hardened
board where secure-download blocks reads (ESP-IDF `otatool.py` reads first, so it can't).
```sh
provision/ota-switch-slot.sh --port <PORT> --slot 1   # reset -> App(Ota1) @ 0x230000
provision/ota-switch-slot.sh --port <PORT> --slot 0   # reset -> App(Ota0) @ 0x020000
```
> ✅ **Verified on hardware** — clean round-trip:
> `boot: Loaded app from partition at offset 0x230000` → `OTA: booted from App(Ota1)`,
> then back to `ota_0`. Slot selection proven both ways. **→ 4.1 complete.**

**Later (per-slot signature enforcement):** flash a **tampered** image (flip a byte,
don't re-sign) into the inactive slot, switch to it → the bootloader must refuse it and
fall back. Needs Secure Boot enrolled with our keys (already true on the current board).

## Phase 2 runbook — in-app apply path (4.2)

**Step 3 · `provision/ota-apply.sh`** builds the app with the `ota-selftest` feature,
flashes it to `ota_0`, points `otadata` at `ota_0`, and monitors. On boot the app reads
its own image length from the esp_image header, copies the **whole** image into the
inactive slot via `OtaUpdater` (`next_partition` → write), `activate_next_partition()`,
marks it `New`, and resets. On the next boot it confirms itself `Valid`
(`ota.rs::confirm_if_pending`). Entirely on-device — no network.

```sh
provision/ota-apply.sh --port <PORT> --ssid <S> --pass <P> --supervisor <K> --keys token2
```
> ✅ **Verified on hardware:** `boot ota_0` → *copying full image (856 KiB)* → *wrote into
> Ota1* → *activated (New); resetting* → `boot ota_1 @ 0x230000` → *self-test passed → marked
> Valid*, and it stays on `ota_1`. **→ 4.2 complete.**

Two gotchas found + fixed here (both real, both would bite a network OTA too):
- The `storage` partition's subtype must be one the OTA library accepts (`spiffs`, not a
  raw `0x40`) — otherwise scanning partitions panics.
- A partial copy corrupts the slot when the two slots hold different builds, so the app
  copies the **exact** image length parsed from its header, not a fixed guess.

> The self-test build stays resident in `ota_1` afterward (fully functional). Reflash a
> plain build (`provision/5-flash-app.sh`) to drop the `ota-selftest` behavior.

## Phase 3 runbook — network delivery (4.3)

Build the app with the **`ota-net`** feature: it runs a TCP server on **:8081** that
receives a length-prefixed signed image (`[u32 LE length][image]`), streams it into the
inactive slot via `OtaUpdater`, activates it, and resets. **`provision/ota-push.sh`**
sends the image from the host over Wi-Fi.

```sh
# on the device: build+sign with ota-net, flash to a slot, boot it (note its "Got IP")
provision/3-build-sign.sh --ssid <S> --pass <P> --supervisor <K> --keys token2 \
  --features "udp-transport,efuse-hmac-identity,ota-net" --skip-bootloader
esptool --chip esp32s3 --port <PORT> --after no-reset write-flash 0x20000 secure-boot/out/app-signed.bin
provision/ota-switch-slot.sh --port <PORT> --slot 0

# from the host: push it over the network
provision/ota-push.sh --host <device-ip> --image secure-boot/out/app-signed.bin
```
> ✅ **Verified on hardware:** device on `ota_0` listening on `:8081`; pushed 876 544
> bytes over TCP; device installed into `ota_1`, activated, rebooted to
> `App(Ota1) @ 0x230000`, and stayed there (confirmed `Valid`). No USB cable.

**One pass (day-to-day update).** Once the board is provisioned and running `ota-net`,
`provision/ota-update.sh` does build → sign → deliver in a single command. Wi-Fi creds,
supervisor pubkey and the device IP come from the Keychain (`provision/store-creds.sh`,
incl. `--host <ip>`), so there are no args and the Token2 PIN is entered once:

```sh
provision/store-creds.sh --host 192.168.178.133   # once
provision/ota-update.sh                            # every update: build+sign+push, one pass
```
It keeps the current bootloader/partition layout (`--skip-bootloader`); on an encrypted
board the firmware encrypt-writes the image. Confirm it landed by the LCD build tag (line
2, `HHMM`) or the serial `Firmware <hash> built …` line changing.

**Security (deferred, tracked):** `:8081` is unauthenticated. Secure Boot is the
integrity backstop — a tampered/garbage image won't boot and rolls back — but a LAN
attacker could force reboots or push an older *validly signed* image. Next: gate the
trigger through the authenticated supervisor channel, and add anti-rollback
(`SECURE_VERSION`).

## Phase 5 — flash encryption (4.5, ✅ complete — Dev-encrypted, network-OTA verified, Release-sealed)

**What's encrypted.** Flash encryption force-encrypts the bootloader, partition table,
**all app slots**, and **`otadata`** (IDF default — `otadata` cannot be made plaintext).
Only `storage`, `nvs`, `phy_init` stay plaintext (data partitions, not flagged).
`esp-storage` reads *raw SPI* (ciphertext under FE), so reading any encrypted region would
need decryption.

**We never decrypt-read.** Instead of reading `otadata` / the partition table, the OTA
path self-manages its state (`src/ota.rs`), which also drops the OTA crate:
- running slot ← the **MMU** (`booted_slot` — a register read, not flash);
- OTA journal (seq / active / pending) ← the **plaintext `storage`** partition;
- we only ever **write** `otadata` + app slots (our own `ota_select` entries), encrypted
  via `esp_rom_spiflash_write_encrypted` when `Efuse::flash_encryption()`, raw otherwise.

The bootloader does the decrypt-reads to pick the slot (built in). Works with or without FE.

> ✅ **A1 verified on hardware (FE off):** the self-managed cycle round-trips —
> `slot 0 →push→ slot 1` (confirmed Valid, stays), `slot 1 →push→ slot 0` — same behavior
> as 4.3 with **zero encrypted-flash reads**. All feature combos compile clean. **A2** (the
> encrypt-write branch) is wired + FE-runtime-gated; it goes live only on an encrypted
> board and is validated below.

**Enablement (a unit, Development mode):**
1. ✅ Bootloader `CONFIG_SECURE_FLASH_ENC_ENABLED=y` + AES-256 + **Development** mode, Secure
   Boot kept on (`secure-boot/sdkconfig.defaults`). Partition table unchanged (app
   auto-encrypted; `storage`/`nvs` plaintext).
2. ✅ Flashed the signed chain; first boot auto-generated + burned the XTS-AES-256 key
   (KEY3/4) and encrypted flash in place. Verified: boots, app runs, roles/threshold load.
3. ✅ **Network OTA under encryption verified on hardware:** pushed the signed image →
   `receiving … [encrypted]` → encrypt-written to `ota_1` → decrypted + booted → *slot 1
   marked Valid* and stable across reset. Dev-mode reflash is `esptool write-flash --encrypt`
   (repeatable). Once encrypted, the app updates itself over the air with no cable.
4. ✅ **Release seal (stage D) — `provision/6-release-seal.sh` — burned + verified on hardware.**
   No bootloader rebuild or re-provision: an already Dev-encrypted board graduates by burning
   three lock bits directly. On the live board (`usbmodem5B7A1147281`) all other hardening was
   already done — Secure Boot on, HMAC identity burned + read-protected (`KEY_PURPOSE_0=HMAC_UP`),
   JTAG off (`DIS_PAD_JTAG`/`DIS_USB_JTAG`) — so only these were pending, and were burned in one
   BLOCK0 write:
   - `SPI_BOOT_CRYPT_CNT` `0b001 → 0b111` — ROM won't re-encrypt flash (kills `write-flash --encrypt`); encryption stays on.
   - `DIS_DOWNLOAD_MANUAL_ENCRYPT` `0 → 1` — UART can't encrypt-write.
   - `ENABLE_SECURITY_DOWNLOAD` `0 → 1` — UART download can't read/dump/erase flash or eFuses.

   The cable can no longer decrypt, dump, or reflash — proven by espefuse itself now refusing
   ("Secure download mode is enabled. espefuse can not continue"). The only way to change
   firmware is signed + encrypted **OTA** (`provision/ota-update.sh`) — the app encrypt-writes
   from RAM, a path these bits don't gate. **Verified post-seal:** power-cycle boots clean, and
   a fresh OTA landed — the on-LCD build tag flipped `0949 → 1228` on a board the cable can no
   longer touch. Re-check the lockout anytime with **`provision/verify-seal.sh --port <dev>`**
   (eFuse read / flash read / encrypt-write — all three reported DENIED; its write test targets
   an unused offset so it's harmless). Not fixed by the seal: `:8081` is unauthenticated and there is no
   `SECURE_VERSION` anti-rollback, so a validly-signed *older* image could still be pushed —
   a separate app-layer/eFuse task.

**Three bugs found + fixed enabling FE** (all in the "not bench-verifiable" set):
- `esp_storage::FlashStorage::new()` probes chip size by reading the bootloader header at
  `0x0` — encrypted under FE → mis-sizes the chip → every storage op fails a bounds check.
  Fixed: `storage.rs` uses the ROM flash functions directly on the fixed `storage` offset.
- `esp_rom_spiflash_write_encrypted_enable()` breaks flash XIP, so the encrypt-write window
  must run from RAM (`.rwtext`), or the next instruction fetch hangs.
- The ROM erase/write need `esp_rom_spiflash_unlock()` first (esp-storage does this).

## Open items to confirm on hardware

1. ~~`booted_partition()` reports the right slot~~ — ✅ verified (Step 1/2).
2. ~~Host-side `otadata` write on a secure-download board~~ — ✅ done write-only
   (`ota-switch-slot.sh`); `otatool.py` is unusable here because it reads first.
3. ~~Flash size~~ — ✅ board is 16 MB; layout needs ≥ 8 MB.
