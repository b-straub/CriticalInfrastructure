# Secure Boot v2 — Enablement Runbook (ESP32-S3, HSM-signed)

Secure Boot v2 makes the ROM run **only firmware signed by an enrolled key**. It is
the layer *above* the eFuse hardening in [`EFUSE-HARDENING.md`](./EFUSE-HARDENING.md):
that doc roots the *device identity* in hardware; this one roots *what code may
boot*. The **signing** half is already validated end-to-end (Token2 + Thetis
RSA-3072-PSS, see EFUSE-HARDENING.md § Secure-boot signing). What remains is the
**bootloader integration + the irreversible enable**, below.

> ⚠️ **`SECURE_BOOT_EN` is permanent and a broken chain bricks the board
> unrecoverably.** Do the first enablement on a **spare ESP32-S3**, never the
> working unit. Everything through Phase A is non-destructive; Phase B burns eFuses.

## The integration challenge (read first)

Secure Boot v2 is an **ESP-IDF** feature: the ROM verifies the **ESP-IDF second-stage
bootloader**, which verifies the app. Our firmware is **bare esp-hal (`no_std` Rust)
flashed with espflash**, which ships a *prebuilt, non-secure* bootloader — there is
**no documented espflash/esp-hal secure-boot path**. So the plan is a hybrid:

- build a **secure-boot bootloader** with `idf.py` (the only supported way),
- **HSM-sign** both that bootloader **and** the esp-hal app with the validated flow,
- flash the signed pair with espflash/esptool, then burn the digests + `SECURE_BOOT_EN`.

**The single biggest unknown** — validate it on the spare board before trusting it —
is whether the IDF secure-boot bootloader **boots a signed esp-hal app image**
(image-format compatibility). Signatures verifying ≠ the bootloader accepting the
image at runtime.

## S3 facts that shape the runbook

- **3 trustable digests** (`SECURE_BOOT_DIGEST0/1/2`); an image can carry **up to 3
  signature blocks**, so we sign each image with **both keys** → either enrolled key
  verifies it. → `DIGEST0` = **Token2** (`fa05a2e9…c88f362`), `DIGEST1` = **Thetis**
  (`25263f48…14dc252`). They occupy key blocks **KEY1/KEY2** (KEY0 is the HMAC
  identity — no collision).
- Digests + `SECURE_BOOT_EN` burn **on first boot** of a valid signed chain (or
  manually via `espefuse`).
- Enabling **auto-disables JTAG** (already done here) and the **USB-OTG** stack —
  but the **USB-Serial-JTAG CDC survives**, so espflash still works.
- **Pair with flash encryption** — without it, a `time-of-check/time-of-use` flash
  swap defeats Secure Boot.
- `KEY_REVOKE0/1/2` are permanent; revoking **all** keys bricks the board.

## Prerequisites

- **ESP-IDF** installed (`idf.py`, `esptool`, `espsecure`) — this is separate from
  the espup Rust toolchain. `. $IDF_PATH/export.sh`.
- The validated HSM setup: `esptool[hsm]`, an `hsm.ini` per token (Token2 = default
  OpenSC; **Thetis needs `OPENSC_DRIVER=PIV-II`**), and the two public keys
  (`sb_pub.pem` = Token2, `sb_backup_pub.pem` = Thetis).
- A **spare ESP32-S3**. A serial console on the USB-Serial-JTAG port.

---

## Phase A — build + sign (no hardware, no burns)

> **✅ Validated end-to-end** (ESP-IDF v5.5.4): the bootloader builds, and both the
> bootloader and the esp-hal app were 2-key HSM-signed (Token2 + Thetis) and
> `verify-signature`-clean, offline. The reproducible bootloader project + a
> `sign-secure-boot.sh` helper live in [`../../secure-boot/`](../../secure-boot/).

**A1. A minimal IDF project for the bootloader** (a `CMakeLists.txt`, a `main/` with
an empty `app_main`, and this `sdkconfig.defaults` — validated with IDF v5.5.4):
```
CONFIG_IDF_TARGET="esp32s3"
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=n          # we sign externally (HSM) — no key at build time
CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE=n   # don't auto-revoke on the spare
CONFIG_SECURE_FLASH_ENC_ENABLED=n                   # flash encryption is a separate, later step
CONFIG_PARTITION_TABLE_OFFSET=0xc000                # SEE NOTE: secure-boot bootloader overruns 0x8000
```
> **Flash-layout note (found while building):** the secure-boot bootloader is
> **larger — `0x9000` bytes** (it embeds RSA-3072 verification + mbedTLS), so it
> overruns the default partition-table offset `0x8000` (`bootloader binary size …
> too large`). Bump it to **`0xc000`**. This shifts the *whole* layout down, so the
> esp-hal app's flash offsets in Phase B **must match this partition table** (the
> app no longer sits at the old `0x10000`).

**A2. Build the (secure-padded, unsigned) bootloader:**
```sh
idf.py set-target esp32s3
idf.py bootloader          # -> build/bootloader/bootloader.bin  (padded, no signature yet)
```

**A3. HSM-sign the bootloader with BOTH keys** (Token2, then append Thetis):
```sh
espsecure sign-data --version 2 --hsm --hsm-config hsm-token2.ini \
  --output bootloader-signed.bin build/bootloader/bootloader.bin
OPENSC_DRIVER=PIV-II espsecure sign-data --version 2 --hsm --hsm-config hsm-thetis.ini \
  --append-signatures --output bootloader-signed.bin bootloader-signed.bin
```

**A4. Build the esp-hal app and export a raw, secure-padded image:**
```sh
cd target-esp32s3
WIFI_SSID=… WIFI_PASS=… SUPERVISOR_PUBKEY=03c5803b… \
  cargo build --release --no-default-features --features "udp-transport,efuse-hmac-identity"
espflash save-image --chip esp32s3 --merge=false \
  target/xtensa-esp32s3-none-elf/release/<app> app.bin      # raw app image
```

**A5. HSM-sign the app with BOTH keys** (same pattern as A3), `-> app-signed.bin`.

**A6. Verify every signature offline — must pass before any hardware:**
```sh
espsecure verify-signature --version 2 --keyfile sb_pub.pem        bootloader-signed.bin
espsecure verify-signature --version 2 --keyfile sb_backup_pub.pem bootloader-signed.bin
espsecure verify-signature --version 2 --keyfile sb_pub.pem        app-signed.bin
espsecure verify-signature --version 2 --keyfile sb_backup_pub.pem app-signed.bin
```
All four `Signature block N … verification successful`. If any fail, **stop**.

---

## Phase B — validate on a SPARE board (this burns eFuses)

Partition offsets from this project's table: bootloader `0x0`, partition table
`0x8000`, factory app `0x10000`.

**B1. Flash the signed chain** (secure boot not yet enabled in eFuse):
```sh
esptool --chip esp32s3 --port <PORT> write_flash \
  0x0 bootloader-signed.bin  0x8000 partition-table.bin  0x10000 app-signed.bin
```

**B2. Enable Secure Boot.** Either let the secure-boot bootloader burn it on first
boot, or (preferred, explicit) burn manually so you control the order:
```sh
espefuse --port <PORT> burn-key BLOCK_KEY1 sb_digest.bin        SECURE_BOOT_DIGEST0
espefuse --port <PORT> burn-key BLOCK_KEY2 sb_backup_digest.bin SECURE_BOOT_DIGEST1
espefuse --port <PORT> burn-efuse SECURE_BOOT_EN 1
```
(Rehearse first with `espefuse --virt --chip esp32s3 …`, as in EFUSE-HARDENING.md.)

**B3. Positive test:** power-cycle → the board boots the signed app (serial shows the
normal boot + secure-boot-enabled banner). This is the moment that proves the
**IDF-bootloader-boots-esp-hal-app** question.

**B4. Negative test:** flash a **tampered** app (flip a byte, don't re-sign) → the
device must **refuse to boot** it. That's Secure Boot working.

**B5. Reflash test:** re-sign a fresh app (HSM) → flashes and boots. An **unsigned**
app must be rejected. Confirms you can still update, but only signed.

If B3–B5 all hold on the spare, the chain is proven.

---

## Phase C — production board + final seals

1. Repeat Phase B on the working unit (its HMAC identity + JTAG-off are already done;
   the digests go in the still-free KEY1/KEY2).
2. **Flash encryption** (XTS-AES-256) — the recommended companion; a separate burn,
   ideally in the same session so the flash key is read-protected from the start.
3. **`ENABLE_SECURITY_DOWNLOAD`** (the read-lock deferred in EFUSE-HARDENING.md
   Stage 4) — with Secure Boot on, download mode already only accepts signed writes;
   this additionally blocks reads. Do it **last**.

## Irreversibility & brick checklist

- [ ] Signed images ready and `verify-signature`-clean **before** burning any digest.
- [ ] Both digests enrolled (Token2 + Thetis) so a lost token isn't fatal.
- [ ] Never revoke all keys.
- [ ] Accept: after enable, only signed firmware boots/flashes; USB-OTG off
      (USB-Serial-JTAG still flashes); no further eFuse read-protection unless
      `CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS` was set (our HMAC key is already
      read-protected, so unaffected).
- [ ] First enablement on a **spare board**.

## Open items to confirm on hardware (documented unknowns, not silent gaps)

1. **IDF bootloader ↔ esp-hal app image** boots at runtime (Phase B3) — the crux.
2. Exact `espflash`/`esptool` offsets vs. this project's partition table (verify with
   `esptool image-info` on the signed app).
3. `--append-signatures` multi-HSM flow produces a 2-block image both keys verify (A6
   already checks this offline).

---

*Signing validated on real hardware (Token2 + Thetis, EFUSE-HARDENING.md). Bootloader
integration + enable are staged here for a spare-board session. Do not run Phase B on
the working unit until the spare passes B3–B5.*
