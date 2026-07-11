# Secure Boot v2 — bootloader project + signing helper

Reproducible pieces for the enablement runbook in
[`../docs/formal/SECURE-BOOT-V2.md`](../docs/formal/SECURE-BOOT-V2.md).

- **`CMakeLists.txt`, `main/`, `sdkconfig.defaults`** — a minimal ESP-IDF project
  whose only job is `idf.py bootloader`: a Secure Boot v2, external/HSM-signed
  second-stage bootloader for the ESP32-S3 (validated with ESP-IDF v5.5.4).
- **`sign-secure-boot.sh`** — sign a bootloader or app image with the primary
  hardware token, append the backup token, and verify both (espsecure + PKCS#11).

## Build the bootloader

```sh
. $IDF_PATH/export.sh
idf.py -C secure-boot set-target esp32s3
idf.py -C secure-boot bootloader        # -> secure-boot/build/bootloader/bootloader.bin
```

## Toolchain + key enrollment — use the pipeline

The full clone→app flow (toolchains, key enrollment, harden, build/sign, flash) lives
in [`../provision/`](../provision/) — one parameterized script per stage. In particular:

```sh
provision/0-toolchains.sh install                 # espsecure[hsm] venv at ~/.esptool-hsm, etc.
provision/1-enroll-key.sh --name mainToken           # -> hsm-mainToken.ini, mainToken_pub.pem, mainToken_digest.bin
provision/1-enroll-key.sh --name backupToken --driver PIV-II
```

This directory holds the two pieces those stages reuse: the **bootloader project**
(built above) and **`sign-secure-boot.sh`** below.

## Sign a bootloader (or any image) standalone

`provision/3-build-sign.sh` calls this for you; run it directly only for one-offs
(defaults read `hsm-mainToken.ini` / `mainToken_pub.pem` from this directory):

```sh
SKIP_BACKUP=1 ./sign-secure-boot.sh build/bootloader/bootloader.bin bootloader-signed.bin
```
(For the backup token backup too: drop `SKIP_BACKUP`; it appends `hsm-backupToken.ini` / `backupToken_pub.pem`.)

## Rebuild + sign + flash the esp-hal app

That's stage 5 — a clean, parameterized command (no env-var prefixes):

```sh
provision/5-flash-app.sh --ssid MyWifi --pass secret \
  --supervisor 03c5803b…af3c --port /dev/cu.usbmodemXXXX --keys mainToken
```

Validated end-to-end (main token + backup token on-card RSA-3072): bootloader **and** app both
2-key HSM-signed and `verify-signature`-clean, offline, zero burns.

> **Phase B** — the irreversible eFuse burns (`SECURE_BOOT_DIGEST0/1` + `SECURE_BOOT_EN`)
> and the boot test — is **spare-board only**. And PIV PINs must be **numeric**
> (macOS CryptoTokenKit requirement).
