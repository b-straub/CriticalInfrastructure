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

## Sign a bootloader or app

```sh
pip install 'esptool[hsm]'                       # once
cp secure-boot/hsm-config.ini.example hsm-token2.ini   # + hsm-thetis.ini; fill per token
PRIMARY_INI=hsm-token2.ini PRIMARY_PUB=sb_pub.pem \
BACKUP_INI=hsm-thetis.ini  BACKUP_PUB=sb_backup_pub.pem BACKUP_DRIVER=PIV-II \
  ./secure-boot/sign-secure-boot.sh secure-boot/build/bootloader/bootloader.bin bootloader-signed.bin
```

Validated end-to-end (Token2 + Thetis on-card RSA-3072): bootloader **and** app both
2-key HSM-signed and `verify-signature`-clean, offline, zero burns.

> **Phase B** — the irreversible eFuse burns (`SECURE_BOOT_DIGEST0/1` + `SECURE_BOOT_EN`)
> and the boot test — is **spare-board only**. And PIV PINs must be **numeric**
> (macOS CryptoTokenKit requirement).
