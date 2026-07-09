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

## Toolchain: `espsecure` with the HSM extra

Homebrew's `esptool` does **not** bundle the PKCS#11 (`[hsm]`) extra. Install it once
in a dedicated venv (no conflict with brew) and point `ESPSECURE` at it:

```sh
python3 -m venv ~/.esptool-hsm && ~/.esptool-hsm/bin/pip install 'esptool[hsm]'
export ESPSECURE=~/.esptool-hsm/bin/espsecure          # add to your shell profile
```

## One-time signing config (gitignored, kept out of the repo)

```sh
cp secure-boot/hsm-config.ini.example secure-boot/hsm-token2.ini   # PIV 9a labels already correct
# the token's secure-boot public key (for verify), read straight from the card:
pkcs11-tool --module /opt/homebrew/lib/opensc-pkcs11.so --read-object --type pubkey --id 01 -o /tmp/t.der \
  && openssl rsa -pubin -inform DER -in /tmp/t.der -pubout -out secure-boot/sb_pub.pem
```

## Sign a bootloader (or any image)

```sh
PRIMARY_INI=secure-boot/hsm-token2.ini PRIMARY_PUB=secure-boot/sb_pub.pem SKIP_BACKUP=1 \
  ./secure-boot/sign-secure-boot.sh secure-boot/build/bootloader/bootloader.bin bootloader-signed.bin
```
(For the Thetis backup too: drop `SKIP_BACKUP`, add `BACKUP_INI`/`BACKUP_PUB`/`BACKUP_DRIVER=PIV-II`.)

## Rebuild + sign + flash the esp-hal app (all-in-one)

`flash-signed-app.sh` builds the firmware with your Wi-Fi creds, signs the app image,
and flashes it to a secure-booted board. See `--help` for every flag/env.

```sh
ESPSECURE=~/.esptool-hsm/bin/espsecure \
PRIMARY_INI=secure-boot/hsm-token2.ini PRIMARY_PUB=secure-boot/sb_pub.pem SKIP_BACKUP=1 \
  ./secure-boot/flash-signed-app.sh \
    --ssid MyWifi --pass secret \
    --supervisor 03c5803b…af3c --port /dev/cu.usbmodemXXXX
```

Validated end-to-end (Token2 + Thetis on-card RSA-3072): bootloader **and** app both
2-key HSM-signed and `verify-signature`-clean, offline, zero burns.

> **Phase B** — the irreversible eFuse burns (`SECURE_BOOT_DIGEST0/1` + `SECURE_BOOT_EN`)
> and the boot test — is **spare-board only**. And PIV PINs must be **numeric**
> (macOS CryptoTokenKit requirement).
