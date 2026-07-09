#!/bin/bash
# ---------------------------------------------------------------------------------
# flash-signed-app.sh
#
# Build the esp-hal firmware, HSM-sign its app image, and flash it to an ESP32-S3
# that already has Secure Boot v2 enabled (only signed firmware boots). Each step
# is echoed as it runs. See docs/formal/SECURE-BOOT-V2.md.
#
# Prerequisites:
#   - Rust ESP toolchain (espup):   ~/export-esp.sh
#   - esptool with the HSM extra:    pip install 'esptool[hsm]'   (provides esptool + espsecure)
#   - OpenSC PKCS#11 + your signing token(s) inserted
#   - Board in download mode on <port>
#
# Required flags:
#   --ssid <s>            Wi-Fi SSID        (baked in at build via option_env!)
#   --pass <p>            Wi-Fi password
#   --supervisor <66hex>  supervisor P-256 pubkey  (SUPERVISOR_PUBKEY)
#   --port <dev>          board serial port, e.g. /dev/cu.usbmodemXXXX
#
# Signing config comes from the environment (passed through to sign-secure-boot.sh):
#   PRIMARY_INI  PRIMARY_PUB           primary token hsm_config + public-key PEM  (required)
#   BACKUP_INI   BACKUP_PUB            backup token (optional; omit or SKIP_BACKUP=1 to skip)
#   BACKUP_DRIVER (default PIV-II)     OpenSC driver for the backup token
#   ESPSECURE    (default espsecure)   espsecure binary (must have the [hsm] extra)
#
# Optional flags:
#   --features <list>    cargo features   (default: udp-transport,efuse-hmac-identity)
#   --app-offset <hex>   app partition offset in the secure-boot flash layout (default: 0x20000)
#
# Example:
#   PRIMARY_INI=hsm-token2.ini PRIMARY_PUB=sb_pub.pem SKIP_BACKUP=1 \
#     secure-boot/flash-signed-app.sh --ssid MyWifi --pass secret \
#       --supervisor 03c5803b...af3c --port /dev/cu.usbmodem5B7A1147281
# ---------------------------------------------------------------------------------
set -eo pipefail

FEATURES="udp-transport,efuse-hmac-identity"
APP_OFFSET="0x20000"
SSID=""; PASS=""; SUP=""; PORT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ssid)        SSID="$2";       shift 2;;
    --pass)        PASS="$2";       shift 2;;
    --supervisor)  SUP="$2";        shift 2;;
    --port)        PORT="$2";       shift 2;;
    --features)    FEATURES="$2";   shift 2;;
    --app-offset)  APP_OFFSET="$2"; shift 2;;
    -h|--help)     sed -n '2,45p' "$0"; exit 0;;
    *) echo "unknown argument: $1  (see --help)"; exit 1;;
  esac
done
: "${SSID:?--ssid required (see --help)}"
: "${PASS:?--pass required}"
: "${SUP:?--supervisor <66-hex P-256 pubkey> required}"
: "${PORT:?--port <serial device> required}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ELF="$REPO/target/xtensa-esp32s3-none-elf/release/target-esp32s3"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# --- Step 1: build the esp-hal firmware with the given Wi-Fi creds + supervisor ---
echo "### 1/4  cargo build  (features: $FEATURES, SSID: $SSID)"
( cd "$REPO/target-esp32s3" \
  && source "$HOME/export-esp.sh" >/dev/null 2>&1 \
  && WIFI_SSID="$SSID" WIFI_PASS="$PASS" SUPERVISOR_PUBKEY="$SUP" \
       cargo build --release --no-default-features --features "$FEATURES" )
[ -f "$ELF" ] || { echo "ELF not found at $ELF"; exit 1; }

# --- Step 2: convert the ELF into a flashable ESP32-S3 app image ---
echo "### 2/4  elf2image -> app.bin"
esptool --chip esp32s3 elf2image "$ELF" --output "$WORK/app.bin"

# --- Step 3: HSM-sign the app image (+ verify) via the shared signing helper ---
echo "### 3/4  HSM-sign + verify  (sign-secure-boot.sh; enter the numeric PIV PIN)"
"$REPO/secure-boot/sign-secure-boot.sh" "$WORK/app.bin" "$WORK/app-signed.bin"

# --- Step 4: flash the signed app; the secure bootloader verifies it on boot ---
echo "### 4/4  flash signed app @ $APP_OFFSET on $PORT"
esptool --chip esp32s3 --port "$PORT" --after hard_reset write_flash "$APP_OFFSET" "$WORK/app-signed.bin"

echo
echo "### done. Watch it boot on the secure-booted firmware:"
echo "    cat $PORT       # expect: 'Signature verified successfully!' -> 'Starting...' -> 'Got IP'"
