#!/bin/bash
# provision/3-build-sign.sh — stage 3: build + HSM-sign the secure-boot chain.
# Builds the ESP-IDF secure-boot bootloader and the esp-hal app, signs BOTH with your
# enrolled key(s), and verifies. No hardware, no burns. Output lands in --outdir.
# See docs/formal/SECURE-BOOT-V2.md Phase A.
#
#   provision/3-build-sign.sh --ssid X --pass Y --supervisor <k> --keys token2,thetis
#   provision/3-build-sign.sh --ssid X --pass Y --supervisor <k> --skip-bootloader   # app only
#
#   --ssid/--pass       Wi-Fi creds baked into the app
#   --supervisor <k>    P-256 supervisor pubkey: 66-hex, PEM file, or inline PEM
#   --keys <a,b>        enrolled key names, first = primary, rest appended  (default: token2)
#   --outdir <dir>      where signed images land            (default: secure-boot/out)
#   --features <list>   cargo features (default: udp-transport,efuse-hmac-identity)
#   --skip-bootloader   sign only the app (bootloader already built/flashed)
source "$(dirname "$0")/lib.sh"

SSID="" PASS="" SUP="" KEYS="token2" OUTDIR="$SB/out" FEATURES="udp-transport,efuse-hmac-identity" SKIPBL=0
while [ $# -gt 0 ]; do case "$1" in
  --ssid) SSID="$2"; shift 2;; --pass) PASS="$2"; shift 2;; --supervisor) SUP="$2"; shift 2;;
  --keys) KEYS="$2"; shift 2;; --outdir) OUTDIR="$2"; shift 2;; --features) FEATURES="$2"; shift 2;;
  --skip-bootloader) SKIPBL=1; shift;; -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
[ -n "$SSID" ] && [ -n "$PASS" ] && [ -n "$SUP" ] || die "--ssid, --pass, --supervisor required"
need esptool "brew install esptool"
SUPHEX="$(supervisor_to_hex "$SUP")"
IFS=',' read -r PRIMARY BACKUP _ <<< "$KEYS"
[ -f "$(key_ini "$PRIMARY")" ] || die "key '$PRIMARY' not enrolled (provision/1-enroll-key.sh --name $PRIMARY)"
mkdir -p "$OUTDIR"

# sign <unsigned> <signed> : primary key, then append backup if a second --keys name was given
sign() {
  ESPSECURE="$(espsecure_bin)" \
  PRIMARY_INI="$(key_ini "$PRIMARY")" PRIMARY_PUB="$(key_pub "$PRIMARY")" \
  BACKUP_INI="$(key_ini "${BACKUP:-x}")" BACKUP_PUB="$(key_pub "${BACKUP:-x}")" \
  BACKUP_DRIVER="$(key_driver "${BACKUP:-}")" \
  SKIP_BACKUP="$([ -n "${BACKUP:-}" ] && echo 0 || echo 1)" \
    "$SB/sign-secure-boot.sh" "$1" "$2"
}

if [ "$SKIPBL" != 1 ]; then
  note "1/4 build the secure-boot bootloader (idf.py)"
  [ -f "$HOME/esp/esp-idf/export.sh" ] || die "ESP-IDF not found (~/esp/esp-idf) — provision/0-toolchains.sh"
  . "$HOME/esp/esp-idf/export.sh" >/dev/null 2>&1
  idf.py -C "$SB" set-target esp32s3 >/dev/null
  idf.py -C "$SB" bootloader
  idf.py -C "$SB" partition-table
  note "2/4 sign the bootloader -> $OUTDIR/bootloader-signed.bin"
  sign "$SB/build/bootloader/bootloader.bin" "$OUTDIR/bootloader-signed.bin"
  cp "$SB/build/partition_table/partition-table.bin" "$OUTDIR/partition-table.bin"
else
  note "1-2/4 bootloader skipped (--skip-bootloader)"
fi

note "3/4 build the esp-hal app (features: $FEATURES)"
( cd "$FW" && source "$HOME/export-esp.sh" >/dev/null 2>&1 \
  && WIFI_SSID="$SSID" WIFI_PASS="$PASS" SUPERVISOR_PUBKEY="$SUPHEX" \
       cargo build --release --no-default-features --features "$FEATURES" )
[ -f "$ELF" ] || die "app ELF missing: $ELF"
esptool --chip esp32s3 elf2image "$ELF" --output "$OUTDIR/app.bin"

note "4/4 sign the app -> $OUTDIR/app-signed.bin"
sign "$OUTDIR/app.bin" "$OUTDIR/app-signed.bin"
echo "OK — signed chain in $OUTDIR/:"; ls -1 "$OUTDIR"
