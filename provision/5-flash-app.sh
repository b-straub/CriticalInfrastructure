#!/bin/bash
# provision/5-flash-app.sh — stage 5: rebuild, sign, and flash JUST the app to an
# already-secure-booted board (the everyday iterate loop). Bootloader + eFuses are
# untouched; the on-device secure bootloader verifies the app on boot.
#
#   provision/5-flash-app.sh --ssid X --pass Y --supervisor <k> --port /dev/cu.XXXX
#   provision/5-flash-app.sh --ssid X --pass Y --supervisor <k> --port /dev/cu.XXXX --keys mainToken,backupToken
#
#   --ssid/--pass       Wi-Fi creds baked into the app
#   --supervisor <k>    P-256 supervisor pubkey: 66-hex, PEM file, or inline PEM
#   --port <dev>        board serial port
#   --keys <a,b>        signing key(s), first = primary  (default: mainToken,backupToken)
#   --features <list>   cargo features (default: udp-transport,efuse-hmac-identity)
#   --app-offset <hex>  app slot (default: 0x20000)
source "$(dirname "$0")/lib.sh"

SSID="" PASS="" SUP="" PORT="" KEYS="mainToken,backupToken" FEATURES="udp-transport,efuse-hmac-identity" OFF="$APP_OFFSET_DEFAULT"
while [ $# -gt 0 ]; do case "$1" in
  --ssid) SSID="$2"; shift 2;; --pass) PASS="$2"; shift 2;; --supervisor) SUP="$2"; shift 2;;
  --port) PORT="$2"; shift 2;; --keys) KEYS="$2"; shift 2;;
  --features) FEATURES="$2"; shift 2;; --app-offset) OFF="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
load_creds # fill SSID/PASS/SUP from the Keychain if not given (provision/store-creds.sh)
[ -n "$SSID" ] && [ -n "$PASS" ] && [ -n "$SUP" ] || die "--ssid/--pass/--supervisor required (or store once: provision/store-creds.sh)"
require_port "$PORT"; need esptool "brew install esptool"
SUPHEX="$(supervisor_to_hex "$SUP")"
IFS=',' read -r PRIMARY BACKUP _ <<< "$KEYS"
[ -f "$(key_ini "$PRIMARY")" ] || die "key '$PRIMARY' not enrolled (provision/1-enroll-key.sh --name $PRIMARY)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

note "1/4 build the app (features: $FEATURES, SSID: $SSID)"
( cd "$FW" && source "$HOME/export-esp.sh" >/dev/null 2>&1 \
  && WIFI_SSID="$SSID" WIFI_PASS="$PASS" SUPERVISOR_PUBKEY="$SUPHEX" \
       cargo build --release --no-default-features --features "$FEATURES" )
[ -f "$ELF" ] || die "app ELF missing: $ELF"

note "2/4 elf2image -> app.bin"
esptool --chip esp32s3 elf2image "$ELF" --output "$WORK/app.bin"

note "3/4 HSM-sign + verify (insert '$PRIMARY'; enter the numeric PIV PIN)"
ESPSECURE="$(espsecure_bin)" \
PRIMARY_INI="$(key_ini "$PRIMARY")" PRIMARY_PUB="$(key_pub "$PRIMARY")" \
BACKUP_INI="$(key_ini "${BACKUP:-x}")" BACKUP_PUB="$(key_pub "${BACKUP:-x}")" \
BACKUP_DRIVER="$(key_driver "${BACKUP:-}")" \
SKIP_BACKUP="$([ -n "${BACKUP:-}" ] && echo 0 || echo 1)" \
  "$SB/sign-secure-boot.sh" "$WORK/app.bin" "$WORK/app-signed.bin"

note "4/4 flash signed app @ $OFF on $PORT"
esptool --chip esp32s3 --port "$PORT" --after hard_reset write_flash "$OFF" "$WORK/app-signed.bin"
echo
echo "OK — watch it boot:  cat $PORT"
echo "     expect: 'Signature verified successfully!' -> 'Starting...' -> 'Got IP'"
