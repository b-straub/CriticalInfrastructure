#!/bin/bash
# provision/store-creds.sh — store the Wi-Fi SSID + password and the supervisor pubkey in
# the macOS Keychain, so the build/flash scripts read them instead of taking them on the
# command line every time. (The Wi-Fi password is the only real secret; SSID and the
# supervisor *public* key aren't, but keeping them together is convenient — and it mirrors
# the SwiftUI app reading the Wi-Fi credential from Keychain.)
#
#   provision/store-creds.sh --ssid <S> --pass <P> --supervisor <66hex|PEM file|inline PEM>
#   provision/store-creds.sh --host <device-ip>   # store the device IP for network OTA
#   provision/store-creds.sh show     # print what's stored (password stays hidden)
#
# Any subset of --ssid/--pass/--supervisor and --host may be given; only what's passed is
# stored. (--ssid/--pass/--supervisor go together — all three or none.)
source "$(dirname "$0")/lib.sh"

if [ "${1:-}" = "show" ]; then
    load_creds
    echo "SSID:       ${SSID:-<none>}"
    echo "supervisor: ${SUP:-<none>}"
    echo "password:   $([ -n "${PASS:-}" ] && echo '<set>' || echo '<none>')"
    echo "device IP:  ${HOST:-<none>}"
    exit 0
fi

SSID="" PASS="" SUP="" HOST=""
while [ $# -gt 0 ]; do case "$1" in
  --ssid) SSID="$2"; shift 2;; --pass) PASS="$2"; shift 2;; --supervisor) SUP="$2"; shift 2;;
  --host) HOST="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done

WROTE=0
if [ -n "$SSID$PASS$SUP" ]; then
  [ -n "$SSID" ] && [ -n "$PASS" ] && [ -n "$SUP" ] || die "--ssid/--pass/--supervisor go together (all three)"
  SUPHEX="$(supervisor_to_hex "$SUP")"  # normalize PEM/hex -> 66-hex before storing
  security add-generic-password -U -s "$KC_WIFI" -a "$SSID" -w "$PASS" \
    && echo "stored Wi-Fi (SSID '$SSID' + password) in Keychain [$KC_WIFI]"
  security add-generic-password -U -s "$KC_SUP" -a "supervisor" -w "$SUPHEX" \
    && echo "stored supervisor pubkey $SUPHEX [$KC_SUP]"
  WROTE=1
fi
if [ -n "$HOST" ]; then
  security add-generic-password -U -s "$KC_HOST" -a "device" -w "$HOST" \
    && echo "stored device IP $HOST [$KC_HOST]"
  WROTE=1
fi
[ "$WROTE" = 1 ] || die "nothing to store — pass --ssid/--pass/--supervisor and/or --host (or: $0 show)"
echo "done — build/flash/update scripts can now omit these."
