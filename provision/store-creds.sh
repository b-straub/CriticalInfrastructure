#!/bin/bash
# provision/store-creds.sh — store the Wi-Fi SSID + password and the supervisor pubkey in
# the macOS Keychain, so the build/flash scripts read them instead of taking them on the
# command line every time. (The Wi-Fi password is the only real secret; SSID and the
# supervisor *public* key aren't, but keeping them together is convenient — and it mirrors
# the SwiftUI app reading the Wi-Fi credential from Keychain.)
#
#   provision/store-creds.sh --ssid <S> --pass <P> --supervisor <66hex|PEM file|inline PEM>
#   provision/store-creds.sh show     # print what's stored (password stays hidden)
source "$(dirname "$0")/lib.sh"

if [ "${1:-}" = "show" ]; then
    load_creds
    echo "SSID:       ${SSID:-<none>}"
    echo "supervisor: ${SUP:-<none>}"
    echo "password:   $([ -n "${PASS:-}" ] && echo '<set>' || echo '<none>')"
    exit 0
fi

SSID="" PASS="" SUP=""
while [ $# -gt 0 ]; do case "$1" in
  --ssid) SSID="$2"; shift 2;; --pass) PASS="$2"; shift 2;; --supervisor) SUP="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
[ -n "$SSID" ] && [ -n "$PASS" ] && [ -n "$SUP" ] || die "need --ssid, --pass, --supervisor (or: $0 show)"
SUPHEX="$(supervisor_to_hex "$SUP")"  # normalize PEM/hex -> 66-hex before storing

security add-generic-password -U -s "$KC_WIFI" -a "$SSID" -w "$PASS" \
  && echo "stored Wi-Fi (SSID '$SSID' + password) in Keychain [$KC_WIFI]"
security add-generic-password -U -s "$KC_SUP" -a "supervisor" -w "$SUPHEX" \
  && echo "stored supervisor pubkey $SUPHEX [$KC_SUP]"
echo "done — build/flash scripts can now omit --ssid/--pass/--supervisor."
