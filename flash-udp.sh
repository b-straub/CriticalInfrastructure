#!/bin/bash
# Flash the firmware for native clients (e.g. the SwiftUI app in clients/apple),
# building the `udp-transport` feature.
#
# NOTE: the device authenticates clients with P-256, so the supervisor arg is a
# P-256 identity. The 3rd arg accepts ANY of:
#   - a 66-hex COMPRESSED P-256 key (the app's "Copy" button),
#   - a PEM public-key FILE path, or
#   - inline PEM text (as keyroost / `openssl ... -pubout` emit)
# PEM is converted to 66-hex automatically. The identity lives in a Mac Secure
# Enclave key or a hardware PIV key (e.g. a Token2 in slot 9c).
#
# Add --efuse-hmac (4th arg) for a chip whose identity is rooted in a read-protected
# eFuse HMAC key (see docs/formal/EFUSE-HARDENING.md).
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
  echo "Error: Missing arguments."
  echo "Usage: ./flash-udp.sh <WIFI_SSID> <WIFI_PASSWORD> <SUPERVISOR_P256_PUBKEY_66HEX> [--efuse-hmac]"
  echo "  --efuse-hmac  derive the device identity from the read-protected eFuse HMAC key"
  echo "                (chip provisioned per docs/formal/EFUSE-HARDENING.md; firmware panics if absent)"
  exit 1
fi

# Export credentials so Rust's option_env!() can bake them into the firmware
export WIFI_SSID="$1"
export WIFI_PASS="$2"

# The supervisor arg accepts a 66-hex compressed P-256 key, a PEM file path, or
# inline PEM (as keyroost / `openssl ... -pubout` emit). PEM is converted to the
# 66-hex compressed form the firmware expects.
pem_to_hex() {  # strips indentation, reads a P-256 PEM pubkey on stdin -> 66-hex compressed
  sed 's/^[[:space:]]*//' | openssl ec -pubin -conv_form compressed -outform DER 2>/dev/null \
    | tail -c 33 | xxd -p -c 33
}
if [ -f "$3" ]; then
  SUPERVISOR_PUBKEY="$(pem_to_hex < "$3")"
elif printf '%s' "$3" | grep -q "BEGIN PUBLIC KEY"; then
  SUPERVISOR_PUBKEY="$(printf '%s\n' "$3" | pem_to_hex)"
else
  SUPERVISOR_PUBKEY="$(printf '%s' "$3" | tr 'A-F' 'a-f')"   # assume already 66-hex
fi
if ! printf '%s' "$SUPERVISOR_PUBKEY" | grep -qE '^0[23][0-9a-f]{64}$'; then
  echo "Error: supervisor key must be a 66-hex compressed P-256 pubkey, or a P-256 PEM (file or inline)."
  echo "  parsed: '$SUPERVISOR_PUBKEY'"
  exit 1
fi
export SUPERVISOR_PUBKEY
echo "==> SUPERVISOR_PUBKEY=$SUPERVISOR_PUBKEY"

# Optional 4th arg (or EFUSE_HMAC=1): derive the device identity from the
# read-protected eFuse HMAC key instead of flash (chip provisioned per
# docs/formal/EFUSE-HARDENING.md; the firmware panics if the key is absent).
FEATURES="udp-transport"
if [ "$4" = "--efuse-hmac" ] || [ "${EFUSE_HMAC:-}" = "1" ]; then
  FEATURES="$FEATURES,efuse-hmac-identity"
  echo "==> eFuse-HMAC identity build (device derives its keys from eFuse)."
fi

# Source the ESP toolchain environment
source ~/export-esp.sh

# Navigate to the firmware directory and flash the UDP flavor
cd target-esp32s3
cargo espflash flash --release --no-default-features --features "$FEATURES" --monitor
