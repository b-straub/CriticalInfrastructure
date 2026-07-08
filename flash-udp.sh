#!/bin/bash
# Flash the UDP-transport ROM flavor (for native clients, e.g. the SwiftUI app in
# clients/apple). Mirrors flash.sh but selects `udp-transport` instead of the
# default `http-transport`. The two flavors are mutually exclusive.
#
# NOTE: the UDP flavor authenticates clients with P-256, so <SUPERVISOR_PUBKEY_HEX>
# here is the 66-hex COMPRESSED P-256 key of the supervisor identity, NOT the
# 64-hex Ed25519 key the HTTP/flash.sh flavor uses. That identity can be either:
#   - a Mac Secure Enclave key (the app's "Copy" button), or
#   - a hardware PIV key (e.g. a Token2 in slot 9c); read its compressed pubkey
#     from the card's certificate:
#       pkcs15-tool --read-certificate 02 | openssl x509 -noout -pubkey \
#         | openssl ec -pubin -conv_form compressed -outform DER | tail -c 33 | xxd -p -c 33
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
  echo "Error: Missing arguments."
  echo "Usage: ./flash-udp.sh <WIFI_SSID> <WIFI_PASSWORD> <SUPERVISOR_P256_PUBKEY_66HEX>"
  exit 1
fi

# Export credentials so Rust's option_env!() can bake them into the firmware
export WIFI_SSID="$1"
export WIFI_PASS="$2"
export SUPERVISOR_PUBKEY="$3"

# Source the ESP toolchain environment
source ~/export-esp.sh

# Navigate to the firmware directory and flash the UDP flavor
cd target-esp32s3
cargo espflash flash --release --no-default-features --features udp-transport --monitor
