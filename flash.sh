#!/bin/bash
# Check if all 3 parameters are provided
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
  echo "Error: Missing arguments."
  echo "Usage: ./flash.sh <WIFI_SSID> <WIFI_PASSWORD> <SUPERVISOR_PUBKEY_HEX>"
  exit 1
fi

# Export credentials so Rust's option_env!() can bake them into the firmware
export WIFI_SSID="$1"
export WIFI_PASS="$2"
export SUPERVISOR_PUBKEY="$3"

# Source the ESP toolchain environment
source ~/export-esp.sh

# Navigate to the firmware directory and flash
cd target-esp32s3
cargo espflash flash --release --monitor
