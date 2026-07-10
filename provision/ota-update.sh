#!/bin/bash
# provision/ota-update.sh — ONE PASS: build + sign the firmware and deliver it to the
# running device over the network. No intermediate hand-off, no hidden transfer — this
# calls the same repo scripts you'd run by hand, in order, in front of you.
#
#   provision/ota-update.sh                 # Wi-Fi/supervisor creds + device IP from Keychain
#   provision/ota-update.sh --host 192.168.178.133
#   provision/ota-update.sh --features "udp-transport,efuse-hmac-identity,ota-net"
#
#   --host <ip>       device IP on the Wi-Fi   (default: Keychain, provision/store-creds.sh)
#   --features <list> cargo features to build  (default: udp-transport,efuse-hmac-identity,ota-net)
#   --keys <a,b>      signing key(s), first = primary                 (default: token2)
#   --port <n>        device OTA TCP port                             (default: 8081)
#
# The build keeps the current secure-boot layout (bootloader + partition table stay put) —
# only the app is rebuilt, signed (Token2 PIN, once), and streamed into the inactive slot.
# On an encrypted device the firmware encrypt-writes it; Secure Boot verifies it on boot.
source "$(dirname "$0")/lib.sh"

HOST="" FEATURES="udp-transport,efuse-hmac-identity,ota-net" KEYS="token2" TPORT=8081
while [ $# -gt 0 ]; do case "$1" in
  --host) HOST="$2"; shift 2;; --features) FEATURES="$2"; shift 2;;
  --keys) KEYS="$2"; shift 2;; --port) TPORT="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
load_creds  # SSID/PASS/SUP + HOST from the Keychain if not passed (provision/store-creds.sh)
[ -n "$HOST" ] || die "no device IP — pass --host <ip> or store it: provision/store-creds.sh --host <ip>"
case "$FEATURES" in *ota-net*) ;; *) die "--features must include ota-net (the OTA server) for a network update";; esac

note "1/2 build + sign the app (Token2 PIN — keep bootloader/table, --skip-bootloader)"
"$REPO/provision/3-build-sign.sh" --features "$FEATURES" --keys "$KEYS" --skip-bootloader

note "2/2 deliver over the network -> $HOST:$TPORT"
"$REPO/provision/ota-push.sh" --host "$HOST" --port "$TPORT" --image "$SB/out/app-signed.bin"

echo
echo "Done. The device installs it into the inactive slot and reboots into it."
echo "Confirm on the LCD: line 2 build tag (HHMM) changes to this build's time;"
echo "or on serial: 'Firmware <hash> built ...' shows the new hash."
