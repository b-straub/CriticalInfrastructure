#!/bin/bash
# provision/ota-apply.sh — OTA step 4.2: prove the in-app apply path (self-copy).
#
# Builds the app with the `ota-selftest` feature, flashes it to ota_0, points otadata
# at ota_0, and monitors. On boot the app copies its running image into the inactive
# slot via OtaUpdater, activates it (state New), reboots into it, and marks it Valid —
# a complete OTA cycle with NO network. See docs/formal/OTA.md step 4.2.
#
#   provision/ota-apply.sh --port <dev> --ssid <S> --pass <P> --supervisor <K> [--keys token2]
#
#   --port <dev>        board serial port
#   --ssid/--pass       Wi-Fi creds baked into the app
#   --supervisor <k>    P-256 supervisor pubkey: 66-hex, PEM file, or inline PEM
#   --keys <a,b>        signing key(s), first = primary  (default: token2)
source "$(dirname "$0")/lib.sh"

PORT="" SSID="" PASS="" SUP="" KEYS="token2" FEATURES="udp-transport,efuse-hmac-identity,ota-selftest"
while [ $# -gt 0 ]; do case "$1" in
  --port) PORT="$2"; shift 2;; --ssid) SSID="$2"; shift 2;; --pass) PASS="$2"; shift 2;;
  --supervisor) SUP="$2"; shift 2;; --keys) KEYS="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
require_port "$PORT"; need esptool "brew install esptool"
[ -n "$SSID" ] && [ -n "$PASS" ] && [ -n "$SUP" ] || die "--ssid --pass --supervisor required"

note "1/4 build + sign the ota-selftest app (bootloader unchanged)"
"$REPO/provision/3-build-sign.sh" --ssid "$SSID" --pass "$PASS" --supervisor "$SUP" \
  --keys "$KEYS" --features "$FEATURES" --skip-bootloader --outdir "$SB/out"

note "2/4 flash the selftest app -> ota_0 (0x20000), leave halted"
esptool --chip esp32s3 --port "$PORT" --after no-reset write-flash 0x20000 "$SB/out/app-signed.bin"

note "3/4 point otadata at ota_0 (so the app boots ota_0 and triggers the self-copy)"
"$REPO/provision/ota-switch-slot.sh" --port "$PORT" --slot 0

note "4/4 monitor the autonomous cycle (read-only; ~35s)"
echo "    expect: boot ota_0 -> 'copying running image' -> reset -> boot ota_1 -> 'marked Valid'"
PYBIN="$HOME/.esptool-hsm/bin/python3"; [ -x "$PYBIN" ] || PYBIN=python3
"$PYBIN" - "$PORT" 35 <<'PY'
import serial, sys, time
port, dur = sys.argv[1], float(sys.argv[2])
end = time.time() + dur
def opn():
    while time.time() < end:
        try: return serial.Serial(port, 115200, timeout=0.3)
        except Exception: time.sleep(0.3)
    return None
s = opn()
while s and time.time() < end:                     # read-only: never resets, won't interrupt the copy
    try: data = s.read(4096)
    except Exception:
        try: s.close()
        except Exception: pass
        s = opn(); continue                        # reopen if USB re-enumerates on software reset
    for line in data.decode('utf-8', 'replace').splitlines():
        if any(k in line for k in ('OTA', 'Loaded app from partition', 'rst:0x', 'ota_0', 'ota_1')):
            print("   " + line.strip())
PY
echo
echo "done. ota_0 -> ota_1 autonomously = 4.2 apply path proven."
