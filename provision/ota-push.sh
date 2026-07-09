#!/bin/bash
# provision/ota-push.sh — OTA step 4.3: push a signed image to the device over TCP.
#
# Sends [u32 LE length][image] to the device's OTA port (:8081, `ota-net` firmware).
# The device streams it into the inactive slot, activates it, and reboots into it;
# Secure Boot verifies it on boot. The device IP is the "Got IP" line on its serial.
#
#   provision/ota-push.sh --host <device-ip> [--image secure-boot/out/app-signed.bin] [--port 8081]
#
#   --host <ip>     device IP on the Wi-Fi (required)
#   --image <file>  signed app image to send  (default: secure-boot/out/app-signed.bin)
#   --port <n>      device OTA TCP port        (default: 8081)
source "$(dirname "$0")/lib.sh"

HOST="" IMG="$SB/out/app-signed.bin" TPORT=8081
while [ $# -gt 0 ]; do case "$1" in
  --host) HOST="$2"; shift 2;; --image) IMG="$2"; shift 2;; --port) TPORT="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
[ -n "$HOST" ] || die "--host <device-ip> required (see the 'Got IP' line on serial)"
[ -f "$IMG" ] || die "image not found: $IMG (build it with provision/3 or provision/5)"

note "push $(basename "$IMG") ($(stat -f%z "$IMG") bytes) -> $HOST:$TPORT"
python3 - "$HOST" "$TPORT" "$IMG" <<'PY'
import socket, sys, struct
host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
data = open(path, 'rb').read()
s = socket.create_connection((host, port), timeout=25)
s.sendall(struct.pack('<I', len(data)))   # u32 LE length prefix
s.sendall(data)
try:                                       # device resets on success -> connection drops
    s.settimeout(25); s.recv(1)
except Exception:
    pass
s.close()
print(f"sent {len(data)} bytes")
PY
echo "watch the device serial: 'OTA: receiving N bytes' -> 'activated new slot; resetting' -> boots the other slot"
