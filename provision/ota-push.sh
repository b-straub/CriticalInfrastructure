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
rc=0
python3 - "$HOST" "$TPORT" "$IMG" <<'PY' || rc=$?
import socket, sys, struct, time
host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
data = open(path, 'rb').read()
# Connect with retries: the device has a single OTA socket and may be transiently unreachable
# (rebooting, a serial monitor attached, or the previous accept still timing out). Retry for up
# to ~45s rather than aborting the whole update on one closed window.
s = None
deadline = time.time() + 45
while True:
    try:
        s = socket.create_connection((host, port), timeout=5)
        break
    except (OSError, socket.timeout) as e:
        if time.time() >= deadline:
            sys.stderr.write(f"could not connect to {host}:{port} within 45s ({e})\n")
            sys.exit(2)
        time.sleep(2)
s.sendall(struct.pack('<I', len(data)))   # u32 LE length prefix
s.sendall(data)
# In-band verdict (ota.rs:295-313): on ACCEPT the device activates the slot and resets, so the
# socket just drops with no data; on REJECT it replies "ERR <reason>\n" then closes. Read the
# reply so a rejection is reported LOUDLY instead of being swallowed as a false success.
s.settimeout(30)
resp = b''
try:
    while len(resp) < 128 and b'\n' not in resp:
        chunk = s.recv(128)
        if not chunk:
            break
        resp += chunk
except Exception:
    pass
s.close()
if resp.startswith(b'ERR'):
    sys.stderr.write("REJECTED by device: " + resp.decode('ascii', 'replace').strip() + "\n")
    sys.exit(3)
print(f"sent {len(data)} bytes — ACCEPTED (device reset to boot the new slot; no ERR reply)")
PY
case "$rc" in
  0) ;;
  2) die "OTA push failed — could not reach $HOST:$TPORT (device rebooting, serial monitor attached, or wrong IP). Nothing was flashed.";;
  3) die "OTA push failed — the device REJECTED the image (see 'REJECTED by device: ...' above). Nothing was flashed; it stays on the current image.";;
  *) die "OTA push failed (exit $rc). Nothing was flashed.";;
esac
echo "watch the device serial: 'OTA: receiving N bytes' -> 'activated new slot; resetting' -> boots the other slot"
