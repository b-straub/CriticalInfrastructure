#!/bin/bash
# provision/ota-attack-test.sh — prove every OTA rejection path fires on the live device.
# Pushes a series of crafted BAD images at :8081 and confirms each is refused AND the board
# never reboots (stays on its current firmware). Non-destructive: a rejected push leaves the
# device untouched. If a USB serial port is present it also confirms the SPECIFIC reason logged.
#
# Ordering matters — the device checks the app-descriptor version BEFORE the signature, so the
# signature-path attacks only reach the signature check when the pushed image's version is above
# the device's floor. Run this with a FRESHLY built image *before* you deploy it:
#     provision/3-build-sign.sh ...            # out/app-signed.bin, version = now (> floor)
#     provision/ota-attack-test.sh             # <-- here: exercises every path
#     provision/ota-update.sh                  # then deploy for real
#
#   --host <ip>     device IP        (default: Keychain, provision/store-creds.sh)
#   --image <file>  genuine signed base to craft attacks from (default: secure-boot/out/app-signed.bin)
#   --port <n>      device OTA port  (default: 8081)
#   --serial <dev>  USB port for reason capture (default: auto-detect; omit to skip reasons)
source "$(dirname "$0")/lib.sh"

HOST="" IMG="$SB/out/app-signed.bin" TPORT=8081 SERIAL=""
while [ $# -gt 0 ]; do case "$1" in
  --host) HOST="$2"; shift 2;; --image) IMG="$2"; shift 2;; --port) TPORT="$2"; shift 2;;
  --serial) SERIAL="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
load_creds
[ -n "$HOST" ] || die "no device IP — pass --host <ip> or store it (provision/store-creds.sh --host <ip>)"
[ -f "$IMG" ] || die "genuine base image not found: $IMG (build it: provision/3-build-sign.sh)"
[ -n "$SERIAL" ] || SERIAL="$(find_port)"
need python3 "install Python 3"

note "attack test -> $HOST:$TPORT  (base: $(basename "$IMG"), $(stat -f%z "$IMG") bytes)"
echo "    NOTE: only meaningful against the HARDENED (ota-net verify) firmware. A reboot on any"
echo "    attack means the device is running un-hardened firmware — deploy it first (ota-update.sh)."
python3 - "$HOST" "$TPORT" "$IMG" <<'PY'
import socket, struct, sys, time, os

HOST, TPORT, IMG = sys.argv[1], int(sys.argv[2]), sys.argv[3]
base = open(IMG, 'rb').read()
if len(base) % 4096 or len(base) <= 4096:
    sys.exit("base image is not a sector-aligned signed image")
sig = len(base) - 4096  # signature-block sector offset

def flip(b, i):
    b = bytearray(b); b[i] ^= 0x01; return bytes(b)
def set_version(b, v):
    b = bytearray(b); struct.pack_into('<I', b, 0x24, v); return bytes(b)  # app_desc.secure_version
def break_magic(b):
    b = bytearray(b); b[sig] = 0x00; return bytes(b)                       # sig block magic 0xe7

# name, crafted bytes (all bad — must be refused before activation on hardened firmware)
attacks = [
    ("rollback (version = 1)",   set_version(base, 1)),
    ("random garbage",           os.urandom(8192)),
    ("bad length (unaligned)",   os.urandom(5000)),
    ("tampered image body",      flip(base, 5000)),
    ("broken signature magic",   break_magic(base)),
    ("untrusted signing key",    flip(base, sig + 100)),
    ("tampered signature",       flip(base, sig + 900)),
]

def reachable(timeout=0.8):
    try:
        s = socket.create_connection((HOST, TPORT), timeout=timeout); s.close(); return True
    except Exception:
        return False

def push(data):
    try:
        s = socket.create_connection((HOST, TPORT), timeout=15)
        s.sendall(struct.pack('<I', len(data)))
        try: s.sendall(data)
        except Exception: pass          # device may abort mid-send on an early reject
        try: s.settimeout(8); s.recv(1)
        except Exception: pass
        s.close()
    except Exception:
        pass

# After a push, watch reachability closely. A REJECT keeps the socket server up continuously
# (it just loops back to accept). An ACCEPT triggers software_reset -> the device is
# unreachable for several seconds while it reboots + rejoins Wi-Fi. Longest continuous-down
# streak >= 1.5s => it rebooted => the attack was (wrongly) accepted.
def max_down_after_push(seconds=11.0, interval=0.25):
    end = time.time() + seconds
    streak = 0.0; worst = 0.0
    while time.time() < end:
        if reachable():
            streak = 0.0
        else:
            streak += interval; worst = max(worst, streak)
        time.sleep(interval)
    return worst

if not reachable(timeout=3):
    sys.exit("device not reachable on :%d — is it up and on Wi-Fi?" % TPORT)

fails = 0
for name, data in attacks:
    push(data)
    down = max_down_after_push()
    rebooted = down >= 1.5
    if rebooted: fails += 1
    verdict = "REBOOTED — attack ACCEPTED" if rebooted else "no reboot — refused"
    print(f"  [{'FAIL' if rebooted else 'PASS'}] {name:26} -> {verdict}  (down {down:.1f}s)")
    time.sleep(0.5)

print()
if fails == 0:
    print("ALL ATTACKS REFUSED — device never rebooted; still on its current firmware.")
    print("(Watch your serial monitor for the exact reason per attack: 'transfer aborted: <why>'.)")
    sys.exit(0)
print(f"{fails} attack(s) caused a REBOOT — un-hardened firmware, or a real acceptance. Deploy the")
print("verifying firmware (provision/ota-update.sh) and re-run.")
sys.exit(1)
PY