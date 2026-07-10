#!/bin/bash
# provision/ota-attack-test.sh — fire crafted BAD OTA images at the live :8081, one at a time,
# so you can confirm on the SERIAL MONITOR that each is refused. Non-destructive: a rejected
# push leaves the device untouched; an accepted one reboots and the bootloader rolls it back.
#
# The device's serial is the ground truth (its network stack answers no ping, and the single
# OTA socket can't be probed mid-transfer — so watching the log is the reliable check):
#   HARDENED firmware -> each attack logs:  OTA: transfer aborted: <reason>     (no reboot)
#   un-hardened       -> each attack logs:  received ... resetting  + 'Init Network'  (a reboot)
#
# Ordering: the device checks the app-descriptor version BEFORE the signature, so signature-path
# attacks only reach the signature check when the pushed image's version is above the device's
# floor. Run with a FRESHLY built image (version = now) before deploying it:
#   provision/3-build-sign.sh ...      # out/app-signed.bin, version = now
#   provision/ota-attack-test.sh       # <-- fire the attacks, watch serial
#   provision/ota-update.sh            # then deploy the good one
#
#   --host <ip>     device IP        (default: Keychain, provision/store-creds.sh)
#   --image <file>  genuine signed base to craft from (default: secure-boot/out/app-signed.bin)
#   --port <n>      device OTA port  (default: 8081)
source "$(dirname "$0")/lib.sh"

HOST="" IMG="$SB/out/app-signed.bin" TPORT=8081
while [ $# -gt 0 ]; do case "$1" in
  --host) HOST="$2"; shift 2;; --image) IMG="$2"; shift 2;; --port) TPORT="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
load_creds
[ -n "$HOST" ] || die "no device IP — pass --host <ip> or store it (provision/store-creds.sh --host <ip>)"
[ -f "$IMG" ] || die "genuine base image not found: $IMG (build it: provision/3-build-sign.sh)"
need python3 "install Python 3"

note "attack test -> $HOST:$TPORT  (base: $(basename "$IMG"), $(stat -f%z "$IMG") bytes)"
echo "    >>> WATCH YOUR SERIAL MONITOR. Each attack below must log 'OTA: transfer aborted: <reason>'"
echo "    >>> and the board must NOT reboot ('Init Network'). A reboot = un-hardened firmware."
echo
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

# name, crafted bad bytes, the exact reason the hardened firmware logs
attacks = [
    ("rollback (version = 1)",   set_version(base, 1),   "version rollback rejected"),
    ("random garbage",           os.urandom(8192),       "not an app image"),
    ("bad length (unaligned)",   os.urandom(5000),       "bad image length"),
    ("tampered image body",      flip(base, 5000),       "image digest mismatch"),
    ("broken signature magic",   break_magic(base),      "sig block magic"),
    ("untrusted signing key",    flip(base, sig + 100),  "untrusted signing key"),
    ("tampered signature",       flip(base, sig + 900),  "PSS verify failed"),
]

def reachable():
    try:
        s = socket.create_connection((HOST, TPORT), timeout=1); s.close(); return True
    except Exception:
        return False

def wait_ready(maxwait=30):
    # wait until :8081 accepts again (covers a reboot+rejoin if the board was un-hardened)
    end = time.time() + maxwait
    while time.time() < end:
        if reachable():
            return True
        time.sleep(0.5)
    return False

def push(data):
    try:
        s = socket.create_connection((HOST, TPORT), timeout=20)
        s.sendall(struct.pack('<I', len(data)))
        try: s.sendall(data)
        except Exception: pass        # device may abort mid-send on an early reject
        try: s.settimeout(15); s.recv(1)
        except Exception: pass
        s.close()
    except Exception as e:
        print(f"      (push error: {e})")

if not wait_ready(10):
    sys.exit("device not reachable on :%d — is it up and on Wi-Fi?" % TPORT)

for i, (name, data, reason) in enumerate(attacks, 1):
    print(f"[{i}/{len(attacks)}] {name}")
    print(f"        want on serial: 'OTA: transfer aborted: {reason}'   (and no reboot)")
    push(data)
    time.sleep(2)
    if not wait_ready():
        print("        !! device did not come back on :8081 within 30s — check it")
    print()

print("Done. Verdict is on your serial log:")
print("  PASS  = every attack logged 'transfer aborted: ...', no 'Init Network' between them.")
print("  FAIL  = you saw 'resetting' / 'Init Network' -> the board is running un-hardened firmware")
print("          (deploy the verifying build first: provision/ota-update.sh).")
PY