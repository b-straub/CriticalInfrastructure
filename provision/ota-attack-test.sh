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

note "attack test -> $HOST:$TPORT  (base: $(basename "$IMG"), $(stat -f%z "$IMG") bytes)${SERIAL:+, serial $SERIAL}"
python3 - "$HOST" "$TPORT" "$IMG" "$SERIAL" <<'PY'
import socket, struct, sys, time, os

HOST, TPORT, IMG, SERIAL = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
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

# name, crafted bytes, expected reason substring (device logs "transfer aborted: <reason>")
attacks = [
    ("rollback (version = 1)",      set_version(base, 1),     "version rollback rejected"),
    ("random garbage",              os.urandom(8192),         "not an app image"),
    ("bad length (unaligned)",      os.urandom(5000),         "bad image length"),
    ("tampered image body",         flip(base, 5000),         "image digest mismatch"),
    ("broken signature magic",      break_magic(base),        "sig block magic"),
    ("untrusted signing key",       flip(base, sig + 100),    "untrusted signing key"),
    ("tampered signature",          flip(base, sig + 900),    "PSS verify failed"),
]

# optional no-reset serial capture (USB-serial-JTAG resets on DTR/RTS; hold them low)
buf = []
ser = None
if SERIAL:
    try:
        import serial, threading
        ser = serial.Serial()
        ser.port = SERIAL; ser.baudrate = 115200; ser.dtr = False; ser.rts = False
        ser.timeout = 0.2; ser.open()
        stop = threading.Event()
        def _rd():
            while not stop.is_set():
                try: buf.append(ser.read(512).decode('utf-8', 'replace'))
                except Exception: pass
        threading.Thread(target=_rd, daemon=True).start()
        time.sleep(0.4)
    except Exception as e:
        print(f"  (serial capture off: {e})"); ser = None

def board_up(timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection((HOST, TPORT), timeout=1); s.close(); return True
        except Exception:
            time.sleep(0.3)
    return False

def push(data):
    try:
        s = socket.create_connection((HOST, TPORT), timeout=15)
        s.sendall(struct.pack('<I', len(data)))
        try: s.sendall(data)
        except Exception: pass         # device may abort mid-send on an early reject
        try: s.settimeout(8); s.recv(1)
        except Exception: pass
        s.close()
    except Exception as e:
        print(f"    push error: {e}")

if not board_up():
    sys.exit("device not reachable on :%d — is it up and on Wi-Fi?" % TPORT)

fails = 0
for name, data, expect in attacks:
    mark = len("".join(buf))
    push(data)
    time.sleep(1.3)
    up = board_up()                                   # rejected -> still up; accepted -> rebooting
    reason = None
    if ser is not None:
        tail = "".join(buf)[mark:]
        reason = expect in tail
    ok = up and (reason is not False)                 # reason None (no serial) doesn't fail it
    if not ok: fails += 1
    detail = "still up" if up else "REBOOTED (accepted!)"
    if ser is not None:
        detail += f", reason logged: {'yes' if reason else 'NO'}"
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:26} -> {detail}" + (f"  (want: {expect})" if not ok else ""))

if ser is not None:
    try: ser.close()
    except Exception: pass

print()
if fails == 0:
    print("ALL ATTACKS REJECTED — device never rebooted; it is still on its current firmware.")
    sys.exit(0)
print(f"{fails} attack(s) not properly rejected — see FAIL rows above.")
sys.exit(1)
PY