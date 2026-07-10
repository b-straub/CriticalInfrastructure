#!/bin/bash
# provision/ota-attack-test.sh — fire crafted BAD OTA images at the live :8081 and read the
# verdict IN-BAND over TCP (no serial — a hardened device exposes no console). The hardened
# firmware replies "ERR <reason>" and stays up; an accepted push instead reboots (the socket
# just drops, no ERR). So each attack is PASS iff the device answers ERR.
#
# Ordering: the device checks version before signature, so signature-path attacks only reach the
# signature check when the pushed image's version is above the device's floor. Run with a FRESHLY
# built image (version = now) before deploying it (provision/3-build-sign.sh / ota-update.sh).
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

note "attack test -> $HOST:$TPORT  (base $(basename "$IMG"), verdict read in-band over TCP)"
python3 - "$HOST" "$TPORT" "$IMG" <<'PY'
import socket, struct, sys, time, os

HOST, TPORT, IMG = sys.argv[1], int(sys.argv[2]), sys.argv[3]
base = open(IMG, 'rb').read()
if len(base) % 4096 or len(base) <= 4096:
    sys.exit("base image is not a sector-aligned signed image")
sig = len(base) - 4096

def flip(b, i):
    b = bytearray(b); b[i] ^= 0x01; return bytes(b)
def set_version(b, v):
    b = bytearray(b); struct.pack_into('<I', b, 0x24, v); return bytes(b)
def break_magic(b):
    b = bytearray(b); b[sig] = 0x00; return bytes(b)

attacks = [
    ("rollback (version = 1)",   set_version(base, 1)),
    ("random garbage",           os.urandom(8192)),
    ("bad length (unaligned)",   os.urandom(5000)),
    ("tampered image body",      flip(base, 5000)),
    ("broken signature magic",   break_magic(base)),
    ("untrusted signing key",    flip(base, sig + 100)),
    ("tampered signature",       flip(base, sig + 900)),
]

def reachable():
    try:
        s = socket.create_connection((HOST, TPORT), timeout=1); s.close(); return True
    except Exception:
        return False

def wait_ready(maxwait=40):
    end = time.time() + maxwait
    while time.time() < end:
        if reachable(): return True
        time.sleep(0.5)
    return False

def push_read(data):
    # return the device's in-band reply: b"ERR <reason>\n" if refused, b"" if it dropped/rebooted
    try:
        s = socket.create_connection((HOST, TPORT), timeout=20)
        s.sendall(struct.pack('<I', len(data)))
        try: s.sendall(data)
        except Exception: pass          # device may drop mid-send on an early reject
        s.settimeout(20)
        resp = b""
        try:
            while len(resp) < 128 and b"\n" not in resp:
                chunk = s.recv(128)
                if not chunk: break
                resp += chunk
        except Exception:
            pass
        s.close()
        return resp
    except Exception:
        return b""

if not wait_ready(15):
    sys.exit("device not reachable on :%d — is it up and on Wi-Fi?" % TPORT)

fails = 0
for name, data in attacks:
    resp = push_read(data)
    if resp.startswith(b"ERR"):
        reason = resp[3:].strip().decode("utf-8", "replace")
        print(f"  [PASS] {name:26} -> refused in-band: {reason}")
    else:
        fails += 1
        print(f"  [FAIL] {name:26} -> no ERR reply (accepted/rebooted, or un-hardened firmware)")
    wait_ready()                        # let the device settle (covers a reboot if un-hardened)
    time.sleep(0.3)

print()
if fails == 0:
    print("ALL ATTACKS REFUSED IN-BAND — device answered ERR for each and never rebooted.")
    sys.exit(0)
print(f"{fails}/{len(attacks)} gave no in-band ERR. If un-hardened, deploy the verifying build")
print("(provision/ota-update.sh) and re-run — then every line should be PASS.")
sys.exit(1)
PY