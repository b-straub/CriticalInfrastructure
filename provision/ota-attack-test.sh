#!/bin/bash
# provision/ota-attack-test.sh — fire crafted BAD OTA images at the live :8081 and read the
# verdict IN-BAND over TCP (no serial — a hardened device exposes no console). The hardened
# firmware replies "ERR <reason>" and stays up; an accepted push instead reboots (socket drops,
# no ERR). Each attack asserts BOTH that it was refused AND that it failed at its INTENDED check
# (the exact reason), so the on-device signature path is proven to fire — not just short-circuited
# by an earlier gate.
#
# The device checks the app-descriptor version BEFORE the signature. So signature-path attacks
# (tampered body/sig/key) only REACH the signature check when the pushed image's version is above
# the device's floor. Use --build-base to sign a FRESH higher-version base first (one Token2 PIN):
# without it, those attacks are caught by the version gate and reported as "gate" (still refused,
# but the intended check wasn't exercised).
#
#   --build-base        build+sign a fresh higher-version base via provision/3 (Token2 PIN once),
#                       then craft the attacks from it — exercises the signature path on-device
#   --secure-version N  base version to stamp (implies --build-base; default: epoch, > any floor)
#   --host <ip>         device IP        (default: Keychain, provision/store-creds.sh)
#   --image <file>      base to craft from when NOT building (default: secure-boot/out/app-signed.bin)
#   --features <list>   base build features (default: udp-transport,efuse-hmac-identity,ota-net)
#   --keys <a,b>        signing key(s)   (default: token2)
#   --port <n>          device OTA port  (default: 8081)
source "$(dirname "$0")/lib.sh"

HOST="" IMG="" TPORT=8081 BUILD_BASE=0 SECVER="" FEATURES="udp-transport,efuse-hmac-identity,ota-net" KEYS="token2"
while [ $# -gt 0 ]; do case "$1" in
  --host) HOST="$2"; shift 2;; --image) IMG="$2"; shift 2;; --port) TPORT="$2"; shift 2;;
  --build-base) BUILD_BASE=1; shift;;
  --secure-version) SECVER="$2"; BUILD_BASE=1; shift 2;;
  --features) FEATURES="$2"; shift 2;; --keys) KEYS="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
load_creds
[ -n "$HOST" ] || die "no device IP — pass --host <ip> or store it (provision/store-creds.sh --host <ip>)"
need python3 "install Python 3"

if [ "$BUILD_BASE" = 1 ]; then
  BASEDIR="$(mktemp -d)"; trap 'rm -rf "$BASEDIR"' EXIT
  note "building a fresh higher-version signed base (enter the Token2 PIN once) — features: $FEATURES"
  "$REPO/provision/3-build-sign.sh" --features "$FEATURES" --keys "$KEYS" --skip-bootloader \
    ${SECVER:+--secure-version "$SECVER"} --outdir "$BASEDIR"
  IMG="$BASEDIR/app-signed.bin"
else
  IMG="${IMG:-$SB/out/app-signed.bin}"
fi
[ -f "$IMG" ] || die "base image not found: $IMG (build it: provision/3-build-sign.sh, or pass --build-base)"

note "attack test -> $HOST:$TPORT  (base $(basename "$IMG"), verdict read in-band over TCP)"
[ "$BUILD_BASE" = 1 ] || echo "    (no --build-base: signature-path attacks may be caught by the version gate — reported 'gate')"
python3 - "$HOST" "$TPORT" "$IMG" <<'PY'
import socket, struct, sys, time, os, threading

HOST, TPORT, IMG = sys.argv[1], int(sys.argv[2]), sys.argv[3]
base = open(IMG, 'rb').read()
if len(base) % 4096 or len(base) <= 4096:
    sys.exit("base image is not a sector-aligned signed image")
sig = len(base) - 4096  # signature-block sector offset

def flip(b, i):
    b = bytearray(b); b[i] ^= 0x01; return bytes(b)
def set_version(b, v):
    b = bytearray(b); struct.pack_into('<I', b, 0x24, v); return bytes(b)
def break_magic(b):
    b = bytearray(b); b[sig] = 0x00; return bytes(b)

# name, crafted bad bytes, the EXACT reason the firmware must log for its intended check
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

def wait_ready(maxwait=40):
    end = time.time() + maxwait
    while time.time() < end:
        if reachable(): return True
        time.sleep(0.5)
    return False

def push_read(data):
    # device's in-band reply: b"ERR <reason>\n" if refused, b"" if it dropped/rebooted.
    # Read CONCURRENTLY with sending: the device rejects early (often at the first sector) and
    # sends ERR while we're still pushing the rest of the image — a blocking send-then-recv would
    # race and miss it. So a background thread sends; the main thread reads the reply.
    try:
        s = socket.create_connection((HOST, TPORT), timeout=20)
    except Exception:
        return b""
    def sender():
        try:
            s.sendall(struct.pack('<I', len(data)))
            s.sendall(data)
        except Exception:
            pass                        # device closes its read half on an early reject
    threading.Thread(target=sender, daemon=True).start()
    s.settimeout(25)
    resp = b""
    try:
        while len(resp) < 128 and b"\n" not in resp:
            chunk = s.recv(128)
            if not chunk: break
            resp += chunk
    except Exception:
        pass
    try: s.close()
    except Exception: pass
    return resp

if not wait_ready(15):
    sys.exit("device not reachable on :%d — is it up and on Wi-Fi?" % TPORT)

accepted = 0   # FAIL: got in, rebooted
offgate = 0    # refused, but by the version gate instead of the intended check
exact = 0      # refused at exactly the intended check
for name, data, expect in attacks:
    resp = push_read(data)
    if not resp.startswith(b"ERR"):
        accepted += 1
        print(f"  [FAIL] {name:26} -> NO ERR (accepted -> rebooted, or un-hardened firmware)")
    else:
        reason = resp[3:].strip().decode("utf-8", "replace")
        if expect in reason:
            exact += 1
            print(f"  [PASS] {name:26} -> {reason}")
        elif "version rollback rejected" in reason:
            offgate += 1
            print(f"  [gate] {name:26} -> caught by version gate (want '{expect}'); use --build-base")
        else:
            offgate += 1
            print(f"  [?]    {name:26} -> refused: {reason}  (expected '{expect}')")
    wait_ready()
    time.sleep(0.3)

print()
total = len(attacks)
print(f"refused: {exact + offgate}/{total}   at intended check: {exact}/{total}   accepted(FAIL): {accepted}")
if accepted:
    print("A push was ACCEPTED (device rebooted) — un-hardened firmware. Deploy the verifying")
    print("build (provision/ota-update.sh) and re-run.")
    sys.exit(1)
if offgate:
    print("All refused, but some were short-circuited by the version gate. Re-run with --build-base")
    print("to sign a higher-version base so the signature-path attacks reach the RSA check.")
    sys.exit(2)
print("ALL ATTACKS REFUSED AT THEIR INTENDED CHECK — signature path exercised on-device, no reboots.")
sys.exit(0)
PY