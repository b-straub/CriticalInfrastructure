#!/bin/bash
# provision/ota-thetis-test.sh — prove the BACKUP Secure Boot signer (Thetis, RSA-3072 =>
# SECURE_BOOT_DIGEST1) is a live boot authority on the device, end-to-end.
#
# Builds a normal firmware image (both key digests baked, so the device stays able to receive
# future updates from either key), signs it with the **Thetis key ONLY**, and pushes it over OTA.
# If the device boots it (LCD build tag changes), then only DIGEST1 could have verified it —
# proving Thetis works as a boot authority. Safe on a sealed board: if Thetis were not trusted,
# Secure Boot fails and the bootloader rolls back to the current image (no brick).
#
# PREREQUISITE — the *currently running* firmware must TRUST Thetis at its OTA receive-check,
# i.e. it must have been built with both digests baked. If it wasn't, this script's push is
# rejected in-band with "untrusted signing key" and it tells you to run, once:
#     provision/ota-update.sh --keys token2,thetis        # deploy a both-keys-trusting firmware
# then re-run this script.
#
#   provision/ota-thetis-test.sh                 # host from Keychain
#   provision/ota-thetis-test.sh --host <ip>
#
#   --host <ip>   device IP           (default: Keychain, provision/store-creds.sh)
#   --port <n>    device OTA TCP port (default: 8081)
#   --keys <a,b>  digests to BAKE (device stays trusting these); signing is always Thetis-only
#                 (default: token2,thetis)
#   --keep        keep the temp build dir (for inspection)
source "$(dirname "$0")/lib.sh"

HOST="" TPORT=8081 BAKE_KEYS="token2,thetis" KEEP=0
while [ $# -gt 0 ]; do case "$1" in
  --host) HOST="$2"; shift 2;; --port) TPORT="$2"; shift 2;;
  --keys) BAKE_KEYS="$2"; shift 2;; --keep) KEEP=1; shift;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
load_creds
[ -n "$HOST" ] || die "no device IP — pass --host <ip> or store it (provision/store-creds.sh --host <ip>)"

# Thetis must be enrolled (provision/1-enroll-key.sh --name thetis --driver PIV-II).
THETIS_INI="$(key_ini thetis)"; THETIS_PUB="$(key_pub thetis)"; THETIS_DRV="$(key_driver thetis)"
[ -f "$THETIS_INI" ] && [ -f "$THETIS_PUB" ] || die "thetis not enrolled — run: provision/1-enroll-key.sh --name thetis --driver PIV-II"
ES="$(espsecure_bin)"

OUT="$(mktemp -d)"; [ "$KEEP" = 1 ] || trap 'rm -rf "$OUT"' EXIT

# 1. Build the app (both digests baked so the device keeps trusting both keys), no signing/PIN.
note "1/4 build the app, baking digests: $BAKE_KEYS (unsigned; --build-only, no PIN)"
"$REPO/provision/3-build-sign.sh" --keys "$BAKE_KEYS" --features "udp-transport,efuse-hmac-identity,ota-net" \
  --skip-bootloader --build-only --outdir "$OUT"
[ -f "$OUT/app.bin" ] || die "build produced no $OUT/app.bin"

# 2. Sign with the THETIS key ONLY (its OpenSC driver applied) — this is the whole point.
note "2/4 sign with Thetis ONLY${THETIS_DRV:+ (OPENSC_DRIVER=$THETIS_DRV)} — enter the Thetis PIN"
OPENSC_DRIVER="$THETIS_DRV" "$ES" sign-data --version 2 --hsm --hsm-config "$THETIS_INI" \
  --output "$OUT/app-signed.bin" "$OUT/app.bin"

# 3. Verify the Thetis signature against its public key (block 0 must verify).
note "3/4 verify the Thetis signature"
"$ES" verify-signature --version 2 --keyfile "$THETIS_PUB" "$OUT/app-signed.bin" 2>&1 \
  | grep -q 'verification successful' || die "Thetis signature did not verify — aborting (nothing pushed)"
echo "    Thetis signature verified (block 0)"

# 4. Push over OTA and read the device's in-band verdict.
note "4/4 push the Thetis-only image -> $HOST:$TPORT"
python3 - "$HOST" "$TPORT" "$OUT/app-signed.bin" <<'PY'
import socket, struct, sys, threading
host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
data = open(path, 'rb').read()
print(f"    sending {len(data)} bytes (Thetis-signed)")
try:
    s = socket.create_connection((host, port), timeout=20)
except Exception as e:
    sys.exit(f"cannot reach {host}:{port} — is the device up? ({e})")
def send():
    try:
        s.sendall(struct.pack('<I', len(data))); s.sendall(data)
    except Exception:
        pass                       # device may drop mid-send on an early reject
threading.Thread(target=send, daemon=True).start()
s.settimeout(25)
resp = b""
try:
    while len(resp) < 128 and b"\n" not in resp:
        chunk = s.recv(128)
        if not chunk: break
        resp += chunk
except Exception:
    pass
s.close()

reason = resp[3:].strip().decode('utf-8', 'replace') if resp.startswith(b"ERR") else ""
print()
if "untrusted signing key" in reason:
    print("REJECTED (in-band): untrusted signing key.")
    print("The RUNNING firmware doesn't trust Thetis at receive yet. Deploy a both-keys-trusting")
    print("firmware first, then re-run:")
    print("    provision/ota-update.sh --keys token2,thetis")
    sys.exit(2)
if reason:
    print(f"REJECTED (in-band): {reason}")
    sys.exit(1)
# No ERR -> the device accepted it and is rebooting into the Thetis-signed slot.
print("ACCEPTED — the device took the Thetis-only-signed image and is rebooting into it.")
print("Watch the board: if it BOOTS (LCD build tag changes / serial 'secure boot verification")
print("succeeded'), then only DIGEST1 (Thetis) could have verified it — the backup signer is a")
print("live boot authority. If it rolls back to the current image, Thetis is not a valid authority.")
PY
