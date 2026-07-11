#!/bin/bash
# provision/ota-backup-signer-test.sh — prove the BACKUP Secure Boot signer (backup signer, RSA-3072 =>
# SECURE_BOOT_DIGEST1) is a live boot authority on the device, end-to-end.
#
# Builds a normal firmware image (both key digests baked, so the device stays able to receive
# future updates from either key), signs it with the **backup key ONLY**, and pushes it over OTA.
# If the device boots it (LCD build tag changes), then only DIGEST1 could have verified it —
# proving backup token works as a boot authority. Safe on a sealed board: if backup token were not trusted,
# Secure Boot fails and the bootloader rolls back to the current image (no brick).
#
# PREREQUISITE — the *currently running* firmware must TRUST backup token at its OTA receive-check,
# i.e. it must have been built with both digests baked. If it wasn't, this script's push is
# rejected in-band with "untrusted signing key" and it tells you to run, once:
#     provision/ota-update.sh --keys mainToken,backupToken        # deploy a both-keys-trusting firmware
# then re-run this script.
#
#   provision/ota-backup-signer-test.sh                 # host from Keychain
#   provision/ota-backup-signer-test.sh --host <ip>
#
#   --host <ip>    device IP           (default: Keychain, provision/store-creds.sh)
#   --port <n>     device OTA TCP port (default: 8081)
#   --keys <a,b>   digests to BAKE (device stays trusting these); signing is always backup-only
#                  (default: mainToken,backupToken)
#   --driver <d>   OpenSC driver for the backup token (default: the recorded one, else PIV-II)
#   --keep         keep the temp build dir (for inspection)
source "$(dirname "$0")/lib.sh"

HOST="" TPORT=8081 BAKE_KEYS="mainToken,backupToken" DRIVER="" KEEP=0
while [ $# -gt 0 ]; do case "$1" in
  --host) HOST="$2"; shift 2;; --port) TPORT="$2"; shift 2;;
  --keys) BAKE_KEYS="$2"; shift 2;; --driver) DRIVER="$2"; shift 2;; --keep) KEEP=1; shift;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
load_creds
[ -n "$HOST" ] || die "no device IP — pass --host <ip> or store it (provision/store-creds.sh --host <ip>)"

# backup token must be enrolled (provision/1-enroll-key.sh --name backupToken --driver PIV-II).
BACKUP_INI="$(key_ini backupToken)"; BACKUP_PUB="$(key_pub backupToken)"
[ -f "$BACKUP_INI" ] && [ -f "$BACKUP_PUB" ] || die "backupToken not enrolled — run: provision/1-enroll-key.sh --name backupToken --driver PIV-II"
# The backup token needs OpenSC's PIV-II driver. Prefer an explicit --driver, then the recorded
# one, then default to PIV-II (matches sign-secure-boot.sh) — never run with an empty driver,
# which fails as an opaque "no slot" HSM error.
BACKUP_DRV="${DRIVER:-$(key_driver backupToken)}"; BACKUP_DRV="${BACKUP_DRV:-PIV-II}"
ES="$(espsecure_bin)"

OUT="$(mktemp -d)"; [ "$KEEP" = 1 ] || trap 'rm -rf "$OUT"' EXIT

# 1. Build the app (both digests baked so the device keeps trusting both keys), no signing/PIN.
note "1/4 build the app, baking digests: $BAKE_KEYS (unsigned; --build-only, no PIN)"
"$REPO/provision/3-build-sign.sh" --keys "$BAKE_KEYS" --features "udp-transport,efuse-hmac-identity,ota-net" \
  --skip-bootloader --build-only --outdir "$OUT"
[ -f "$OUT/app.bin" ] || die "build produced no $OUT/app.bin"

# 2. Sign with the THETIS key ONLY (its OpenSC driver applied) — this is the whole point.
note "2/4 sign with backup token ONLY${BACKUP_DRV:+ (OPENSC_DRIVER=$BACKUP_DRV)} — enter the backup token PIN"
OPENSC_DRIVER="$BACKUP_DRV" "$ES" sign-data --version 2 --hsm --hsm-config "$BACKUP_INI" \
  --output "$OUT/app-signed.bin" "$OUT/app.bin"

# 3. Verify the backup signature against its public key (block 0 must verify).
note "3/4 verify the backup signature"
"$ES" verify-signature --version 2 --keyfile "$BACKUP_PUB" "$OUT/app-signed.bin" 2>&1 \
  | grep -q 'verification successful' || die "backup signature did not verify — aborting (nothing pushed)"
echo "    backup signature verified (block 0)"

# 4. Push over OTA and determine the verdict from TWO signals: the in-band ERR reason (if the
#    device refuses) AND whether the device rebooted afterwards (an ACCEPT triggers a reset →
#    :8081 goes unreachable for several seconds; a REJECT keeps it listening continuously).
note "4/4 push the backup-only image -> $HOST:$TPORT"
python3 - "$HOST" "$TPORT" "$OUT/app-signed.bin" <<'PY'
import socket, struct, sys, threading, time
host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
data = open(path, 'rb').read()
print(f"    sending {len(data)} bytes (backup-signed)")
try:
    s = socket.create_connection((host, port), timeout=20)
except Exception as e:
    sys.exit(f"cannot reach {host}:{port} — is the device up? ({e})")

def send():
    try:
        s.sendall(struct.pack('<I', len(data))); s.sendall(data)
    except Exception:
        pass                       # device may drop mid-send / on close after an ERR
threading.Thread(target=send, daemon=True).start()

# The device rejects a full-size image only AFTER streaming it all (signature check is post-
# receive), so keep reading well past the transfer for a late "ERR <reason>\n".
s.settimeout(30)
resp = b""
try:
    while len(resp) < 128 and b"\n" not in resp:
        chunk = s.recv(128)
        if not chunk:
            break
        resp += chunk
except Exception:
    pass
try: s.close()
except Exception: pass
reason = resp[3:].strip().decode('utf-8', 'replace') if resp.startswith(b"ERR") else ""

# Confirm reboot vs still-up: after the outcome is decided, an ACCEPT reboots (:8081 unreachable
# for several seconds while it resets + rejoins Wi-Fi); a REJECT keeps it listening (reachable
# immediately). Measure the down-streak by REAL elapsed time — a failed connect can itself take
# up to the timeout, so a fixed per-iteration increment badly undercounts it.
def reachable():
    try:
        c = socket.create_connection((host, port), timeout=0.8); c.close(); return True
    except Exception:
        return False
worst_down, down_since = 0.0, None
end = time.time() + 18
while time.time() < end:
    if reachable():
        down_since = None
    else:
        now = time.time()
        if down_since is None:
            down_since = now
        worst_down = max(worst_down, now - down_since)
    time.sleep(0.3)
rebooted = worst_down >= 2.5

print()
if not rebooted:
    # Stayed up -> refused. Show the reason if we caught it; otherwise infer the usual one.
    if "untrusted signing key" in reason or not reason:
        print("REJECTED — the device stayed up (no reboot)%s." %
              (": untrusted signing key" if reason else "; reason not captured"))
        print("The RUNNING firmware does not trust backup token at its receive-check yet (it bakes only")
        print("the main token's digest). Deploy a both-keys-trusting firmware once, then re-run this test:")
        print("    provision/ota-update.sh --keys mainToken,backupToken")
        print("    provision/ota-backup-signer-test.sh")
        sys.exit(2)
    print(f"REJECTED (in-band): {reason}")
    sys.exit(1)

print("ACCEPTED + REBOOTED — the device took the backup-only-signed image and reset into it.")
print("Check the board: if the LCD build tag CHANGED (it booted), then only DIGEST1 (backup token)")
print("could have verified it — the backup signer is a live boot authority. If the tag is")
print("unchanged, Secure Boot rejected it at boot and rolled back (backup token not a valid authority).")
PY
