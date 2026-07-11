#!/bin/bash
# provision/3-build-sign.sh — stage 3: build + HSM-sign the secure-boot chain.
# Builds the ESP-IDF secure-boot bootloader and the esp-hal app, signs BOTH with your
# enrolled key(s), and verifies. No hardware, no burns. Output lands in --outdir.
# See docs/formal/SECURE-BOOT-V2.md Phase A.
#
#   provision/3-build-sign.sh --ssid X --pass Y --supervisor <k> --keys token2,thetis
#   provision/3-build-sign.sh --ssid X --pass Y --supervisor <k> --skip-bootloader   # app only
#
#   --ssid/--pass       Wi-Fi creds baked into the app
#   --supervisor <k>    P-256 supervisor pubkey: 66-hex, PEM file, or inline PEM
#   --keys <a,b>        enrolled key names, first = primary, rest appended  (default: token2)
#   --outdir <dir>      where signed images land            (default: secure-boot/out)
#   --features <list>   cargo features (default: udp-transport,efuse-hmac-identity)
#   --secure-version <n> anti-rollback version stamped into the app descriptor before signing
#                       (default: current epoch seconds — monotonic per build). The device
#                       rejects any OTA whose version is not strictly above the one it runs.
#   --skip-bootloader   sign only the app (bootloader already built/flashed)
#   --build-only        build + stamp app.bin but DON'T sign it (leaves an unsigned, checksum-
#                       valid image for a custom HSM sign — e.g. a single backup-key signature)
source "$(dirname "$0")/lib.sh"

SSID="" PASS="" SUP="" KEYS="token2" OUTDIR="$SB/out" FEATURES="udp-transport,efuse-hmac-identity" SKIPBL=0 SECVER="" BUILDONLY=0
while [ $# -gt 0 ]; do case "$1" in
  --ssid) SSID="$2"; shift 2;; --pass) PASS="$2"; shift 2;; --supervisor) SUP="$2"; shift 2;;
  --keys) KEYS="$2"; shift 2;; --outdir) OUTDIR="$2"; shift 2;; --features) FEATURES="$2"; shift 2;;
  --secure-version) SECVER="$2"; shift 2;;
  --build-only) BUILDONLY=1; shift;;
  --skip-bootloader) SKIPBL=1; shift;; -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
load_creds # fill SSID/PASS/SUP from the Keychain if not given (provision/store-creds.sh)
[ -n "$SSID" ] && [ -n "$PASS" ] && [ -n "$SUP" ] || die "--ssid/--pass/--supervisor required (or store once: provision/store-creds.sh)"
need esptool "brew install esptool"
SUPHEX="$(supervisor_to_hex "$SUP")"
IFS=',' read -r PRIMARY BACKUP _ <<< "$KEYS"
[ -f "$(key_ini "$PRIMARY")" ] || die "key '$PRIMARY' not enrolled (provision/1-enroll-key.sh --name $PRIMARY)"
mkdir -p "$OUTDIR"

# sign <unsigned> <signed> : primary key, then append backup if a second --keys name was given
sign() {
  ESPSECURE="$(espsecure_bin)" \
  PRIMARY_INI="$(key_ini "$PRIMARY")" PRIMARY_PUB="$(key_pub "$PRIMARY")" \
  BACKUP_INI="$(key_ini "${BACKUP:-x}")" BACKUP_PUB="$(key_pub "${BACKUP:-x}")" \
  BACKUP_DRIVER="$(key_driver "${BACKUP:-}")" \
  SKIP_BACKUP="$([ -n "${BACKUP:-}" ] && echo 0 || echo 1)" \
    "$SB/sign-secure-boot.sh" "$1" "$2"
}

if [ "$SKIPBL" != 1 ]; then
  note "1/4 build the secure-boot bootloader (idf.py)"
  [ -f "$HOME/esp/esp-idf/export.sh" ] || die "ESP-IDF not found (~/esp/esp-idf) — provision/0-toolchains.sh"
  . "$HOME/esp/esp-idf/export.sh" >/dev/null 2>&1
  idf.py -C "$SB" set-target esp32s3 >/dev/null
  idf.py -C "$SB" bootloader
  idf.py -C "$SB" partition-table
  note "2/4 sign the bootloader -> $OUTDIR/bootloader-signed.bin"
  sign "$SB/build/bootloader/bootloader.bin" "$OUTDIR/bootloader-signed.bin"
  cp "$SB/build/partition_table/partition-table.bin" "$OUTDIR/partition-table.bin"
else
  note "1-2/4 bootloader skipped (--skip-bootloader)"
fi

# Trusted SECURE_BOOT_DIGEST(s) for the ota-net receive-time signature check: SHA-256 of each
# enrolled key's public section (the same value burned in eFuse). Baked into the app so it can
# verify an incoming image's Secure Boot signature before activating a slot.
DIGESTS="$(xxd -p "$(key_digest "$PRIMARY")" 2>/dev/null | tr -d '\n')"
if [ -n "${BACKUP:-}" ] && [ -f "$(key_digest "$BACKUP")" ]; then
  DIGESTS="$DIGESTS,$(xxd -p "$(key_digest "$BACKUP")" | tr -d '\n')"
fi
[ -n "$DIGESTS" ] || die "no key digest for '$PRIMARY' (provision/1-enroll-key.sh --name $PRIMARY)"

note "3/4 build the esp-hal app (features: $FEATURES)"
( cd "$FW" && source "$HOME/export-esp.sh" >/dev/null 2>&1 \
  && WIFI_SSID="$SSID" WIFI_PASS="$PASS" SUPERVISOR_PUBKEY="$SUPHEX" SECURE_BOOT_DIGESTS="$DIGESTS" \
       cargo build --release --no-default-features --features "$FEATURES" )
[ -f "$ELF" ] || die "app ELF missing: $ELF"
esptool --chip esp32s3 elf2image "$ELF" --output "$OUTDIR/app.bin"

# Stamp the anti-rollback version into the app descriptor (esp_app_desc.secure_version) BEFORE
# signing, so the RSA signature covers it and the device can trust it. The esp_app_desc macro
# hardcodes this field to 0, so we patch it here. Default = epoch seconds (monotonic per build).
[ -n "$SECVER" ] || SECVER="$(date +%s)"
note "3b/4 stamp secure_version = $SECVER into app.bin + recompute checksum/hash (anti-rollback)"
python3 - "$OUTDIR/app.bin" "$SECVER" <<'PY'
import sys, struct, hashlib
path, ver = sys.argv[1], int(sys.argv[2])
if not (0 < ver <= 0xFFFFFFFF):
    sys.exit(f"secure-version {ver} out of u32 range")
d = bytearray(open(path, 'rb').read())
if d[0] != 0xE9:
    sys.exit("not an esp image (bad header magic 0xE9)")
MAGIC, OFF = 0xABCD5432, 0x20            # app_desc magic @0x20, secure_version @0x24
if struct.unpack_from('<I', d, OFF)[0] != MAGIC:
    sys.exit(f"app_desc magic mismatch at {OFF:#x} — image layout changed")
struct.pack_into('<I', d, OFF + 4, ver)
# The stamp changed segment data, so the esp_image 1-byte checksum AND the appended SHA-256
# (which elf2image already computed) are now stale — recompute both, else the image fails its
# checksum at boot and the bootloader rolls back. Must run BEFORE signing so the RSA sig covers it.
nseg, hash_appended = d[1], d[23]
off, csum = 24, 0xEF
for _ in range(nseg):
    slen = struct.unpack_from('<I', d, off + 4)[0]
    for b in d[off + 8: off + 8 + slen]:
        csum ^= b
    off += 8 + slen
cpos = off + ((15 - (off % 16)) % 16)   # checksum byte: first offset >= end-of-segments with %16==15
d[cpos] = csum
if hash_appended:
    d[cpos + 1: cpos + 33] = hashlib.sha256(d[:cpos + 1]).digest()
open(path, 'wb').write(d)
print(f"  secure_version = {ver} stamped at {OFF + 4:#x}; checksum 0x{csum:02x} + hash recomputed")
PY

if [ "$BUILDONLY" = 1 ]; then
  echo "OK — built (unsigned) $OUTDIR/app.bin  (SECURE_BOOT_DIGESTS baked: $DIGESTS)"
  echo "     --build-only: skipped signing. Sign it yourself (e.g. a single-key or driver-specific HSM sign)."
  exit 0
fi

note "4/4 sign the app -> $OUTDIR/app-signed.bin"
sign "$OUTDIR/app.bin" "$OUTDIR/app-signed.bin"
echo "OK — signed chain in $OUTDIR/:"; ls -1 "$OUTDIR"
