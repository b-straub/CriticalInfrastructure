#!/bin/bash
# provision/ota-flash-slots.sh — OTA step 4.1a: set up an A/B board (SPARE board).
#
# Builds + signs the OTA chain, then flashes the SAME signed app into BOTH slots
# (ota_0 @ 0x20000 and ota_1 @ 0x230000) and clears otadata so the bootloader boots
# ota_0. Proves the secure-boot bootloader boots an esp-hal image from the A/B table.
# See docs/formal/OTA.md.  ⚠ spare board — the layout change repartitions flash.
#
#   provision/ota-flash-slots.sh --port /dev/cu.XXXX --ssid <S> --pass <P> --supervisor <K>
#   provision/ota-flash-slots.sh --port /dev/cu.XXXX --skip-build     # reuse secure-boot/out/
#
#   --port <dev>        spare board in download mode (required)
#   --ssid/--pass       Wi-Fi creds baked into the app (needed unless --skip-build)
#   --supervisor <k>    P-256 supervisor pubkey: 66-hex, PEM file, or inline PEM
#   --keys <a,b>        signing key(s), first = primary  (default: token2)
#   --skip-build        reuse an already-built secure-boot/out/ (must be post-partitions.csv)
#   --indir <dir>       signed chain location          (default: secure-boot/out)
source "$(dirname "$0")/lib.sh"

PORT="" SSID="" PASS="" SUP="" KEYS="token2" INDIR="$SB/out" SKIP_BUILD=0
while [ $# -gt 0 ]; do case "$1" in
  --port) PORT="$2"; shift 2;; --ssid) SSID="$2"; shift 2;; --pass) PASS="$2"; shift 2;;
  --supervisor) SUP="$2"; shift 2;; --keys) KEYS="$2"; shift 2;;
  --skip-build) SKIP_BUILD=1; shift;; --indir) INDIR="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
require_port "$PORT"; need esptool "brew install esptool"
load_creds # fill SSID/PASS/SUP from the Keychain if not given (provision/store-creds.sh)

# 1. preflight — the A/B layout needs >= 8 MB flash (ends at ~0x410000)
note "1/4 preflight: flash size (need >= 8 MB)"
SIZE_LINE="$(esptool --chip esp32s3 --port "$PORT" flash-id 2>/dev/null | grep -i 'flash size' || true)"
echo "  ${SIZE_LINE:-<no flash-size line from esptool>}"
MB="$(printf '%s' "$SIZE_LINE" | grep -oiE '[0-9]+ ?MB' | grep -oE '[0-9]+' | head -1)"
[ -n "$MB" ] || die "could not read flash size (need >= 8 MB); check the line above / board in download mode"
[ "$MB" -ge 8 ] || die "flash is ${MB}MB — the A/B layout needs >= 8 MB"
echo "  ${MB}MB OK"

# 2. build + sign the OTA chain (partition table now comes from secure-boot/partitions.csv)
if [ "$SKIP_BUILD" != 1 ]; then
  [ -n "$SSID" ] && [ -n "$PASS" ] && [ -n "$SUP" ] || die "build needs --ssid --pass --supervisor (or --skip-build)"
  note "2/4 build + sign the OTA chain (provision/3)"
  "$REPO/provision/3-build-sign.sh" --ssid "$SSID" --pass "$PASS" --supervisor "$SUP" --keys "$KEYS" --outdir "$INDIR"
else
  note "2/4 reuse signed chain in $INDIR (--skip-build)"
fi
for f in bootloader-signed.bin partition-table.bin app-signed.bin; do
  [ -f "$INDIR/$f" ] || die "missing $INDIR/$f — run without --skip-build"
done

# 3. flash bootloader + table + the SAME app into BOTH slots
note "3/4 flash bootloader + table + app -> ota_0 (0x20000) AND ota_1 (0x230000)"
esptool --chip esp32s3 --port "$PORT" write-flash \
  0x0      "$INDIR/bootloader-signed.bin" \
  0xc000   "$INDIR/partition-table.bin" \
  0x20000  "$INDIR/app-signed.bin" \
  0x230000 "$INDIR/app-signed.bin"

# 4. blank otadata -> bootloader has no selection -> boots ota_0. Use write-flash:
# its implicit sector-erase works even on secure boards, whereas the standalone
# erase-region command is blocked by esptool when security features are enabled.
note "4/4 blank otadata (0xd000, 0x2000) -> boots ota_0"
BLANK="$(mktemp)"; trap 'rm -f "$BLANK"' EXIT
python3 -c "import sys; open(sys.argv[1],'wb').write(b'\xff'*0x2000)" "$BLANK"
esptool --chip esp32s3 --port "$PORT" write-flash 0xd000 "$BLANK"

echo
echo "OK. Watch it boot:   cat $PORT"
echo "     expect:   OTA: booted from Ota0 @ 0x020000 (1920 KiB)"
echo "Then prove slot selection (step 2):"
echo "     provision/ota-switch-slot.sh --port $PORT --slot 1"
