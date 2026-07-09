#!/bin/bash
# provision/4-flash-enable-secureboot.sh — stage 4: flash the signed chain and enable
# Secure Boot v2 (per board). Flashing is safe; the eFuse enable is IRREVERSIBLE.
# Defaults to flash + REHEARSE the burns; add --yes-burn to burn.
# See docs/formal/SECURE-BOOT-V2.md Phase B.  ⚠ do the FIRST enable on a spare board.
#
#   provision/4-flash-enable-secureboot.sh --port /dev/cu.XXXX --keys token2,thetis
#   provision/4-flash-enable-secureboot.sh --port /dev/cu.XXXX --keys token2,thetis --yes-burn
#
#   --port <dev>     board in download mode
#   --keys <a,b>     enrolled names -> DIGEST0 = a, DIGEST1 = b (key blocks KEY1/KEY2)
#   --indir <dir>    signed images from stage 3       (default: secure-boot/out)
#   --yes-burn       actually burn SECURE_BOOT_DIGEST* + SECURE_BOOT_EN (permanent)
source "$(dirname "$0")/lib.sh"

PORT="" KEYS="token2" INDIR="$SB/out" BURN=0
while [ $# -gt 0 ]; do case "$1" in
  --port) PORT="$2"; shift 2;; --keys) KEYS="$2"; shift 2;;
  --indir) INDIR="$2"; shift 2;; --yes-burn) BURN=1; shift;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
require_port "$PORT"; need esptool "brew install esptool"; need espefuse "brew install esptool"
for f in bootloader-signed.bin partition-table.bin app-signed.bin; do
  [ -f "$INDIR/$f" ] || die "missing $INDIR/$f — run provision/3-build-sign.sh first"
done
IFS=',' read -r K0 K1 _ <<< "$KEYS"
[ -f "$(key_digest "$K0")" ] || die "no digest for '$K0' (provision/1-enroll-key.sh --name $K0)"

note "1/2 flash signed chain (bootloader @0x0, partition-table @0xc000, app @0x20000)"
esptool --chip esp32s3 --port "$PORT" write_flash \
  0x0    "$INDIR/bootloader-signed.bin" \
  0xc000 "$INDIR/partition-table.bin" \
  0x20000 "$INDIR/app-signed.bin"

BURN_CMDS=( "espefuse --port $PORT burn-key BLOCK_KEY1 $(key_digest "$K0") SECURE_BOOT_DIGEST0" )
if [ -n "${K1:-}" ]; then
  [ -f "$(key_digest "$K1")" ] || die "no digest for '$K1'"
  BURN_CMDS+=( "espefuse --port $PORT burn-key BLOCK_KEY2 $(key_digest "$K1") SECURE_BOOT_DIGEST1" )
fi
BURN_CMDS+=( "espefuse --port $PORT burn-efuse SECURE_BOOT_EN 1" )

if [ "$BURN" != 1 ]; then
  note "2/2 DRY RUN — the burns below are permanent. Re-run with --yes-burn to execute:"
  printf '    %s\n' "${BURN_CMDS[@]}"
  exit 0
fi
note "2/2 REAL BURN — enabling Secure Boot v2 (permanent; espefuse will ask to confirm)"
for c in "${BURN_CMDS[@]}"; do echo "+ $c"; $c; done
echo "done — power-cycle; serial should show 'secure boot verification succeeded'."
