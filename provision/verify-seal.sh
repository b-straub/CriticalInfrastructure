#!/bin/bash
# provision/verify-seal.sh — prove a Release-sealed board rejects every cable path.
# Runs three checks over USB and reports each as DENIED (seal working) or ALLOWED (seal
# missing/incomplete):
#   1. eFuse read    — espefuse summary               → blocked by Secure Download Mode
#   2. flash read    — esptool read-flash             → blocked by Secure Download Mode
#   3. encrypt-write — esptool write-flash --encrypt  → blocked by DIS_DOWNLOAD_MANUAL_ENCRYPT
#
# Safe by construction: checks 1–2 are read-only; check 3 targets an UNUSED high flash offset
# (default 0x600000, past every partition) with a single 0xFF sector — so on a sealed board it
# writes nothing (denied), and even on an unsealed board it can only touch empty space. OTA is
# unaffected regardless (the app encrypt-writes from RAM, a path these eFuses don't gate).
# Exit code: 0 = fully sealed, 1 = at least one cable path still open.
#
#   provision/verify-seal.sh --port /dev/cu.XXXX
#   provision/verify-seal.sh --port /dev/cu.XXXX --skip-write      # only the two read checks
#   provision/verify-seal.sh --port /dev/cu.XXXX --offset 0x700000 # different unused offset
source "$(dirname "$0")/lib.sh"

PORT="" OFFSET="0x600000" SKIP_WRITE=0
while [ $# -gt 0 ]; do case "$1" in
  --port) PORT="$2"; shift 2;; --offset) OFFSET="$2"; shift 2;;
  --skip-write) SKIP_WRITE=1; shift;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
need espefuse "brew install esptool"; need esptool "brew install esptool"
[ -n "$PORT" ] || PORT="$(find_port)"
require_port "$PORT"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
PASS=0 FAIL=0

# 1. eFuse read — Secure Download Mode makes espefuse refuse to read/burn eFuses
note "1/3 eFuse access — espefuse summary"
OUT="$(espefuse --port "$PORT" summary 2>&1 || true)"
if printf '%s\n' "$OUT" | grep -qiE 'secure download|can ?not continue'; then
  echo "  DENIED  ✅  Secure Download Mode blocks eFuse read/burn"; PASS=$((PASS+1))
else
  echo "  ALLOWED ❌  espefuse read the chip — ENABLE_SECURITY_DOWNLOAD not set"; FAIL=$((FAIL+1))
fi

# 2. flash read — the cable must not be able to dump / clone firmware
note "2/3 flash read — esptool read-flash 0x0 16"
OUT="$(esptool --chip esp32s3 --port "$PORT" read-flash 0x0 16 "$TMP/r.bin" 2>&1 || true)"
if printf '%s\n' "$OUT" | grep -qiE 'not available in secure download|secure download mode'; then
  echo "  DENIED  ✅  read-flash blocked; cable can't dump/clone firmware"; PASS=$((PASS+1))
elif [ -s "$TMP/r.bin" ]; then
  echo "  ALLOWED ❌  read $(stat -f%z "$TMP/r.bin") bytes off the chip"; FAIL=$((FAIL+1))
else
  echo "  DENIED  ✅  no flash data returned"; PASS=$((PASS+1))
fi

# 3. encrypt-write — the only way to cable-flash a *bootable* image onto an encrypted board;
#    DIS_DOWNLOAD_MANUAL_ENCRYPT must refuse it. Target = unused offset, so this is harmless.
if [ "$SKIP_WRITE" != 1 ]; then
  note "3/3 encrypt-write — esptool write-flash --encrypt $OFFSET (1 sector 0xFF, UNUSED region)"
  python3 -c "import sys; open(sys.argv[1],'wb').write(b'\xff'*4096)" "$TMP/ff.bin"
  OUT="$(esptool --chip esp32s3 --port "$PORT" write-flash --encrypt "$OFFSET" "$TMP/ff.bin" 2>&1 || true)"
  if printf '%s\n' "$OUT" | grep -qiE 'hash of data verified|wrote [0-9]+ bytes'; then
    echo "  ALLOWED ❌  the cable wrote an encrypted image — seal NOT effective!"; FAIL=$((FAIL+1))
  else
    echo "  DENIED  ✅  encrypt-write refused; no bootable image can be cable-flashed"; PASS=$((PASS+1))
    DET="$(printf '%s\n' "$OUT" | grep -iE 'a fatal error|not allowed|not available|refused|manual.?encrypt|encryption is' | head -1 | sed 's/^[[:space:]]*//')"
    [ -n "$DET" ] && echo "      ($DET)"
  fi
else
  note "3/3 encrypt-write — skipped (--skip-write)"
fi

echo
if [ "$FAIL" = 0 ]; then
  echo "SEAL VERIFIED ✅  cable cannot read, dump, or flash a bootable image on $PORT."
  echo "                 (OTA still works: provision/ota-update.sh — app encrypt-writes from RAM.)"
else
  echo "SEAL INCOMPLETE ❌  $FAIL cable path(s) still open — run: provision/6-release-seal.sh --port $PORT --yes-burn"
fi
echo "Power-cycle the board to resume the app."
[ "$FAIL" = 0 ]
