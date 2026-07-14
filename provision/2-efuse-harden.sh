#!/bin/bash
# provision/2-efuse-harden.sh — stage 2: root the device identity in hardware (per board).
# Burns the HMAC identity key (auto read-protected) and disables JTAG. IRREVERSIBLE.
# Defaults to a DRY RUN on a virtual eFuse; add --yes-burn for real.
#
# ORDER: this does NOT enable Secure Download Mode — that read-lock blocks eFuse reads,
# so it must come AFTER Secure Boot (stage 4). ENABLE_SECURITY_DOWNLOAD is burned last,
# by stage 6 (provision/6-release-seal.sh). Correct sequence: 1 → 2 → 3 → 4 → [5] → 6.
# See docs/formal/EFUSE-HARDENING.md and SECURE-BOOT-V2.md.
#
#   provision/2-efuse-harden.sh --port /dev/cu.XXXX               # dry run + read the real chip
#   provision/2-efuse-harden.sh --port /dev/cu.XXXX --yes-burn    # REAL burns (permanent)
#
#   --port <dev>       board in download mode (auto-detected if omitted)
#   --hmac-key <file>  32-byte identity root (generated if omitted; you destroy it after)
#   --yes-burn         actually burn (otherwise rehearse on --virt only)
source "$(dirname "$0")/lib.sh"

PORT="" HMAC="" BURN=0 GEN=0
while [ $# -gt 0 ]; do case "$1" in
  --port)     PORT="$2"; shift 2;;
  --hmac-key) HMAC="$2"; shift 2;;
  --yes-burn) BURN=1;    shift;;
  -h|--help)  show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
need espefuse "brew install esptool"
[ -n "$PORT" ] || PORT="$(find_port)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
[ -n "$HMAC" ] || { HMAC="$TMP/hmac_key.bin"; head -c 32 /dev/urandom > "$HMAC"; GEN=1; }

if [ "$BURN" != 1 ]; then
  note "DRY RUN — rehearsing on a virtual ESP32-S3 (no hardware writes)"
  espefuse --virt --chip esp32s3 --path-efuse-file "$TMP/virt.json" --do-not-confirm \
    burn-key BLOCK_KEY0 "$HMAC" HMAC_UP \
    burn-efuse DIS_PAD_JTAG 1 DIS_USB_JTAG 1 >/dev/null
  echo "-- resulting virtual eFuse state --"
  espefuse --virt --chip esp32s3 --path-efuse-file "$TMP/virt.json" summary 2>/dev/null \
    | grep -iE 'RD_DIS |DIS_PAD_JTAG|DIS_USB_JTAG' || true
  echo "OK (dry run). Re-run with --yes-burn to make it permanent."
  [ "$GEN" = 1 ] && echo "NOTE: a real run generates + saves the HMAC key; destroy it after burning."
  exit 0
fi

require_port "$PORT"
if [ "$GEN" = 1 ]; then
  OUT="$REPO/hmac_key.bin"; cp "$HMAC" "$OUT"; chmod 600 "$OUT"; HMAC="$OUT"
  echo "generated identity root -> $OUT   (destroy after burn:  rm -P $OUT)"
fi
note "REAL BURN on $PORT (permanent): HMAC identity + JTAG off (NOT secure download — that's stage 6)"
espefuse --port "$PORT" burn-key BLOCK_KEY0 "$HMAC" HMAC_UP
espefuse --port "$PORT" burn-efuse DIS_PAD_JTAG 1 DIS_USB_JTAG 1
echo "done. Destroy the key file now:  rm -P $HMAC"
echo "Secure Download Mode is deferred to stage 6 (after Secure Boot) — do NOT burn it here."
