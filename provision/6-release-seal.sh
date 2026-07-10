#!/bin/bash
# provision/6-release-seal.sh — stage D: seal flash encryption to Release level (per board).
# Burns the remaining flash-encryption lock bits so the CABLE can no longer decrypt, dump,
# or reflash the device — leaving signed + encrypted OTA (provision/ota-update.sh) as the
# ONLY way to change firmware. IRREVERSIBLE. Assumes Dev-mode encryption is already on
# (key + SPI_BOOT_CRYPT_CNT=1, from provision/4 + first boot). See docs/formal/OTA.md.
#
#   provision/6-release-seal.sh                       # dry run: rehearse + read live state
#   provision/6-release-seal.sh --port /dev/cu.XXXX --yes-burn   # REAL burns (permanent)
#
#   --port <dev>   board in download mode (auto-detected if omitted)
#   --yes-burn     actually burn (otherwise rehearse on a virtual eFuse + read the chip)
#
# Seal bits (why each):
#   SPI_BOOT_CRYPT_CNT=7           max the counter -> ROM won't re-encrypt flash (kills
#                                  esptool write-flash --encrypt); encryption stays ON (odd).
#   DIS_DOWNLOAD_MANUAL_ENCRYPT=1  UART downloader can no longer encrypt-write.
#   ENABLE_SECURITY_DOWNLOAD=1     UART download can't read/dump/erase flash or eFuses.
#                                  (Usually already set by provision/2 — then this is a no-op.)
# OTA is unaffected: it's the running app encrypt-writing from RAM, a path these bits don't gate.
source "$(dirname "$0")/lib.sh"

PORT="" BURN=0
while [ $# -gt 0 ]; do case "$1" in
  --port) PORT="$2"; shift 2;; --yes-burn) BURN=1; shift;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
need espefuse "brew install esptool"
[ -n "$PORT" ] || PORT="$(find_port)"

# One espefuse session burns all three; ENABLE_SECURITY_DOWNLOAD only takes effect after the
# next reset, so there's no mid-session self-lockout.
SEAL=( SPI_BOOT_CRYPT_CNT 7 DIS_DOWNLOAD_MANUAL_ENCRYPT 1 ENABLE_SECURITY_DOWNLOAD 1 )
GREP='SPI_BOOT_CRYPT_CNT|DIS_DOWNLOAD_MANUAL_ENCRYPT|ENABLE_SECURITY_DOWNLOAD|SECURE_BOOT_EN'

if [ "$BURN" != 1 ]; then
  note "DRY RUN — rehearse the seal on a virtual ESP32-S3 (no hardware writes)"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  espefuse --virt --chip esp32s3 --path-efuse-file "$TMP/virt.json" --do-not-confirm \
    burn-efuse "${SEAL[@]}" >/dev/null
  echo "-- resulting virtual eFuse state --"
  espefuse --virt --chip esp32s3 --path-efuse-file "$TMP/virt.json" summary 2>/dev/null \
    | grep -iE "$GREP" || true
  echo
  if [ -n "$PORT" ] && [ -e "$PORT" ]; then
    note "live state on $PORT (what's already set vs pending):"
    espefuse --port "$PORT" summary 2>&1 | grep -iE "$GREP" \
      || echo "  (couldn't read — board may already be in Secure Download Mode = already sealed)"
  else
    echo "  (no board on USB — connect it in download mode to read the live state)"
  fi
  echo
  echo "Would run:  espefuse --port <dev> burn-efuse ${SEAL[*]}"
  echo "IRREVERSIBLE: afterward the cable can't decrypt/dump/reflash; OTA is the only update path."
  echo "Re-run with --port <dev> --yes-burn to seal."
  exit 0
fi

require_port "$PORT"
note "1/2 read live eFuse state on $PORT"
if ! SUM="$(espefuse --port "$PORT" summary 2>&1)"; then
  printf '%s\n' "$SUM" | grep -qi 'download mode' \
    && die "board is already in Secure Download Mode — espefuse can't touch eFuses. The cable is already locked out; there is nothing left to seal."
  die "espefuse summary failed:
$SUM"
fi
printf '%s\n' "$SUM" | grep -iE "$GREP" || true

note "2/2 REAL BURN — sealing flash encryption to Release level (permanent; espefuse will confirm)"
echo "+ espefuse --port $PORT burn-efuse ${SEAL[*]}"
espefuse --port "$PORT" burn-efuse "${SEAL[@]}"
echo "done — power-cycle. Firmware now changes ONLY via signed+encrypted OTA: provision/ota-update.sh"
