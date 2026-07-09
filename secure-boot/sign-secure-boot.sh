#!/bin/bash
# Sign a Secure Boot v2 image (bootloader or app) with the PRIMARY hardware token,
# append the BACKUP token's signature, and verify both — via espsecure + PKCS#11.
# See docs/formal/SECURE-BOOT-V2.md. Needs esptool[hsm]: pip install 'esptool[hsm]'.
#
# Config via env (defaults in parentheses):
#   ESPSECURE     espsecure binary                       (espsecure)
#   PRIMARY_INI   primary token hsm_config   (hsm-token2.ini)   PRIMARY_PUB (sb_pub.pem)
#   BACKUP_INI    backup  token hsm_config   (hsm-thetis.ini)   BACKUP_PUB  (sb_backup_pub.pem)
#   BACKUP_DRIVER OpenSC driver for the backup (PIV-II — some cards need it)
#   SKIP_BACKUP=1 sign with the primary only
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <unsigned.bin> <signed.bin>"; exit 1; }
IN="$1"; OUT="$2"
ES="${ESPSECURE:-espsecure}"
PRIMARY_INI="${PRIMARY_INI:-hsm-token2.ini}"; PRIMARY_PUB="${PRIMARY_PUB:-sb_pub.pem}"
BACKUP_INI="${BACKUP_INI:-hsm-thetis.ini}";  BACKUP_PUB="${BACKUP_PUB:-sb_backup_pub.pem}"
BACKUP_DRIVER="${BACKUP_DRIVER:-PIV-II}"

echo "==> [primary] insert the primary token — PIN prompt"
"$ES" sign-data --version 2 --hsm --hsm-config "$PRIMARY_INI" --output "$OUT" "$IN"
"$ES" verify-signature --version 2 --keyfile "$PRIMARY_PUB" "$OUT" >/dev/null && echo "    primary signature verified"

if [ "${SKIP_BACKUP:-0}" != "1" ]; then
  read -r -p "==> [backup] swap to the backup token, then press Enter (Ctrl-C to keep 1 key)… " _
  TMP="$(mktemp)"; cp "$OUT" "$TMP"
  OPENSC_DRIVER="$BACKUP_DRIVER" "$ES" sign-data --version 2 --hsm --hsm-config "$BACKUP_INI" \
    --append-signatures --output "$OUT" "$TMP"
  rm -f "$TMP"
  "$ES" verify-signature --version 2 --keyfile "$BACKUP_PUB" "$OUT" >/dev/null && echo "    backup signature verified"
fi
echo "==> done: $OUT"
