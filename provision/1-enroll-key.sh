#!/bin/bash
# provision/1-enroll-key.sh — stage 1: enroll ONE inserted security key.
#
# Prereq (manual, GUI): first generate an on-card RSA-3072 key with keyroost — a shell
# script can't drive the card's key generation. This stage then exports that key's
# PUBLIC half, writes its PKCS#11 signing config, and computes its Secure Boot v2
# digest — the three artifacts the later stages consume. Nothing is burned.
#
#   provision/1-enroll-key.sh --name mainToken
#   provision/1-enroll-key.sh --name backupToken --driver PIV-II
#
#   --name <n>          short name -> secure-boot/{hsm-<n>.ini, <n>_pub.pem, <n>_digest.bin}
#   --driver <d>        OpenSC driver the card needs (e.g. PIV-II for the backup token); omit for the main token
#   --pubkey-label <l>  PKCS#11 label of the public key   (default: "PIV AUTH pubkey")
#   --key-label <l>     PKCS#11 label of the private key  (default: "PIV AUTH key")
#   --module <path>     PKCS#11 module (default: /opt/homebrew/lib/opensc-pkcs11.so)
source "$(dirname "$0")/lib.sh"

NAME="" DRIVER="" PUBLABEL="PIV AUTH pubkey" KEYLABEL="PIV AUTH key" MODULE=/opt/homebrew/lib/opensc-pkcs11.so
while [ $# -gt 0 ]; do case "$1" in
  --name)         NAME="$2";     shift 2;;
  --driver)       DRIVER="$2";   shift 2;;
  --pubkey-label) PUBLABEL="$2"; shift 2;;
  --key-label)    KEYLABEL="$2"; shift 2;;
  --module)       MODULE="$2";   shift 2;;
  -h|--help)      show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
[ -n "$NAME" ] || die "--name required"
need pkcs11-tool "brew install opensc"; need openssl "brew install openssl"
ES="$(espsecure_bin)"
INI="$(key_ini "$NAME")"; PUB="$(key_pub "$NAME")"; DIG="$(key_digest "$NAME")"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

note "1/3 read the on-card public key -> $PUB"
# Only force an OpenSC card driver when one was actually requested (--driver, e.g.
# PIV-II for the backup token). Setting OPENSC_DRIVER to the EMPTY string — as the
# main token's blank $DRIVER did — makes OpenSC fail the read with "object not
# found" even though the key is present; leaving it unset uses the right driver.
if [ -n "$DRIVER" ]; then export OPENSC_DRIVER="$DRIVER"; fi
pkcs11-tool --module "$MODULE" --read-object --type pubkey --label "$PUBLABEL" -o "$TMP/pub.der" \
  || die "could not read '$PUBLABEL' — card inserted and key generated (keyroost)?"
openssl rsa -pubin -inform DER -in "$TMP/pub.der" -pubout -out "$PUB"
openssl rsa -pubin -in "$PUB" -noout -text 2>/dev/null | head -1 || true

note "2/3 write PKCS#11 signing config -> $INI"
cat > "$INI" <<EOF
[hsm_config]
pkcs11_lib = $MODULE
slot = 0
label = $KEYLABEL
label_pubkey = $PUBLABEL
EOF
[ -n "$DRIVER" ] && { printf '%s' "$DRIVER" > "$SB/hsm-$NAME.driver"; echo "  driver: $DRIVER (recorded)"; }

note "3/3 compute Secure Boot v2 digest -> $DIG"
"$ES" digest-sbv2-public-key --keyfile "$PUB" --output "$DIG" >/dev/null
echo "  digest: $(xxd -l8 -p "$DIG")…  (burned later as SECURE_BOOT_DIGESTn)"
echo "OK — key '$NAME' enrolled."
