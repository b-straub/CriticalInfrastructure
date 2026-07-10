#!/bin/bash
# provision/lib.sh — shared helpers for the provisioning pipeline (provision/[0-5]-*.sh).
# SOURCED, never run directly. Single source of truth for repo paths, tool resolution
# and token/key helpers, so each stage script stays short and readable.
#
# No fallbacks: a missing tool or a broken espsecure dies loudly rather than silently
# degrading — a hidden fallback would mask a real problem.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SB="$REPO/secure-boot"                            # signing config + IDF bootloader project (gitignored keys)
FW="$REPO/target-esp32s3"                          # esp-hal firmware crate
ELF="$REPO/target/xtensa-esp32s3-none-elf/release/target-esp32s3"
APP_OFFSET_DEFAULT="0x20000"                        # app slot in the secure-boot flash layout

die()  { echo "ERROR: $*" >&2; exit 1; }
note() { echo "### $*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 not on PATH (${2:-install it})"; }
# print a script's leading comment block as its --help text
show_help() { grep -E '^#( |$)' "${1:-$0}" | sed 's/^#[[:space:]]\{0,1\}//'; }

# espsecure MUST carry the PKCS#11 ([hsm]) extra — Homebrew's build does NOT, and the
# gap surfaces only as a cryptic "No module named pkcs11" mid-sign. Resolve the
# dedicated venv that stage 0 builds; never fall back to a broken espsecure.
espsecure_bin() {
  local b="$HOME/.esptool-hsm/bin/espsecure"
  [ -x "$b" ] || die "espsecure[hsm] missing — run: provision/0-toolchains.sh install"
  "$b" sign-data --help 2>&1 | grep -q -- '--hsm' || die "$b has no [hsm] extra"
  printf '%s' "$b"
}

find_port()    { ls /dev/cu.usbmodem* /dev/cu.usbserial* 2>/dev/null | head -1 || true; }
require_port() { [ -n "${1:-}" ] || die "no board port (pass --port /dev/cu.XXXX)"; [ -e "$1" ] || die "port not found: $1"; }

# A supervisor P-256 pubkey argument -> 66-hex compressed. Accepts 66-hex, a PEM file,
# or inline PEM text (as keyroost / `openssl ... -pubout` emit; indentation tolerated).
supervisor_to_hex() {
  local in="$1" src hex
  if [ -f "$in" ] || printf '%s' "$in" | grep -q 'BEGIN PUBLIC KEY'; then
    if [ -f "$in" ]; then src="$(cat "$in")"; else src="$in"; fi
    hex="$(printf '%s\n' "$src" | sed 's/^[[:space:]]*//' \
      | openssl ec -pubin -conv_form compressed -outform DER 2>/dev/null | tail -c 33 | xxd -p -c 33)"
  else
    hex="$(printf '%s' "$in" | tr 'A-F' 'a-f')"
  fi
  printf '%s' "$hex" | grep -qE '^0[23][0-9a-f]{64}$' || die "not a P-256 pubkey (66-hex or PEM): '$hex'"
  printf '%s' "$hex"
}

# Per-enrolled-key artifacts, addressed by short name, all under secure-boot/ (gitignored).
key_ini()    { printf '%s' "$SB/hsm-$1.ini"; }
key_pub()    { printf '%s' "$SB/$1_pub.pem"; }
key_digest() { printf '%s' "$SB/$1_digest.bin"; }
# Some cards (e.g. Thetis) need OpenSC's PIV-II driver; stage 1 records it here if so.
key_driver() { local f="$SB/hsm-$1.driver"; [ -f "$f" ] && cat "$f" || true; }

# --- provisioning creds in the macOS Keychain (store once, don't retype each build) ---
KC_WIFI="${KC_WIFI:-CriticalInfra-WiFi}"      # account = SSID, password = Wi-Fi password
KC_SUP="${KC_SUP:-CriticalInfra-Supervisor}"  # password = 66-hex P-256 supervisor pubkey

# Fill empty SSID / PASS / SUP from the Keychain. Command-line values always win; a
# missing Keychain entry just leaves the value empty (the caller's :? check then fires).
# Only the Wi-Fi password is secret; SSID + supervisor pubkey are kept alongside it for
# convenience. Set them with provision/store-creds.sh.
load_creds() {
    [ -n "${PASS:-}" ] || PASS="$(security find-generic-password -s "$KC_WIFI" -w 2>/dev/null || true)"
    [ -n "${SSID:-}" ] || SSID="$(security find-generic-password -s "$KC_WIFI" 2>/dev/null | awk -F'"' '/"acct"<blob>/{print $4}')"
    [ -n "${SUP:-}" ]  || SUP="$(security find-generic-password -s "$KC_SUP" -w 2>/dev/null || true)"
}
