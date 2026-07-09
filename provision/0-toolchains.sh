#!/bin/bash
# provision/0-toolchains.sh — stage 0: machine toolchains (one-time per Mac).
#
#   provision/0-toolchains.sh            # check what's present/missing (default)
#   provision/0-toolchains.sh check
#   provision/0-toolchains.sh install    # build the espsecure[hsm] venv; brew-install esptool/opensc
#
# espup (Rust ESP) and ESP-IDF are large, interactive installs — this script checks
# for them and prints the exact command rather than running them blind.
source "$(dirname "$0")/lib.sh"

ok() { echo "  [ok]   $1"; }
no() { echo "  [MISS] $1 — $2"; }

case "${1:-check}" in
  check)
    echo "== toolchain status =="
    [ -f "$HOME/export-esp.sh" ]           && ok "espup Rust ESP toolchain (~/export-esp.sh)" || no "espup"          "cargo install espup && espup install"
    [ -f "$HOME/esp/esp-idf/export.sh" ]   && ok "ESP-IDF (~/esp/esp-idf)"                    || no "ESP-IDF"        "https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/get-started/"
    command -v esptool >/dev/null          && ok "esptool ($(command -v esptool))"            || no "esptool"        "brew install esptool"
    if [ -x "$HOME/.esptool-hsm/bin/espsecure" ] && "$HOME/.esptool-hsm/bin/espsecure" sign-data --help 2>&1 | grep -q -- '--hsm'; then
      ok "espsecure[hsm] (~/.esptool-hsm)"; else no "espsecure[hsm]" "run: $0 install"; fi
    [ -f /opt/homebrew/lib/opensc-pkcs11.so ] && ok "OpenSC PKCS#11"                          || no "OpenSC"         "brew install opensc"
    ;;
  install)
    note "esptool[hsm] venv -> ~/.esptool-hsm"
    if [ -x "$HOME/.esptool-hsm/bin/espsecure" ]; then echo "  (already present)"; else
      python3 -m venv "$HOME/.esptool-hsm"
      "$HOME/.esptool-hsm/bin/pip" -q install 'esptool[hsm]'
    fi
    command -v esptool >/dev/null            || { note "brew install esptool"; brew install esptool; }
    [ -f /opt/homebrew/lib/opensc-pkcs11.so ] || { note "brew install opensc";  brew install opensc;  }
    echo; "$0" check
    ;;
  -h|--help) show_help "$0" ;;
  *) die "usage: $0 {check|install}" ;;
esac
