#!/bin/bash
# Guided helper for the eFuse hardening runbook (docs/formal/EFUSE-HARDENING.md).
#
# SAFE: never burns real eFuses. It rehearses the whole sequence on a VIRTUAL eFuse
# (espefuse --virt), shows the real chip's current state (read-only), and generates
# the HMAC identity key. You run the actual `espefuse burn-*` commands yourself, per
# the runbook — they are IRREVERSIBLE (bits only go 0 -> 1).
set -euo pipefail

# esptool >=5 provides `espefuse` (the `.py` form is deprecated). brew install esptool
EF="$(command -v espefuse || command -v espefuse.py || true)"
[ -n "$EF" ] || { echo "espefuse not found — 'brew install esptool' (or pip install esptool)"; exit 1; }

find_port() {
  ls /dev/cu.usbmodem* /dev/cu.usbserial* /dev/cu.wchusbserial* /dev/cu.SLAB_USBtoUART* 2>/dev/null | head -1 || true
}

usage() { echo "usage: $0 {rehearse | check [port] | genkey [outfile]}"; exit 1; }

case "${1:-}" in
  rehearse) # dry-run the full runbook on a virtual ESP32-S3 — no hardware, no burns
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    head -c 32 /dev/urandom > "$tmp/hmac_key.bin"
    "$EF" --virt --chip esp32s3 --path-efuse-file "$tmp/virt.json" --do-not-confirm \
      burn-key BLOCK_KEY0 "$tmp/hmac_key.bin" HMAC_UP \
      burn-efuse DIS_PAD_JTAG 1 DIS_USB_JTAG 1 ENABLE_SECURITY_DOWNLOAD 1 >/dev/null
    echo "== resulting VIRTUAL eFuse state (what the real burns would produce) =="
    "$EF" --virt --chip esp32s3 --path-efuse-file "$tmp/virt.json" summary 2>/dev/null \
      | grep -iE 'RD_DIS |DIS_PAD_JTAG|DIS_USB_JTAG|ENABLE_SECURITY_DOWNLOAD|DIS_DOWNLOAD_MODE'
    echo "OK — matches the runbook target (identity read-protected, JTAG off, secure download)."
    ;;
  check) # read-only: the REAL chip's current eFuse state (device in download mode)
    port="${2:-$(find_port)}"
    [ -n "$port" ] || { echo "No ESP device found. Connect the ESP32-S3 in download mode, or: $0 check /dev/cu.XXXX"; exit 1; }
    echo "Using port: $port"
    "$EF" --port "$port" summary
    ;;
  genkey)
    out="${2:-hmac_key.bin}"
    [ -e "$out" ] && { echo "$out exists — refusing to overwrite"; exit 1; }
    head -c 32 /dev/urandom > "$out"; chmod 600 "$out"
    echo "Wrote 256-bit HMAC identity root -> $out"
    echo "Burn it (IRREVERSIBLE), then destroy the file:"
    echo "  $EF --port <PORT> burn-key BLOCK_KEY0 $out HMAC_UP   # auto read-protects"
    echo "  rm -P $out          # macOS overwrite+delete (Linux: shred -u $out)"
    ;;
  *) usage ;;
esac
