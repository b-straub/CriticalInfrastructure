#!/bin/bash
# provision/show-device-keys.sh — read the device's public keys off the serial
# boot log, so you can paste them into the macOS/iOS app's Settings.
#
# Why this exists: the keys are derived on-chip from the read-protected eFuse HMAC
# root and never leave the device, so the host cannot compute them — the ONLY
# source is the boot log the firmware prints. `flash-udp.sh --monitor` shows them
# while flashing; `ota-update.sh` pushes over the network and never sees serial.
# This reads them without reflashing: it resets the board and greps the two lines.
#
#   provision/show-device-keys.sh                 # auto-detect the serial port
#   provision/show-device-keys.sh /dev/cu.usbmodemXXXX
#
# The device prints (identity.rs):
#   ESP32 Ed25519 Response-Signing PubKey: <64 hex>   -> app "Ed25519 sig key"
#   ESP32 X25519 PubKey:                   <64 hex>   -> app "X25519 (ROM) key"
set -euo pipefail

find_port() {
  ls /dev/cu.usbmodem* /dev/cu.usbserial* /dev/cu.wchusbserial* /dev/cu.SLAB_USBtoUART* 2>/dev/null | head -1 || true
}
# Accept `--port <dev>` (used by the in-app Showcase) or a bare positional port; else auto-detect.
PORT=""
case "${1:-}" in
  --port) PORT="${2:-}";;
  "") ;;
  *) PORT="$1";;
esac
[ -n "$PORT" ] || PORT="$(find_port)"
[ -n "$PORT" ] || { echo "No serial port found. Connect the board (UART port) or pass it: $0 /dev/cu.XXXX"; exit 1; }
echo "==> Reading keys from $PORT (resetting the board; ~6s)…"

python3 - "$PORT" <<'PY'
import sys, time, re
PORT = sys.argv[1]
try:
    import serial  # pyserial (pip3 install pyserial); optional path below if absent
    ser = serial.Serial(PORT, 115200, timeout=0.3)
    # Auto-reset pulse (CH34x/CP210x DTR->IO0, RTS->EN): tap EN low then release.
    ser.dtr = False
    ser.rts = True; time.sleep(0.12); ser.rts = False
    reader = lambda: ser.read(4096).decode("utf-8", "replace")
except Exception:
    # No pyserial (or a JTAG port that ignores RTS): fall back to a raw read and
    # ask the user to press RESET themselves.
    import termios, os
    print("   (pyserial not installed — press the RESET button on the board now;")
    print("    `pip3 install pyserial` enables an automatic reset next time)")
    fd = os.open(PORT, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    a = termios.tcgetattr(fd)
    a[0] = 0; a[1] = 0; a[2] = termios.CREAD | termios.CLOCAL | termios.CS8; a[3] = 0
    a[4] = termios.B115200; a[5] = termios.B115200
    a[6][termios.VMIN] = 0; a[6][termios.VTIME] = 5  # 0.5s read timeout -> deadline is honored
    termios.tcsetattr(fd, termios.TCSANOW, a)
    def reader():
        try:
            return os.read(fd, 4096).decode("utf-8", "replace")
        except BlockingIOError:
            time.sleep(0.2)
            return ""

buf, deadline = "", time.time() + 20
sig = x25 = ip = None
while time.time() < deadline and not (sig and x25):
    buf += reader()
    m = re.search(r"Response-Signing PubKey:\s*([0-9a-fA-F]{64})", buf)
    if m: sig = m.group(1)
    m = re.search(r"X25519 PubKey:\s*([0-9a-fA-F]{64})", buf)
    if m: x25 = m.group(1)
    m = re.search(r"Got IP:\s*([0-9.]+)", buf)   # only present in UDP mode
    if m: ip = m.group(1)

if not (sig and x25):
    print("\nCould not read both keys. Is the board on this port and booting? "
          "Try pressing RESET, or use the UART port (not native USB-JTAG).")
    sys.exit(1)

import json, subprocess
# All public: X25519 pub (encrypt-to-device) + Ed25519 pub (verify replies). No
# secrets — the eFuse-held private halves never leave the chip — so this JSON is
# safe to share / AirDrop. `criticalinfra` version tag lets the app recognize it.
payload = {"criticalinfra": 1,
           "espX25519PubHex": x25,
           "espSigPubHex": sig}
if ip:
    payload["host"] = ip
blob = json.dumps(payload)

print()
print("  App field 'X25519 (ROM) key':  " + x25)
print("  App field 'Ed25519 sig key':   " + sig)
if ip:
    print("  Device IP (UDP host):          " + ip)
print()
print("JSON (public keys — safe to share):")
print("  " + blob)

# Copy to the clipboard so the app's Settings > Import config can read it (macOS;
# Universal Clipboard carries it to a nearby iPhone/iPad on the same Apple ID).
try:
    subprocess.run(["pbcopy"], input=blob.encode(), check=True)
    print("\nCopied to the clipboard — in the app: Settings > Import config.")
except Exception:
    pass

# Also drop a file you can AirDrop to an iPhone/iPad and open in the app.
try:
    with open("device-config.json", "w") as f:
        f.write(blob + "\n")
    print("Wrote device-config.json (AirDrop it to a phone, or open in the app).")
except Exception:
    pass
PY
