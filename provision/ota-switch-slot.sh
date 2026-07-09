#!/bin/bash
# provision/ota-switch-slot.sh — OTA step 4.1b: select the active A/B slot (host-side).
#
# Writes a fresh otadata that selects ota_<slot>, marked Valid (so anti-rollback leaves
# it alone), then you reset. WRITE-ONLY: no flash read, no erase-region — so it works on
# hardened boards where secure-download blocks reads and esptool blocks standalone erase
# (ESP-IDF otatool.py reads the current otadata first, so it can't). See docs/formal/OTA.md.
#
#   provision/ota-switch-slot.sh --port <dev> --slot <0|1>
#
#   --port <dev>   board serial port
#   --slot <0|1>   OTA slot to boot next
#   --count <n>    number of OTA app slots (default 2)
source "$(dirname "$0")/lib.sh"

PORT="" SLOT="" COUNT=2 OTADATA_OFF=0xd000
while [ $# -gt 0 ]; do case "$1" in
  --port) PORT="$2"; shift 2;; --slot) SLOT="$2"; shift 2;; --count) COUNT="$2"; shift 2;;
  -h|--help) show_help "$0"; exit 0;;
  *) die "unknown arg: $1 (see --help)";;
esac; done
require_port "$PORT"; need esptool "brew install esptool"
[ "$SLOT" = 0 ] || [ "$SLOT" = 1 ] || die "--slot must be 0 or 1"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
IMG="$WORK/otadata.bin"
python3 - "$SLOT" "$COUNT" "$IMG" <<'PY'
import sys, struct
slot, count, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
# ESP ota_select CRC: reflected CRC-32 (poly 0xEDB88320), init 0, xorout 0xFFFFFFFF,
# over the 4-byte ota_seq only. Validated against esp-bootloader-esp-idf test vectors.
def crc(seq):
    c = 0
    for byte in struct.pack('<I', seq):
        c ^= byte
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
    return (c ^ 0xFFFFFFFF) & 0xFFFFFFFF
assert crc(1) == 0x4743989a and crc(2) == 0x55f63774, "otadata CRC mismatch"
# active = (ota_seq - 1) % count  ->  smallest seq that selects `slot` is slot+1
seq = slot + 1
VALID = 2  # OtaImageState::Valid -> anti-rollback won't revert this slot
entry = struct.pack('<I', seq) + b'\xff' * 20 + struct.pack('<I', VALID) + struct.pack('<I', crc(seq))
open(out, 'wb').write(entry + b'\xff' * (0x2000 - len(entry)))  # sector0 = entry, sector1 blank
print(f"otadata: ota_seq={seq} state=Valid crc={crc(seq):#010x} -> boots ota_{slot}")
PY

note "write otadata @ $OTADATA_OFF -> boot ota_$SLOT  (write-flash; safe on secure boards)"
esptool --chip esp32s3 --port "$PORT" write-flash "$OTADATA_OFF" "$IMG"
echo
echo "OK. Reset the board, then watch:  expect  OTA: booted from App(Ota$SLOT)"
