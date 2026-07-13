# BLE Transport — GATT Second Path (implemented & hardware-verified 2026-07-13)

The device speaks the **same signed command envelope** as the UDP path over a Bluetooth LE
GATT link, so it is controllable with no Wi-Fi/LAN at all — commissioning, network-down
operation, or an iOS client without Local Network access. The security boundary is the
app-layer envelope (X25519 + AES-GCM + P-256/Ed25519, see
[`UDP-TRANSPORT.md`](UDP-TRANSPORT.md) §1); the BLE link itself needs **no pairing/bonding**
— bad envelopes are rejected by `process_envelope` exactly as over UDP.

Verified end-to-end on the sealed reference board (Secure Boot v2 + flash encryption +
eFuse-hardened): discovery, connection, authenticated Admin commands (`READ_SENSOR`,
`COLOR`, `CLEAR_ALARM`), chunked replies, LCD/LED parity.

## 1. Transport select — one radio at a time (no coex)

A hybrid image (`udp-transport` + `ble-transport` cargo features) contains both stacks; a
**physical switch on GPIO10** picks exactly one radio at boot:

| GPIO10 (internal pull-up, active-low) | Mode |
| --- | --- |
| open → HIGH | **UDP/Wi-Fi only** (and this is the only mode that can receive OTA) |
| closed to GND → LOW | **BLE only** |

Wi-Fi/BLE coexistence is deliberately not used — one radio keeps timing simple and robust.
Consequence: **OTA updates always require the switch on UDP** and a reset first.

A pure BLE build (`--no-default-features --features ble-transport`) links no Wi-Fi at all,
but then has **no OTA path** — never deploy that to a sealed board.

## 2. Advertisement

CoreBluetooth clients discover by **service UUID filter** (`scanForPeripherals(withServices:)`),
which only matches UUIDs present in the advertisement. Flags (3 B) + one 128-bit UUID (18 B)
fill the 31-byte ADV payload, so the name moves to the **scan response**; scanners merge both.

| Packet | AD structures |
| --- | --- |
| ADV_IND | Flags (LE General Discoverable, BR/EDR not supported) + `ServiceUuids128` = service UUID |
| SCAN_RSP | `CompleteLocalName` = `CriticalInfra` |

The advertising address is a **static random address** — the spec requires the two most
significant bits set, and Apple's stack silently drops advertisements with malformed random
addresses (`[0xff, .., 0xff]` keeps it valid regardless of byte-order convention).

## 3. GATT service

Vendor service (matches `DeviceConfig.bleServiceUUID` in the Swift client):

| UUID | Role |
| --- | --- |
| `9e7312e0-2354-11eb-9f10-fbc30a62cf38` | Control service |
| `…cf39` | `rx` — client → device, **write** |
| `…cf3a` | `tx` — device → client, **read + notify** |

Framing mirrors the UDP path (§2.3 there) so the Swift `ChunkAssembler` is reused unchanged:
each GATT packet is `[total: u8][seq: u8][payload…]` with payload ≤ `MAX_CHUNK = 240` bytes.
Requests arrive chunked on `rx` (reset on `seq == 0`, complete after `total` chunks, max
reassembled request 1024 B); responses are chunked out as `tx` notifications the same way.
One request/response exchange at a time (the Swift `DeviceClient` actor serializes).

## 4. Runtime behavior (parity with UDP mode)

Persisted state is transport-independent and loaded **before** the transport split: the
role table and alarm threshold from flash apply identically over BLE (a granted client
identity resolves to the same role).

- **LCD line 1**: BLE link status — `BLE starting…` / `BLE advertising` / `BLE connected`
  (published by the BLE task via an atomic; the display loop runs in `main`).
- **LCD line 2**: `{temp}C {rh}%H {fw-tag}` — DHT11 read every 2 s, same format as UDP mode.
  Each reading is published to the shared state, so `READ_SENSOR` returns live values and
  the alarm threshold is evaluated in BLE mode too.
- **LED ring**: same semantics as the UDP idle render at the same 250 ms cadence — a
  command color override (set by `protocol.rs`, transport-independent) wins, then the red
  alarm blink, else off.

## 5. Firmware stack & version coupling

| Crate | Version | Note |
| --- | --- | --- |
| esp-hal | 1.1.1 | `unstable` feature required by esp-radio |
| esp-radio | 0.18 | `ble` (+ `wifi` in hybrid), `unstable` |
| esp-rtos | 0.3 | replaces esp-hal-embassy **and** the old radio scheduler; `esp-radio` + `embassy` features |
| trouble-host | 0.6 | the release built against bt-hci 0.8 (0.7 needs bt-hci 0.9) |
| bt-hci | 0.8 | must match what esp-radio's `BleConnector` implements |
| embassy-sync | 0.7 | what trouble 0.6's GATT macros expand to |
| heapless | 0.9 (aliased `heapless-v09`) | trouble's `AsGatt` impls are for its own heapless generation |

**Bump these together.** The historical pin comment lives in `target-esp32s3/Cargo.toml`.

### Why not esp-wifi 0.15.1 (the original attempt)

BLE on the ESP32-S3 deadlocked forever in `btdm_controller_enable`: the BT controller
blob's init handshake relies on scheduling semantics that esp-wifi 0.15.1's poll-and-yield
compat layer never satisfied — the `btController` task parked on a semaphore nothing gave,
init's ack wait timed out (blob returns 0 anyway), and enable blocked forever. Upstream
rewrote that entire layer after 0.15.1 (esp-rtos priority scheduler + real blocking
primitives); on esp-radio the same blob initializes immediately. Not fixable app-side —
don't try to revive the old stack.

## 6. Operational constraints (hard-won, do not regress)

1. **The radio needs a quiet console.** Trace/debug-level logging in BLE mode delays the
   BT controller task behind blocking 115200-baud UART writes past its radio deadlines:
   the host stack reports advertising success while **nothing is emitted on air**. The
   same flood in Wi-Fi mode cripples DHCP/OTA. Ship Info-level logging; scope `ESP_LOG`
   narrowly only while hunting a specific bug, and expect the radio to be degraded then.
   (`ESP_LOG` is a **compile-time** filter baked by esp-println — the runtime logger can
   only lower it. Default lives in `target-esp32s3/.cargo/config.toml`.)
2. **OTA only in UDP mode** (see §1). After a BLE session, flip the switch back.
3. Serial monitoring on the sealed board: use the CH343 UART port (right-hand USB on the
   Freenove board) with a dumb tty reader — `cargo espflash monitor` fails in Secure
   Download Mode, and the native USB-Serial-JTAG console can die during radio bring-up.

## 7. Client (Swift)

`BleTransport.swift` implements `DeviceTransport` over CoreBluetooth: UUID-filtered scan,
connect, subscribe to `tx`, chunked write to `rx`, reassemble notifications. The app's
Settings has a **Transport** picker (Wi-Fi (UDP) / Bluetooth (BLE)); device keys, client
identities, and roles are shared between transports. First BLE use prompts for macOS/iOS
Bluetooth permission.
