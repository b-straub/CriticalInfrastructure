//! BLE GATT transport — carries the SAME command envelope as the UDP path over a Bluetooth LE
//! GATT link, so the device is controllable without Wi-Fi/LAN (commissioning, network-down, iOS
//! without a network). In a hybrid build (both `udp-transport` + `ble-transport`) a physical
//! switch on GPIO10 (LOW = BLE, active-low pull-up) selects this path over UDP at boot; only one
//! radio runs (no coex), which keeps it robust and lets a hybrid image deploy to a sealed board
//! via OTA.
//!
//! The security boundary is the app-layer envelope (X25519 + AES-GCM + P-256/Ed25519), so the
//! BLE link itself needs no pairing/bonding — a "just works" connection is fine; bad envelopes
//! are rejected by `process_envelope` exactly as over UDP.
//!
//! Wire framing mirrors the UDP path so the Swift `ChunkAssembler` is reused unchanged:
//! each GATT packet is `[total: u8][seq: u8][payload…]`, payload ≤ `MAX_CHUNK`. Requests arrive
//! chunked on the `rx` (write) characteristic; responses are chunked out on `tx` (notify).

use bt_hci::controller::ExternalController;
use embassy_futures::join::join;
use ed25519_dalek::SigningKey;
use esp_hal::rng::Rng;
use esp_radio::ble::controller::BleConnector;

use log::info;
use trouble_host::prelude::*;
use x25519_dalek::StaticSecret;

/// Max application payload per BLE frame (frame = 2 header + payload ≤ char size ~244).
const MAX_CHUNK: usize = 240;
/// Characteristic value capacity (frame max = MAX_CHUNK + 2).
const CHAR_CAP: usize = MAX_CHUNK + 2;
/// Largest reassembled request we accept.
const MAX_REQ: usize = 1024;

// heapless 0.9 (aliased): trouble's AsGatt/FromGatt impls are for its own heapless generation.
type Frame = heapless_v09::Vec<u8, CHAR_CAP>;

#[gatt_server]
struct Server {
    control: ControlService,
}

// Vendor service; rx = client→device (write), tx = device→client (notify).
#[gatt_service(uuid = "9e7312e0-2354-11eb-9f10-fbc30a62cf38")]
struct ControlService {
    #[characteristic(uuid = "9e7312e0-2354-11eb-9f10-fbc30a62cf39", write)]
    rx: Frame,
    #[characteristic(uuid = "9e7312e0-2354-11eb-9f10-fbc30a62cf3a", read, notify)]
    tx: Frame,
}

/// Never returns — runs the BLE host + GATT server forever. Also drives the LCD (line 1 = BLE
/// status since there is no IP in BLE mode; line 2 = firmware build tag).
#[embassy_executor::task]
pub async fn ble_task(
    connector: BleConnector<'static>,
    esp_x25519_secret: StaticSecret,
    esp_signing_key: SigningKey,
    mut rng: Rng,
) -> ! {
    // Mirrors the upstream trouble-host bas_peripheral example (esp-radio 0.18) with the GATT
    // service swapped for the command-envelope transport. Deliberately minimal — no LCD/I2C, no
    // flash reads; restore the LCD + role/threshold load once BLE is confirmed on hardware.
    info!("BLE min 2: ExternalController::new");
    let controller: ExternalController<_, 20> = ExternalController::new(connector);
    info!("BLE min 3: HostResources::new");
    let mut resources: HostResources<DefaultPacketPool, 1, 2> = HostResources::new();
    info!("BLE min 4: trouble_host::new + stack.build");
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random([0xff, 0x11, 0x22, 0x33, 0x44, 0xff]));
    let Host { mut peripheral, runner, .. } = stack.build();
    info!("BLE min 5: Server::new_with_config");
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "CriticalInfra",
        appearance: &appearance::UNKNOWN,
    }))
    .unwrap();
    info!("BLE min 6: join(run_host, app) -> advertising");

    let app = async {
        loop {
            info!("BLE app: advertising...");
            match advertise(&mut peripheral, &server).await {
                Ok(conn) => {
                    info!("BLE connected");
                    serve(&server, &conn, &esp_x25519_secret, &esp_signing_key, &mut rng).await;
                }
                Err(e) => info!("BLE advertise error: {:?}", e),
            }
        }
    };
    join(run_host(runner), app).await;
    loop {}
}

async fn run_host<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) {
    info!("BLE host: runner.run() starting");
    if let Err(e) = runner.run().await {
        info!("BLE host runner exited: {:?}", e);
    }
}

async fn advertise<'a, 'b, C: Controller>(
    peripheral: &mut Peripheral<'a, C, DefaultPacketPool>,
    server: &'b Server<'_>,
) -> Result<GattConnection<'a, 'b, DefaultPacketPool>, BleHostError<C::Error>> {
    let mut adv_data = [0u8; 31];
    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteLocalName(b"CriticalInfra"),
        ],
        &mut adv_data[..],
    )?;
    let advertiser = peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data[..len],
                scan_data: &[],
            },
        )
        .await?;
    let conn = advertiser.accept().await?;
    info!("BLE connected");
    conn.with_attribute_server(server)
        .map_err(BleHostError::from)
}

/// Handle one connection: reassemble request chunks, run `process_envelope`, chunk the reply back.
async fn serve(
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    esp_x25519_secret: &StaticSecret,
    esp_signing_key: &SigningKey,
    rng: &mut Rng,
) {
    let mut req = heapless::Vec::<u8, MAX_REQ>::new();
    let mut want: u8 = 0; // chunks still expected in the current request (0 = idle)
    loop {
        match conn.next().await {
            GattConnectionEvent::Disconnected { .. } => {
                info!("BLE disconnected");
                break;
            }
            GattConnectionEvent::Gatt { event } => {
                let mut complete = false;
                if let GattEvent::Write(w) = &event {
                    if w.handle() == server.control.rx.handle {
                        complete = accept_chunk(w.data(), &mut req, &mut want);
                    }
                }
                let _ = event.accept().map(|r| r.send());
                if complete {
                    respond(server, conn, &req, esp_x25519_secret, esp_signing_key, rng).await;
                    req.clear();
                    want = 0;
                }
            }
            _ => {}
        }
    }
}

/// Append a `[total][seq][payload]` frame to the request buffer. Returns true when the last chunk
/// of the request has arrived. Resets on `seq == 0` (start of a fresh request).
fn accept_chunk(frame: &[u8], req: &mut heapless::Vec<u8, MAX_REQ>, want: &mut u8) -> bool {
    if frame.len() < 2 {
        return false;
    }
    let total = frame[0];
    let seq = frame[1];
    let payload = &frame[2..];
    if seq == 0 {
        req.clear();
        *want = total;
    }
    let _ = req.extend_from_slice(payload);
    if *want > 0 {
        *want -= 1;
    }
    *want == 0 && total > 0
}

async fn respond(
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    req: &[u8],
    esp_x25519_secret: &StaticSecret,
    esp_signing_key: &SigningKey,
    rng: &mut Rng,
) {
    let payload = core::str::from_utf8(req).unwrap_or("");
    let result = crate::protocol::process_envelope(payload, esp_x25519_secret, esp_signing_key, rng);
    // The BLE spike has no LCD/LED; the command still executes and returns a signed reply. The
    // led/status_line side-effects (rendered over UDP) are intentionally ignored here.
    let _ = (&result.led, &result.status_line);
    let bytes = result.response.as_bytes();
    let total = bytes.len().div_ceil(MAX_CHUNK).max(1);
    for (seq, chunk) in bytes.chunks(MAX_CHUNK).enumerate() {
        let mut frame = Frame::new();
        let _ = frame.push(total as u8);
        let _ = frame.push(seq as u8);
        let _ = frame.extend_from_slice(chunk);
        if let Err(e) = server.control.tx.notify(conn, &frame).await {
            info!("BLE notify error on chunk {}/{}: {:?}", seq + 1, total, e);
            break;
        }
    }
}
