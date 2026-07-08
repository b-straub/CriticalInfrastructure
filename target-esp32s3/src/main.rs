#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

esp_bootloader_esp_idf::esp_app_desc!();

use embassy_executor::Spawner;
use embassy_net::{Config as NetConfig, StackResources};
use embassy_time::{Duration, Timer};
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    rng::Rng,
    spi::{
        master::{Config as SpiConfig, Spi},
        Mode,
    },
    timer::timg::TimerGroup,
};
use log::info;
use smart_leds::{colors, SmartLedsWrite};
use ws2812_spi::Ws2812;
use static_cell::StaticCell;
use shared::terminology::*;

mod clientauth;
mod commands;
mod crypto;
#[cfg(feature = "http-transport")]
mod http;
mod identity;
mod net;
mod protocol;
mod sensor;
mod state;
mod storage;
use crate::state::*;

// Exactly one transport flavor per ROM (see Cargo.toml / UDP-TRANSPORT.md).
#[cfg(all(feature = "http-transport", feature = "udp-transport"))]
compile_error!("enable exactly one transport: `http-transport` OR `udp-transport`");
#[cfg(not(any(feature = "http-transport", feature = "udp-transport")))]
compile_error!("enable one transport: `http-transport` (default) or `udp-transport`");

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger_from_env();
    info!("Starting...");
    if let Some(raw_hex_str) = option_env!("SUPERVISOR_PUBKEY") {
        let hex_str = raw_hex_str.trim();
        info!("SSOT Supervisor PubKey ({} chars): {}", hex_str.len(), hex_str);
    } else {
        info!("WARNING: No SUPERVISOR_PUBKEY found at compile time! Crypto will default to zeros.");
    }

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_hal_embassy::init(timg0.timer0);

    esp_alloc::heap_allocator!(size: 72 * 1024);

    let timg1 = TimerGroup::new(peripherals.TIMG1);
    let mut rng = Rng::new(peripherals.RNG);

    // Device identity (X25519 for the command envelope, Ed25519 for signing
    // responses). The two provisioning paths live in `identity.rs`.
    #[cfg(feature = "efuse-hmac-identity")]
    let (esp_x25519_secret, esp_signing_key) =
        identity::derive_identity(peripherals.SHA, peripherals.HMAC);
    #[cfg(not(feature = "efuse-hmac-identity"))]
    let (esp_x25519_secret, esp_signing_key) = identity::derive_identity(&mut rng);

    // We can still pass rng to esp_wifi because we didn't consume it
    let init = static_cell::make_static!(esp_wifi::init(timg1.timer0, rng).unwrap());

    let (mut _controller, interfaces) =
        esp_wifi::wifi::new(init, peripherals.WIFI).unwrap();
    let wifi_interface = interfaces.sta;

    let spi_config = SpiConfig::default().with_frequency(esp_hal::time::Rate::from_mhz(3)).with_mode(Mode::_0);
    let spi = Spi::new(peripherals.SPI2, spi_config).expect("SPI new failed")
        .with_mosi(peripherals.GPIO4);
    let mut ws2812 = Ws2812::new(spi);

    let data = [colors::BLACK; 8];
    ws2812.write(data.iter().cloned()).unwrap();

    use esp_hal::i2c::master::{I2c, Config as I2cConfig};
    use lcd1602_driver::lcd::{Lcd, Basic, Ext};
    use lcd1602_driver::sender::I2cSender;

    let mut i2c = I2c::new(peripherals.I2C0, I2cConfig::default())
        .expect("I2C new failed")
        .with_sda(peripherals.GPIO8)
        .with_scl(peripherals.GPIO9);

    let mut delay = esp_hal::delay::Delay::new();

    // Robust LCD reset BEFORE the driver init. A warm flash resets the ESP but
    // not the LCD, which can be left mid-command in 4-bit mode. The lcd1602
    // driver assumes a cold 8-bit start and only switches to 4-bit once, so it
    // desyncs and prints garbage after a flash. Per the HD44780 datasheet,
    // strobe the 0x3 reset nibble three times on the PCF8574 backpack
    // (P4-7 = data, P3 = backlight, P2 = Enable) to force the controller back to
    // 8-bit; the driver's normal init then switches it to 4-bit cleanly.
    delay.delay_millis(100);
    for wait_us in [4500u32, 200, 200] {
        let _ = i2c.write(0x27u8, &[0x3Cu8]); // nibble 0x3, backlight on, Enable high
        delay.delay_micros(1);
        let _ = i2c.write(0x27u8, &[0x38u8]); // Enable low -> latch
        delay.delay_micros(wait_us);
    }
    delay.delay_millis(5);

    let mut sender = I2cSender::new(&mut i2c, 0x27);
    let mut lcd = Lcd::new(&mut sender, &mut delay, Default::default(), Default::default());

    // Set up GPIO21 for DHT11 data line
    use esp_hal::gpio::Flex;
    let mut dht_pin = Flex::new(peripherals.GPIO21);

    lcd.clean_display();
    lcd.write_str_to_cur("Init Network...");

    let net_config = NetConfig::dhcpv4(Default::default());

    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(
        wifi_interface,
        net_config,
        RESOURCES.init(StackResources::<3>::new()),
        1234, // Random seed
    );

    spawner.spawn(net::connection(_controller)).unwrap();
    spawner.spawn(net::net_task(runner)).unwrap();

    if let Some(saved_roles) = storage::load_roles() {
        unsafe {
            ROLES = saved_roles;
        }
        info!("Loaded roles from flash");
    }

    // Load the persisted alarm threshold (falls back to the compiled default if
    // never written / flash erased).
    if let Some(stored) = storage::load_threshold() {
        unsafe {
            THRESHOLD = stored;
        }
        info!("Loaded threshold from flash: {:.1}C", stored);
    }


    loop {
        if stack.is_link_up() {
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    info!("Waiting to get IP address...");
    loop {
        if let Some(config) = stack.config_v4() {
            info!("Got IP: {}", config.address);
            lcd.clean_display();
            lcd.set_cursor_pos((0, 0));

            let mut ip_str = heapless::String::<32>::new();
            use core::fmt::Write;
            write!(&mut ip_str, "{}", config.address).unwrap();

            // split CIDR mask (e.g. 192.168.1.100/24 -> 192.168.1.100)
            let ip_only = ip_str.split('/').next().unwrap_or(&ip_str);
            lcd.write_str_to_cur(ip_only);

            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    let mut last_dht_read = 0u64;

    // Single owner of the LCD status line + LED ring, driven either by the idle
    // tick or by a processed command. A closure (not a fn) so both serve loops
    // share it without having to name the concrete LCD/LED driver types.
    enum Render<'a> {
        Idle,
        Command(&'a protocol::ProcessResult),
    }
    let mut render = |ev: Render| {
        use core::fmt::Write as _;
        match ev {
            Render::Idle => {
                let now_ms = embassy_time::Instant::now().as_millis();
                if now_ms - last_dht_read > 2000 {
                    last_dht_read = now_ms;
                    let reading = sensor::read_dht11(&mut dht_pin);
                    lcd.set_cursor_pos((0, 1));
                    let mut status_str = heapless::String::<16>::new();
                    if let Some((temp, hum)) = reading {
                        let _ = write!(&mut status_str, "{:.1}C {:.0}% RH  ", temp, hum);
                        unsafe {
                            LAST_TEMP = temp;
                            LAST_RH = hum;
                            if temp > THRESHOLD {
                                ALARM_ACTIVE = true;
                            }
                        }
                    } else {
                        let _ = write!(&mut status_str, "Sensor Error    ");
                    }
                    lcd.write_str_to_cur(&status_str);
                }

                unsafe {
                    let now = embassy_time::Instant::now().as_millis();
                    if now < COMMAND_OVERRIDE_UNTIL {
                        // Copy out of the mutable static before borrowing it for
                        // the iterator (avoids a reference to a `static mut`).
                        let color_copy = COMMAND_OVERRIDE_COLOR;
                        ws2812.write(color_copy.iter().cloned()).unwrap();
                    } else if ALARM_ACTIVE {
                        if (now / 250) % 2 == 0 {
                            ws2812.write([colors::RED; 8].iter().cloned()).unwrap();
                        } else {
                            ws2812.write([colors::BLACK; 8].iter().cloned()).unwrap();
                        }
                    } else {
                        ws2812.write([colors::BLACK; 8].iter().cloned()).unwrap();
                    }
                }
            }
            Render::Command(r) => {
                if let Some(line) = &r.status_line {
                    lcd.set_cursor_pos((0, 1));
                    lcd.write_str_to_cur(line);
                }
                if let Some(color) = r.led {
                    ws2812.write(color.iter().cloned()).unwrap();
                }
            }
        }
    };

    // ---- HTTP flavor: one browser-reachable TCP connection at a time --------
    #[cfg(feature = "http-transport")]
    {
        let mut rx_buffer = [0; 4096];
        let mut tx_buffer = [0; 4096];

        loop {
            let mut socket =
                embassy_net::tcp::TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
            socket.set_timeout(Some(Duration::from_secs(10)));

            info!("HTTP listening on :{}...", SUPERVISOR_PORT);

            // Keep the accept future ALIVE across idle ticks (pinned + select) so
            // the socket never stops listening. A browser SYN that lands while
            // accept is dropped/re-armed would be lost; here the task stays parked
            // in accept() and the idle sensor/LED runs on the timer branch.
            let connected = {
                let mut accept = core::pin::pin!(socket.accept(SUPERVISOR_PORT));
                loop {
                    use embassy_futures::select::{select, Either};
                    match select(
                        accept.as_mut(),
                        Timer::after(Duration::from_millis(250)),
                    )
                    .await
                    {
                        Either::First(Ok(())) => break true,
                        Either::First(Err(e)) => {
                            info!("Accept error: {:?}", e);
                            break false;
                        }
                        Either::Second(_) => render(Render::Idle),
                    }
                }
            };

            if !connected {
                continue;
            }

            info!("Accepted connection from {:?}", socket.remote_endpoint());
            let mut buf = [0; 1024];

            match http::read_request(&mut socket, &mut buf).await {
                Some(http::Request::Preflight) => {
                    http::write_preflight(&mut socket).await;
                }
                Some(http::Request::Post(body)) => {
                    let payload = core::str::from_utf8(&body).unwrap_or("");
                    info!("Received payload: {}", payload);
                    let result = protocol::process_envelope(
                        payload,
                        &esp_x25519_secret,
                        &esp_signing_key,
                        &mut rng,
                    );
                    render(Render::Command(&result));
                    http::write_response(&mut socket, &result.response).await;
                }
                _ => {}
            }
            socket.close();
        }
    }

    // ---- UDP flavor: connectionless datagrams for native clients -----------
    #[cfg(feature = "udp-transport")]
    {
        use embassy_net::udp::{PacketMetadata, UdpSocket};

        let mut rx_meta = [PacketMetadata::EMPTY; 8];
        let mut rx_buffer = [0; 4096];
        let mut tx_meta = [PacketMetadata::EMPTY; 8];
        let mut tx_buffer = [0; 4096];
        let mut socket = UdpSocket::new(
            stack,
            &mut rx_meta,
            &mut rx_buffer,
            &mut tx_meta,
            &mut tx_buffer,
        );
        socket.bind(SUPERVISOR_PORT).unwrap();
        info!("UDP listening on :{}...", SUPERVISOR_PORT);

        // Replies are framed as 1+ chunks of `[total][seq][payload]`, so a reply
        // larger than one datagram (e.g. a many-role LIST_ROLES) still arrives:
        // smoltcp does not IPv4-TX-fragment, so we fragment at the app layer and
        // the client reassembles by `seq`. See docs/formal/UDP-TRANSPORT.md sec. 2.3.
        const UDP_CHUNK_PAYLOAD: usize = 1024;
        const UDP_FRAME_MAX: usize = UDP_CHUNK_PAYLOAD + 2;

        let mut buf = [0u8; 2048];
        loop {
            // One datagram = one command. The idle sensor/LED runs on the 250ms
            // timer branch while recv_from stays parked (same shape as the HTTP
            // accept loop above).
            let received = {
                let mut recv = core::pin::pin!(socket.recv_from(&mut buf));
                use embassy_futures::select::{select, Either};
                match select(recv.as_mut(), Timer::after(Duration::from_millis(250))).await {
                    Either::First(Ok((n, meta))) => Some((n, meta.endpoint)),
                    Either::First(Err(e)) => {
                        info!("UDP recv error: {:?}", e);
                        None
                    }
                    Either::Second(_) => {
                        render(Render::Idle);
                        None
                    }
                }
            };

            if let Some((n, endpoint)) = received {
                let payload = core::str::from_utf8(&buf[..n]).unwrap_or("");
                info!("Received datagram ({} bytes) from {:?}", n, endpoint);
                let result = protocol::process_envelope(
                    payload,
                    &esp_x25519_secret,
                    &esp_signing_key,
                    &mut rng,
                );
                render(Render::Command(&result));
                // Send the reply as 1+ framed chunks (see the const comment
                // above); the client reassembles by `seq` until it has `total`.
                let bytes = result.response.as_bytes();
                let total = bytes.len().div_ceil(UDP_CHUNK_PAYLOAD).max(1);
                for (seq, chunk) in bytes.chunks(UDP_CHUNK_PAYLOAD).enumerate() {
                    let mut frame = heapless::Vec::<u8, UDP_FRAME_MAX>::new();
                    let _ = frame.push(total as u8);
                    let _ = frame.push(seq as u8);
                    let _ = frame.extend_from_slice(chunk);
                    if let Err(e) = socket.send_to(&frame, endpoint).await {
                        info!("UDP send error on chunk {}/{}: {:?}", seq + 1, total, e);
                        break;
                    }
                }
            }
        }
    }
}
