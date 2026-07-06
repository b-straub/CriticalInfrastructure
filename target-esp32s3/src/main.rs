#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

esp_bootloader_esp_idf::esp_app_desc!();

use embassy_executor::Spawner;
use embassy_net::{
    tcp::TcpSocket,
    Config as NetConfig, StackResources,
};
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

mod commands;
mod crypto;
mod http;
mod identity;
mod net;
mod sensor;
mod state;
mod storage;
use crate::state::*;

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
    
    let mut data = [colors::BLACK; 8];
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

    // TCP Server Loop
    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];
    
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
    
    let mut last_dht_read = 0;
    
    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));
        
        info!("HTTP listening on :8080...");
        
        let connected = loop {
            match embassy_time::with_timeout(embassy_time::Duration::from_millis(250), socket.accept(8080)).await {
                Ok(Err(e)) => {
                    info!("Accept error: {:?}", e);
                    break false;
                }
                Ok(Ok(())) => {
                    break true;
                }
                Err(_) => {
                    // Socket timeout - Idle mode (runs every 250ms)
                    let now_ms = embassy_time::Instant::now().as_millis();
                    if now_ms - last_dht_read > 2000 {
                        last_dht_read = now_ms;
                        // Read DHT11 and update display!
            let reading = sensor::read_dht11(&mut dht_pin);

            lcd.set_cursor_pos((0, 1));
            let mut status_str = heapless::String::<16>::new();
            use core::fmt::Write;
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

            } // End of 2-second DHT11 read block

            unsafe {
                let now = embassy_time::Instant::now().as_millis();
                if now < COMMAND_OVERRIDE_UNTIL {
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
            }
        };

        if !connected {
            continue;
        }
        
        info!("Accepted connection from {:?}", socket.remote_endpoint());
        let mut buf = [0; 1024];

        {
            match http::read_request(&mut socket, &mut buf).await {
                Some(http::Request::Preflight) => {
                    http::write_preflight(&mut socket).await;
                }
                Some(http::Request::Post(body)) => {
                    let payload = core::str::from_utf8(&body).unwrap_or("");
                    info!("Received payload: {}", payload);
                    
                    let mut supervisor_key = [0u8; 32];
                    if let Some(raw_hex_str) = option_env!("SUPERVISOR_PUBKEY") {
                        let hex_str = raw_hex_str.trim();
                        if hex_str.len() == 64 {
                            for i in 0..32 {
                                if let Ok(b) = u8::from_str_radix(&hex_str[i*2..i*2+2], 16) {
                                    supervisor_key[i] = b;
                                }
                            }
                        }
                    }
                    
                    let mut parts = payload.split(';');
                    let ephemeral_pub_hex = parts.next().unwrap_or("");
                    let iv_hex = parts.next().unwrap_or("");
                    let ciphertext_hex = parts.next().unwrap_or("");
                    
                    let mut valid_crypto = true;
                    let mut ephemeral_pub_bytes = [0u8; 32];
                    if ephemeral_pub_hex.len() == 64 {
                        for i in 0..32 {
                            if let Ok(b) = u8::from_str_radix(&ephemeral_pub_hex[i*2..i*2+2], 16) {
                                ephemeral_pub_bytes[i] = b;
                            } else { valid_crypto = false; }
                        }
                    } else { valid_crypto = false; }

                    let mut iv = [0u8; 12];
                    if iv_hex.len() == 24 {
                        for i in 0..12 {
                            if let Ok(b) = u8::from_str_radix(&iv_hex[i*2..i*2+2], 16) {
                                iv[i] = b;
                            } else { valid_crypto = false; }
                        }
                    } else { valid_crypto = false; }
                    
                    let mut ciphertext = heapless::Vec::<u8, 1024>::new();
                    if ciphertext_hex.len() % 2 == 0 && ciphertext_hex.len() <= 2048 {
                        for i in 0..(ciphertext_hex.len() / 2) {
                            if let Ok(b) = u8::from_str_radix(&ciphertext_hex[i*2..i*2+2], 16) {
                                let _ = ciphertext.push(b);
                            } else { valid_crypto = false; }
                        }
                    } else { valid_crypto = false; }
                    
                    let mut response_msg = "Invalid Crypto Envelope";
                    let mut dynamic_msg = heapless::String::<512>::new();
                    // Timestamp of the incoming command, echoed and signed into the
                    // response so the WebApp can bind the response to its request.
                    let mut resp_ts = heapless::String::<24>::new();
                    
                    if valid_crypto {
                        #[allow(deprecated)]
                        use aes_gcm::{Aes256Gcm, Key, Nonce};
                        #[allow(deprecated)]
                        use aes_gcm::aead::{AeadInPlace, KeyInit};
                        use sha2::{Sha256, Digest};
                        
                        let ephemeral_pub = x25519_dalek::PublicKey::from(ephemeral_pub_bytes);
                        let shared_secret = esp_x25519_secret.diffie_hellman(&ephemeral_pub);
                        
                        let tx_key_hash = Sha256::digest(shared_secret.as_bytes());
                        
                        #[allow(deprecated)]
                        let key = Key::<Aes256Gcm>::from_slice(&tx_key_hash);
                        let cipher = Aes256Gcm::new(key);
                        #[allow(deprecated)]
                        let nonce = Nonce::from_slice(&iv);
                        
                        let len = ciphertext.len();
                        if len >= 16 {
                            let (msg, tag_bytes) = ciphertext.split_at_mut(len - 16);
                            #[allow(deprecated)]
                            let tag = aes_gcm::Tag::from_slice(tag_bytes);
                            
                            #[allow(deprecated)]
                            if cipher.decrypt_in_place_detached(nonce, b"", msg, tag).is_ok() {
                                if let Ok(plaintext) = core::str::from_utf8(msg) {
                                    let mut inner_parts = plaintext.split(';');
                                    let timestamp_str = inner_parts.next().unwrap_or("");
                                    { use core::fmt::Write as _; let _ = write!(&mut resp_ts, "{}", timestamp_str); }
                                    let cmd = inner_parts.next().unwrap_or("");
                                    let sig_hex = inner_parts.next().unwrap_or("");
                                    
                                    let incoming_ts = timestamp_str.parse::<u64>().unwrap_or(0);
                                    let is_replay = unsafe { incoming_ts <= LAST_TIMESTAMP };
                                    
                                    if !is_replay {
                                        let mut sig_bytes = [0u8; 64];
                                        let mut valid_sig_format = true;
                                        if sig_hex.len() == 128 {
                                            for i in 0..64 {
                                                if let Ok(b) = u8::from_str_radix(&sig_hex[i*2..i*2+2], 16) {
                                                    sig_bytes[i] = b;
                                                } else { valid_sig_format = false; }
                                            }
                                        } else { valid_sig_format = false; }
                                        
                                        if valid_sig_format {
                                            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                                            use ed25519_dalek::Verifier;
                                            
                                            let mut role_authorized = false;
                                            let mut is_supervisor = false;
                                            let mut authenticated_role = heapless::String::<32>::new();
                                            
                                            let mut signed_payload = heapless::String::<512>::new();
                                            use core::fmt::Write;
                                            let _ = write!(&mut signed_payload, "{}|{}", timestamp_str, cmd);
                                            
                                            if let Ok(supervisor_verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&supervisor_key) {
                                                // 1. Try Supervisor Key mathematically
                                                if supervisor_verifying_key.verify(signed_payload.as_bytes(), &sig).is_ok() {
                                                    role_authorized = true;
                                                    is_supervisor = true;
                                                    let _ = core::fmt::Write::write_str(&mut authenticated_role, "Supervisor");
                                                } else {
                                                    // 2. Check dynamic roles mathematically
                                                    for entry in unsafe { &*core::ptr::addr_of!(ROLES) }.iter() {
                                                        if let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&entry.pubkey) {
                                                            if verifying_key.verify(signed_payload.as_bytes(), &sig).is_ok() {
                                                            let mut cert_msg = heapless::String::<128>::new();
                                                            use core::fmt::Write;
                                                            let mut pk_hex = heapless::String::<64>::new();
                                                            for b in entry.pubkey {
                                                                let _ = write!(&mut pk_hex, "{:02x}", b);
                                                            }
                                                            let _ = write!(&mut cert_msg, "ROLE:{};PUBKEY:{}", entry.name, pk_hex);
                                                            
                                                            let mut sig_arr = [0u8; 64];
                                                            sig_arr.copy_from_slice(&entry.cert_sig);
                                                            let cert_sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                                                            
                                                            if supervisor_verifying_key.verify(cert_msg.as_bytes(), &cert_sig).is_ok() {
                                                                role_authorized = true;
                                                                let _ = write!(&mut authenticated_role, "{}", entry.name);
                                                                break;
                                                            } else {
                                                                info!("RAM Tampering Detected for role {}!", entry.name);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        
                                        if role_authorized {
                                            let role = &authenticated_role;
                                            info!("Authenticated Command: {} (Role: {})", cmd, role);
                                            
                                            let outcome = commands::dispatch(cmd, role, is_supervisor, &mut parts, &mut dynamic_msg);
                                            let allowed = outcome.allowed;
                                            let color_name = outcome.color_name;
                                            response_msg = outcome.response_msg;
                                                    
                                                    lcd.set_cursor_pos((0, 1));
                                                    let mut status_str = heapless::String::<16>::new();
                                                    use core::fmt::Write;
                                                    
                                                    if allowed {
                                                        unsafe { LAST_TIMESTAMP = incoming_ts; }
                                                        if response_msg == "Invalid Crypto Envelope" {
                                                            response_msg = "Command Executed. (Sensors visible on local display)";
                                                        }
                                                        let _ = write!(&mut status_str, "{:<6} Pass   ", color_name);
                                                        lcd.write_str_to_cur(&status_str);
                                                        
                                                        if cmd.starts_with(CMD_COLOR_RED) || cmd.starts_with(CMD_CLEAR_ALARM) {
                                                            data = [colors::RED; 8];
                                                        } else if cmd.starts_with(CMD_COLOR_YELLOW) || cmd.starts_with(CMD_SET_THRESHOLD) {
                                                            data = [colors::YELLOW; 8];
                                                        } else if cmd.starts_with(CMD_COLOR_GREEN) || cmd.starts_with(CMD_READ_SENSOR) {
                                                            data = [colors::GREEN; 8];
                                                        } else if cmd.starts_with(CMD_ADD_ROLE) || cmd.starts_with(CMD_REVOKE_ROLE) || cmd.starts_with(CMD_LIST_ROLES) || cmd.starts_with(CMD_WHOAMI) {
                                                            data = [colors::BLUE; 8]; // Blue for system actions
                                                        } else {
                                                            data = [colors::WHITE; 8];
                                                        }
                                                        ws2812.write(data.iter().cloned()).unwrap();
                                                        
                                                        unsafe {
                                                            COMMAND_OVERRIDE_COLOR = data;
                                                            COMMAND_OVERRIDE_UNTIL = embassy_time::Instant::now().as_millis() + shared::terminology::COMMAND_LED_TIMEOUT_MS;
                                                        }
                                                    } else {
                                                        if response_msg == "Invalid Crypto Envelope" {
                                                            response_msg = "Permission Denied";
                                                        }
                                                        let _ = write!(&mut status_str, "{:<6} Reject ", color_name);
                                                        lcd.write_str_to_cur(&status_str);
                                                    }
                                        } else {
                                            response_msg = "Signature verification failed or Unknown Role";
                                        }
                                        } else {
                                            response_msg = "Invalid Signature Format";
                                        }
                                    } else {
                                        response_msg = "Replay Attack Detected";
                                    }
                                } else {
                                    response_msg = "Invalid UTF-8 in payload";
                                }
                            } else {
                                response_msg = "Decryption Failed";
                            }
                        } else {
                            response_msg = "Payload too short";
                        }
                    }
                    
                    // Build, sign, and encrypt the response (see crypto.rs).
                    let mut resp_message = heapless::String::<512>::new();
                    {
                        use core::fmt::Write as _;
                        if !dynamic_msg.is_empty() {
                            let _ = write!(&mut resp_message, "{}", dynamic_msg);
                        } else {
                            let _ = write!(&mut resp_message, "{}", response_msg);
                        }
                    }
                    let final_response = crypto::build_signed_response(
                        &resp_ts,
                        &resp_message,
                        &esp_signing_key,
                        &ephemeral_pub_bytes,
                        &mut rng,
                    );

                    http::write_response(&mut socket, &final_response).await;
                }
                _ => {}
            }
        }
        socket.close();
    }
}
