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
use esp_wifi::wifi::{
    ClientConfiguration, Configuration, WifiController, WifiDevice, WifiEvent, WifiState,
};
use log::info;
use smart_leds::{colors, SmartLedsWrite};
use ws2812_spi::Ws2812;
use static_cell::StaticCell;
use serde::{Serialize, Deserialize};
use shared::terminology::*;
use embedded_storage::{ReadStorage, Storage};
use esp_storage::FlashStorage;

static mut LAST_TIMESTAMP: u64 = 0;

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    info!("wifi connection task starting");
    loop {
        if esp_wifi::wifi::wifi_state() == WifiState::StaConnected {
            controller.wait_for_event(WifiEvent::StaDisconnected).await;
            Timer::after(Duration::from_millis(5000)).await;
        }
        
        if !matches!(controller.is_started(), Ok(true)) {
            let client_config = Configuration::Client(ClientConfiguration {
                ssid: option_env!("WIFI_SSID").unwrap_or("YOUR_SSID").try_into().unwrap(),
                password: option_env!("WIFI_PASS").unwrap_or("YOUR_PASSWORD").try_into().unwrap(),
                ..Default::default()
            });
            controller.set_configuration(&client_config).unwrap();
            controller.start_async().await.unwrap();
            info!("WiFi started");
        }
        info!("Connecting...");
        
        match controller.connect_async().await {
            Ok(_) => info!("Wifi connected!"),
            Err(e) => {
                info!("Failed to connect to wifi: {:?}", e);
                Timer::after(Duration::from_millis(5000)).await;
            }
        }
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}

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
    
    let mut flash = FlashStorage::new();
    let mut seed_buf = [0u8; 4096];
    let mut esp_seed = [0u8; 32];
    let mut has_seed = false;
    
    if flash.read(0x210000, &mut seed_buf).is_ok() {
        let is_empty = seed_buf[0..32].iter().all(|&b| b == 0xFF || b == 0x00);
        if !is_empty {
            esp_seed.copy_from_slice(&seed_buf[0..32]);
            has_seed = true;
        }
    }
    
    if !has_seed {
        for chunk in esp_seed.chunks_mut(4) {
            let rand_val = rng.random();
            chunk.copy_from_slice(&rand_val.to_le_bytes());
        }
        let mut write_buf = [0u8; 4096];
        write_buf[0..32].copy_from_slice(&esp_seed);
        let _ = flash.write(0x210000, &write_buf);
    }
    
    let esp_x25519_secret = x25519_dalek::StaticSecret::from(esp_seed);
    let esp_x25519_pub = x25519_dalek::PublicKey::from(&esp_x25519_secret);
    
    let mut hex_x25519 = heapless::String::<64>::new();
    use core::fmt::Write;
    for b in esp_x25519_pub.as_bytes() { let _ = write!(&mut hex_x25519, "{:02x}", b); }
    info!("ESP32 X25519 PubKey: {}", hex_x25519);
    
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
    
    let mut sender = I2cSender::new(&mut i2c, 0x27);
    let mut delay = esp_hal::delay::Delay::new();
    
    // Delay 500ms before initializing the LCD. During a warm flash (without power cycling),
    // the HD44780 controller can be left in a weird state. Giving it time and allowing
    // the driver to send a clean init sequence fixes "bogus" characters on reboot.
    delay.delay_millis(500);
    
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

    spawner.spawn(connection(_controller)).unwrap();
    spawner.spawn(net_task(runner)).unwrap();

    // TCP Server Loop
    let mut rx_buffer = [0; 4096];
    
#[derive(Clone, Serialize, Deserialize)]
struct RoleEntry {
    name: heapless::String<16>,
    pubkey: [u8; 32],
    cert_sig: heapless::Vec<u8, 64>,
}
static mut ROLES: heapless::Vec<RoleEntry, 10> = heapless::Vec::new();

    let mut tx_buffer = [0; 4096];
    
    let mut flash = FlashStorage::new();
    let mut flash_buf = [0u8; 4096];
    if flash.read(0x200000, &mut flash_buf).is_ok() {
        if let Ok(saved_roles) = postcard::from_bytes::<heapless::Vec<RoleEntry, 10>>(&flash_buf) {
            unsafe {
                ROLES = saved_roles;
            }
            info!("Loaded roles from flash");
        }
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
    
    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));
        
        info!("Listening on TCP:8080...");
        
        let connected = loop {
            match embassy_time::with_timeout(embassy_time::Duration::from_secs(3), socket.accept(8080)).await {
                Ok(Err(e)) => {
                    info!("Accept error: {:?}", e);
                    break false;
                }
                Ok(Ok(())) => {
                    break true;
                }
                Err(_) => {
                    // Socket timeout - Idle mode
                    // Read DHT11 and update display!
            let mut temp = 24.5;
            let mut hum = 45.0;
            
            let dht_delay = esp_hal::delay::Delay::new();
            dht_pin.set_output_enable(true);
            dht_pin.set_low();
            dht_delay.delay_millis(20);
            // Let the external pull-up pull the line HIGH! Don't drive it HIGH actively.
            dht_pin.set_output_enable(false);
            dht_pin.set_input_enable(true);
            
            let mut success = true;
            let mut data = [0u8; 5];
            
            critical_section::with(|_| {
                macro_rules! wait_pulse {
                    ($state:expr) => {{
                        let start = embassy_time::Instant::now();
                        let mut res = None;
                        while start.elapsed().as_micros() < 200 {
                            if dht_pin.is_high() != $state {
                                res = Some(start.elapsed().as_micros());
                                break;
                            }
                        }
                        res
                    }};
                }

                if wait_pulse!(true).is_none() { success = false; }
                if wait_pulse!(false).is_none() { success = false; }
                if wait_pulse!(true).is_none() { success = false; }
                
                if success {
                    for i in 0..40 {
                        if wait_pulse!(false).is_none() { success = false; break; }
                        if let Some(len) = wait_pulse!(true) {
                            if len > 40 {
                                data[i / 8] |= 1 << (7 - (i % 8));
                            }
                        } else {
                            success = false; break;
                        }
                    }
                }
            });
            
            if success {
                let checksum = data[0].wrapping_add(data[1]).wrapping_add(data[2]).wrapping_add(data[3]);
                if checksum == data[4] && (data[0] > 0 || data[2] > 0) {
                    hum = data[0] as f32 + (data[1] as f32 / 10.0);
                    temp = data[2] as f32 + (data[3] as f32 / 10.0);
                } else {
                    success = false;
                }
            }

            lcd.set_cursor_pos((0, 1));
            let mut status_str = heapless::String::<16>::new();
            use core::fmt::Write;
            if success {
                let _ = write!(&mut status_str, "{:.1}C {:.0}% RH  ", temp, hum);
            } else {
                let _ = write!(&mut status_str, "Sensor Error    ");
            }
            lcd.write_str_to_cur(&status_str);
                }
            }
        };

        if !connected {
            continue;
        }
        
        info!("Accepted connection from {:?}", socket.remote_endpoint());
        let mut buf = [0; 1024];
        
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => {
                    info!("Connection closed");
                    break;
                }
                Ok(n) => {
                    let payload = core::str::from_utf8(&buf[..n]).unwrap_or("");
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
                                            
                                            let mut allowed = false;
                                                    let mut color_name = "Unknown";
                                                    
                                                    if cmd.starts_with(CMD_ADD_ROLE) && is_supervisor {
                                                        let mut cmd_parts = cmd.split_whitespace();
                                                        cmd_parts.next(); // skip ADD_ROLE
                                                        if let (Some(new_role), Some(new_pk_hex), Some(new_cert_hex)) = (cmd_parts.next(), cmd_parts.next(), cmd_parts.next()) {
                                                            let mut new_pk = [0u8; 32];
                                                            let mut new_cert = heapless::Vec::<u8, 64>::new();
                                                            let mut valid_parse = true;
                                                            
                                                            if new_pk_hex.len() == 64 && new_cert_hex.len() == 128 {
                                                                for i in 0..32 {
                                                                    if let Ok(b) = u8::from_str_radix(&new_pk_hex[i*2..i*2+2], 16) {
                                                                        new_pk[i] = b;
                                                                    } else { valid_parse = false; }
                                                                }
                                                                for i in 0..64 {
                                                                    if let Ok(b) = u8::from_str_radix(&new_cert_hex[i*2..i*2+2], 16) {
                                                                        let _ = new_cert.push(b);
                                                                    } else { valid_parse = false; }
                                                                }
                                                            } else { valid_parse = false; }
                                                            
                                                            if valid_parse {
                                                                    let mut name_str = heapless::String::<16>::new();
                                                                    let _ = name_str.push_str(new_role);
                                                                    let entry = RoleEntry {
                                                                        name: name_str,
                                                                        pubkey: new_pk,
                                                                        cert_sig: new_cert,
                                                                    };
                                                                    // replace if exists
                                                                    let mut replaced = false;
                                                                    for e in unsafe { &mut *core::ptr::addr_of_mut!(ROLES) }.iter_mut() {
                                                                        if e.name == entry.name {
                                                                            *e = entry.clone();
                                                                            replaced = true;
                                                                            break;
                                                                        }
                                                                    }
                                                                    if !replaced {
                                                                        let _ = unsafe { &mut *core::ptr::addr_of_mut!(ROLES) }.push(entry);
                                                                    }
                                                                    
                                                                    if let Ok(bytes) = postcard::to_vec::<_, 4096>(unsafe { &*core::ptr::addr_of!(ROLES) }) {
                                                                        let mut flash = FlashStorage::new();
                                                                        let mut write_buf = [0u8; 4096];
                                                                        write_buf[..bytes.len()].copy_from_slice(&bytes);
                                                                        let _ = flash.write(0x200000, &write_buf);
                                                                        info!("Saved roles to flash");
                                                                    }
                                                                response_msg = "Role Added Securely";
                                                                allowed = true;
                                                                color_name = "System";
                                                            } else {
                                                                response_msg = "Invalid Role Data Format";
                                                            }
                                                        } else {
                                                            response_msg = "Malformed ADD_ROLE command";
                                                        }
                                                    } else if cmd.starts_with(CMD_COLOR_GREEN) {
                                                            if role == ROLE_OBSERVER || role == ROLE_OPERATOR || role == ROLE_ADMIN { allowed = true; }
                                                            color_name = "Green";
                                                        } else if cmd.starts_with(CMD_COLOR_YELLOW) {
                                                            if role == ROLE_OPERATOR || role == ROLE_ADMIN { allowed = true; }
                                                            color_name = "Yellow";
                                                        } else if cmd.starts_with(CMD_COLOR_RED) {
                                                            if role == ROLE_ADMIN { allowed = true; }
                                                            color_name = "Red";
                                                    }
                                                    
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
                                                        
                                                        if cmd.starts_with(CMD_COLOR_RED) {
                                                            data = [colors::RED; 8];
                                                        } else if cmd.starts_with(CMD_COLOR_YELLOW) {
                                                            data = [colors::YELLOW; 8];
                                                        } else if cmd.starts_with(CMD_COLOR_GREEN) {
                                                            data = [colors::GREEN; 8];
                                                        } else if cmd.starts_with(CMD_ADD_ROLE) {
                                                            data = [colors::BLUE; 8]; // Blue for system actions
                                                        } else {
                                                            data = [colors::WHITE; 8];
                                                        }
                                                        ws2812.write(data.iter().cloned()).unwrap();
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
                    
                    // Encrypt response (Authentication is provided by AES-GCM tag)
                    let mut final_response = heapless::String::<1024>::new();
                    let mut plaintext = heapless::String::<256>::new();
                    use core::fmt::Write;
                    let _ = write!(&mut plaintext, "{}", response_msg);
                    
                    #[allow(deprecated)]
                    use aes_gcm::{Aes256Gcm, Key, Nonce};
                    #[allow(deprecated)]
                    use aes_gcm::aead::{AeadInPlace, KeyInit};
                    
                    // ESP32 generates ephemeral X25519 for the response
                    let ticks = embassy_time::Instant::now().as_ticks();
                    let mut resp_ephemeral_seed = [0u8; 32];
                    for i in 0..8 {
                        resp_ephemeral_seed[i] = ((ticks >> (i * 8)) & 0xFF) as u8;
                        resp_ephemeral_seed[i+8] = ((ticks >> (i * 8)) & 0xFF) as u8 ^ 0xAA;
                    }
                    let resp_ephemeral_secret = x25519_dalek::StaticSecret::from(resp_ephemeral_seed);
                    let resp_ephemeral_pub = x25519_dalek::PublicKey::from(&resp_ephemeral_secret);
                    
                    // The WebApp must have sent an ephemeral pubkey that we used earlier.
                    // Wait, the WebApp's ephemeral pubkey was used for the request.
                    // We can just use the exact same shared secret we just computed, 
                    // OR we compute a new one using the WebApp's ephemeral pubkey.
                    // Actually, if we use the WebApp's ephemeral pubkey, we just re-use the `shared_secret`.
                    // But wait, `shared_secret` is out of scope here.
                    // Let's just recompute it, or rely on the `ephemeral_pub` we parsed!
                    
                    let ephemeral_pub = x25519_dalek::PublicKey::from(ephemeral_pub_bytes);
                    let resp_shared_secret = resp_ephemeral_secret.diffie_hellman(&ephemeral_pub);
                    use sha2::Digest;
                    let tx_key_hash = sha2::Sha256::digest(resp_shared_secret.as_bytes());
                    
                    #[allow(deprecated)]
                    let key = Key::<Aes256Gcm>::from_slice(&tx_key_hash);
                    let cipher = Aes256Gcm::new(key);
                    
                    let mut iv = [0u8; 12];
                    for i in 0..8 {
                        iv[i] = ((ticks >> (i * 8)) & 0xFF) as u8;
                    }
                    #[allow(deprecated)]
                    let nonce = Nonce::from_slice(&iv);
                    
                    let mut ciphertext = heapless::Vec::<u8, 256>::new();
                    let _ = ciphertext.extend_from_slice(plaintext.as_bytes());
                    
                    #[allow(deprecated)]
                    if let Ok(tag) = cipher.encrypt_in_place_detached(nonce, b"", &mut ciphertext) {
                        let _ = ciphertext.extend_from_slice(&tag);
                        
                        let mut iv_hex_out = heapless::String::<24>::new();
                        for b in iv {
                            let _ = write!(&mut iv_hex_out, "{:02x}", b);
                        }
                        
                        let mut cipher_hex_out = heapless::String::<512>::new();
                        for b in ciphertext.as_slice() {
                            let _ = write!(&mut cipher_hex_out, "{:02x}", b);
                        }
                        
                        let mut resp_eph_pub_hex = heapless::String::<64>::new();
                        for b in resp_ephemeral_pub.as_bytes() {
                            let _ = write!(&mut resp_eph_pub_hex, "{:02x}", b);
                        }
                        
                        let _ = write!(&mut final_response, "{};{};{}", resp_eph_pub_hex, iv_hex_out, cipher_hex_out);
                    } else {
                        let _ = write!(&mut final_response, "Encryption Error");
                    }
                    
                    let _ = socket.write(final_response.as_bytes()).await;
                }
                Err(e) => {
                    info!("Read error: {:?}", e);
                    break;
                }
            }
        }
    }
}
