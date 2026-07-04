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

    let peripherals = esp_hal::init(esp_hal::Config::default());
    
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_hal_embassy::init(timg0.timer0);
    
    esp_alloc::heap_allocator!(size: 72 * 1024);
    
    let timg1 = TimerGroup::new(peripherals.TIMG1);
    let rng = Rng::new(peripherals.RNG);
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
    let mut tx_buffer = [0; 4096];
    
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
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }
    
    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));
        
        info!("Listening on TCP:8080...");
        if let Err(e) = socket.accept(8080).await {
            info!("Accept error: {:?}", e);
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
                    let cmd = core::str::from_utf8(&buf[..n]).unwrap_or("");
                    info!("Received: {}", cmd);
                    if cmd.starts_with("COLOR red") {
                        data = [colors::RED; 8];
                    } else if cmd.starts_with("COLOR yellow") {
                        data = [colors::YELLOW; 8];
                    } else if cmd.starts_with("COLOR green") {
                        data = [colors::GREEN; 8];
                    } else {
                        data = [colors::WHITE; 8];
                    }
                    ws2812.write(data.iter().cloned()).unwrap();
                }
                Err(e) => {
                    info!("Read error: {:?}", e);
                    break;
                }
            }
        }
    }
}
