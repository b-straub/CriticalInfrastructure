#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::{
    delay::Delay,
    rmt::Rmt,
    time::Rate,
    Blocking,
};
use esp_hal_smartled::Ws2812SmartLeds;
use smart_leds::{SmartLedsWrite, colors, RGB8};
use log::info;

#[esp_hal::main]
fn main() -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    esp_println::logger::init_logger_from_env();
    let delay = Delay::new();

    // Initialize the RMT peripheral
    let rmt = Rmt::new(peripherals.RMT, Rate::from_mhz(80)).unwrap();
    
    // Connect the 8-LED stick to GPIO 4 (Channel 0)
    let mut led_stick = Ws2812SmartLeds::<8, Blocking>::new(rmt.channel0, peripherals.GPIO4).unwrap();

    info!("---------------------------------------");
    info!("ESP32-S3 Hardware Smoke Test Passed!");
    info!("Testing 8-RGB LED Stick...");
    info!("---------------------------------------");

    let mut data = [colors::BLACK; 8];

    loop {
        info!("State: SECURE (Green)");
        data.fill(RGB8 { r: 0, g: 50, b: 0 }); // Green (brightness 50)
        led_stick.write(data.iter().copied()).unwrap();
        delay.delay_millis(1000);

        info!("State: WARNING (Yellow)");
        data.fill(RGB8 { r: 50, g: 50, b: 0 }); // Yellow
        led_stick.write(data.iter().copied()).unwrap();
        delay.delay_millis(1000);

        info!("State: BREACH (Red Flashing)");
        for _ in 0..4 {
            data.fill(RGB8 { r: 255, g: 0, b: 0 }); // Max Red
            led_stick.write(data.iter().copied()).unwrap();
            delay.delay_millis(125);
            
            data.fill(colors::BLACK);
            led_stick.write(data.iter().copied()).unwrap();
            delay.delay_millis(125);
        }
    }
}
