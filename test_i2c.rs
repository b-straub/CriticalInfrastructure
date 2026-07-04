#![no_std]
#![no_main]
use esp_hal::{i2c::master::{I2c, Config}, peripherals::Peripherals};
fn test() {
    let peripherals = Peripherals::take();
    let i2c = I2c::new(peripherals.I2C0, Config::default())
        .unwrap()
        .with_sda(peripherals.GPIO8)
        .with_scl(peripherals.GPIO9);
}
