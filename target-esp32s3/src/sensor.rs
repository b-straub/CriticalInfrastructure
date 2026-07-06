//! DHT11 temperature / humidity sensor — bit-banged single-wire protocol.

use esp_hal::gpio::Flex;

/// Read one sample from the DHT11 on `dht_pin`. Returns `Some((temp_c, rh_pct))`
/// on a checksum-valid read, or `None` on timeout / checksum failure.
///
/// Runs the timing-critical bit sampling inside a `critical_section`.
pub fn read_dht11(dht_pin: &mut Flex<'_>) -> Option<(f32, f32)> {
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
            let hum = data[0] as f32 + (data[1] as f32 / 10.0);
            let temp = data[2] as f32 + (data[3] as f32 / 10.0);
            return Some((temp, hum));
        }
    }
    None
}
