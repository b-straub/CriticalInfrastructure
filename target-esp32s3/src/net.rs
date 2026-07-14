//! Wi-Fi connection management and the network stack runner task.
//!
//! The station config (SSID/password) is set at `esp_radio::wifi::new` in `main`; this task
//! only drives the connect/reconnect loop — esp-radio starts the driver on construction.

use embassy_time::{Duration, Timer};
use esp_radio::wifi::{Interface, WifiController};
use log::info;

#[embassy_executor::task]
pub async fn connection(mut controller: WifiController<'static>) {
    info!("wifi connection task starting");
    loop {
        info!("Connecting...");
        match controller.connect_async().await {
            Ok(_) => {
                info!("Wifi connected!");
                // Park until the link drops, then fall through to reconnect.
                let _ = controller.wait_for_disconnect_async().await;
                info!("Wifi disconnected");
            }
            Err(e) => {
                info!("Failed to connect to wifi: {:?}", e);
            }
        }
        Timer::after(Duration::from_millis(5000)).await;
    }
}

#[embassy_executor::task]
pub async fn net_task(mut runner: embassy_net::Runner<'static, Interface<'static>>) {
    runner.run().await
}
