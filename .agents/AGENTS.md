# CriticalInfrastructure Project Context
## ESP32-S3 Firmware Compilation Rules
When modifying `target-esp32s3/Cargo.toml` or `main.rs`, strict dependency version locking is required due to hardware constraints (eFuse block rev v1.3) and `esp-wifi` v0.15.1 couplings.

1. **`esp-bootloader-esp-idf`**: MUST BE LOCKED to version `0.4.0`. Using `0.5.0` or newer brings in a newer ESP-IDF 2nd-stage bootloader that mandates eFuse block revision >= v1.15, which bricks flashing on the v1.3 chip revision.
2. **`esp_app_desc!()`**: The macro `esp_bootloader_esp_idf::esp_app_desc!();` must ALWAYS be present at the top of `main.rs`. Without it, `cargo espflash flash` will fail with "ESP-IDF App Descriptor not found".
3. **`esp-alloc` conflict**: `esp-wifi = "0.15.1"` implicitly pulls in `esp-alloc = "0.8.0"`. Do NOT specify `esp-alloc = "0.10.0"` manually in `Cargo.toml`, or it will result in dual `#[global_allocator]` linker collisions (`multiple definition of malloc`). Lock `esp-alloc` to `"0.8.0"` without the `esp32s3` feature (which didn't exist in 0.8.0).
4. **`embassy-executor` and `embassy-time`**: `esp-wifi 0.15.1` requires downgrading `embassy-executor` to `0.7.0` (from 0.7.1). However, `embassy-net 0.9.1` requires `embassy-time = "0.5.1"`.
5. **WiFi Credentials**: Must be passed via `option_env!("WIFI_SSID")` and `option_env!("WIFI_PASS")`.

## Strict Rust Compilation Verification
Whenever modifying or writing Rust code, you MUST ALWAYS execute `cargo check` (or `cargo check --release` for embedded targets) before declaring the coding task complete.
You are strictly forbidden from handing over code that contains compilation errors or warnings. You must resolve all compiler issues before communicating completion to the user.

## Atomic Version Control
You MUST execute `git commit` to commit your code to version control immediately after successfully completing each update or fix, rather than waiting for the end of the session.
