import re

with open("target-esp32s3/src/main.rs", "r") as f:
    content = f.read()

# Add imports
imports = """use log::info;
use smart_leds::{colors, SmartLedsWrite};
use ws2812_spi::Ws2812;
use static_cell::StaticCell;
use serde::{Serialize, Deserialize};
use embedded_storage::{ReadStorage, Storage};
use esp_storage::FlashStorage;
"""
content = content.replace("""use log::info;
use smart_leds::{colors, SmartLedsWrite};
use ws2812_spi::Ws2812;
use static_cell::StaticCell;""", imports)

# Add derive
content = content.replace("#[derive(Clone)]\nstruct RoleEntry {", "#[derive(Clone, Serialize, Deserialize)]\nstruct RoleEntry {")

# Add boot read logic
boot_read = """static mut ROLES: heapless::Vec<RoleEntry, 10> = heapless::Vec::new();

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
"""
content = content.replace("""static mut ROLES: heapless::Vec<RoleEntry, 10> = heapless::Vec::new();

    let mut tx_buffer = [0; 4096];""", boot_read)

# Add flash write logic
write_logic = """                                                                    if !replaced {
                                                                        let _ = ROLES.push(entry);
                                                                    }
                                                                    
                                                                    if let Ok(bytes) = postcard::to_vec::<_, 4096>(&ROLES) {
                                                                        let mut flash = FlashStorage::new();
                                                                        let mut write_buf = [0u8; 4096];
                                                                        write_buf[..bytes.len()].copy_from_slice(&bytes);
                                                                        let _ = flash.write(0x200000, &write_buf);
                                                                        info!("Saved roles to flash");
                                                                    }
                                                                }
                                                                response_msg = "Role Added Securely";"""
content = content.replace("""                                                                    if !replaced {
                                                                        let _ = ROLES.push(entry);
                                                                    }
                                                                }
                                                                response_msg = "Role Added Securely";""", write_logic)


with open("target-esp32s3/src/main.rs", "w") as f:
    f.write(content)
print("Storage patch applied")
