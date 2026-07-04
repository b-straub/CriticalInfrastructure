import re

with open("target-esp32s3/src/main.rs", "r") as f:
    content = f.read()

# 1. Add the RoleEntry struct and ROLES static variable
structs = """
struct RoleEntry {
    name: heapless::String<16>,
    pubkey: [u8; 32],
    cert_sig: [u8; 64],
}
static mut ROLES: heapless::Vec<RoleEntry, 10> = heapless::Vec::new();
"""
content = content.replace("let mut tx_buffer = [0; 4096];", structs + "\n    let mut tx_buffer = [0; 4096];")

# 2. Replace the old RBAC and Signature Verification
old_verify = """                                    if valid_sig_format {
                                        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                                        use ed25519_dalek::Verifier;
                                        
                                        // We use the supervisor key as the seed for the verifying key
                                        let signing_key = ed25519_dalek::SigningKey::from_bytes(&supervisor_key);
                                        let verifying_key = signing_key.verifying_key();
                                        
                                        if verifying_key.verify(cmd.as_bytes(), &sig).is_ok() {
                                            info!("Authenticated Command: {} (Role: {})", cmd, role);
                                            
                                            let mut allowed = false;
                                            let color_name = if cmd.starts_with("COLOR green") {
                                                allowed = true;
                                                "Green"
                                            } else if cmd.starts_with("COLOR yellow") {
                                                if role == "User" || role == "Admin" || role == "Supervisor" { allowed = true; }
                                                "Yellow"
                                            } else if cmd.starts_with("COLOR red") {
                                                if role == "Admin" || role == "Supervisor" { allowed = true; }
                                                "Red"
                                            } else {
                                                "Unknown"
                                            };
                                            
                                            lcd.set_cursor_pos((0, 1));
                                            let mut status_str = heapless::String::<16>::new();
                                            use core::fmt::Write;
                                            
                                            if allowed {
                                                response_msg = "Command Executed";
                                                write!(&mut status_str, "{:<6} Pass   ", color_name).unwrap();
                                                lcd.write_str_to_cur(&status_str);
                                                
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
                                            } else {
                                                response_msg = "Permission Denied";
                                                write!(&mut status_str, "{:<6} Reject ", color_name).unwrap();
                                                lcd.write_str_to_cur(&status_str);
                                            }
                                        } else {
                                            response_msg = "Signature verification failed";
                                        }
                                    } else {
                                        response_msg = "Invalid Signature Format";
                                    }"""

new_verify = """                                    if valid_sig_format {
                                        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                                        use ed25519_dalek::Verifier;
                                        
                                        let supervisor_signing_key = ed25519_dalek::SigningKey::from_bytes(&supervisor_key);
                                        let supervisor_verifying_key = supervisor_signing_key.verifying_key();
                                        
                                        let mut role_pubkey = [0u8; 32];
                                        let mut role_authorized = false;
                                        
                                        if role == "Supervisor" {
                                            role_pubkey = supervisor_verifying_key.to_bytes();
                                            role_authorized = true;
                                        } else {
                                            unsafe {
                                                for entry in ROLES.iter() {
                                                    if entry.name == role {
                                                        let mut cert_msg = heapless::String::<128>::new();
                                                        use core::fmt::Write;
                                                        let mut pk_hex = heapless::String::<64>::new();
                                                        for b in entry.pubkey {
                                                            let _ = write!(&mut pk_hex, "{:02x}", b);
                                                        }
                                                        let _ = write!(&mut cert_msg, "ROLE:{};PUBKEY:{}", entry.name, pk_hex);
                                                        
                                                        let cert_sig = ed25519_dalek::Signature::from_bytes(&entry.cert_sig);
                                                        
                                                        if supervisor_verifying_key.verify(cert_msg.as_bytes(), &cert_sig).is_ok() {
                                                            role_pubkey = entry.pubkey;
                                                            role_authorized = true;
                                                            break;
                                                        } else {
                                                            info!("RAM Tampering Detected for role {}!", role);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        
                                        if role_authorized {
                                            if let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&role_pubkey) {
                                                if verifying_key.verify(cmd.as_bytes(), &sig).is_ok() {
                                                    info!("Authenticated Command: {} (Role: {})", cmd, role);
                                                    
                                                    let mut allowed = false;
                                                    let mut color_name = "Unknown";
                                                    
                                                    if cmd.starts_with("ADD_ROLE ") && role == "Supervisor" {
                                                        let mut cmd_parts = cmd.split_whitespace();
                                                        cmd_parts.next(); // skip ADD_ROLE
                                                        if let (Some(new_role), Some(new_pk_hex), Some(new_cert_hex)) = (cmd_parts.next(), cmd_parts.next(), cmd_parts.next()) {
                                                            let mut new_pk = [0u8; 32];
                                                            let mut new_cert = [0u8; 64];
                                                            let mut valid_parse = true;
                                                            
                                                            if new_pk_hex.len() == 64 && new_cert_hex.len() == 128 {
                                                                for i in 0..32 {
                                                                    if let Ok(b) = u8::from_str_radix(&new_pk_hex[i*2..i*2+2], 16) {
                                                                        new_pk[i] = b;
                                                                    } else { valid_parse = false; }
                                                                }
                                                                for i in 0..64 {
                                                                    if let Ok(b) = u8::from_str_radix(&new_cert_hex[i*2..i*2+2], 16) {
                                                                        new_cert[i] = b;
                                                                    } else { valid_parse = false; }
                                                                }
                                                            } else { valid_parse = false; }
                                                            
                                                            if valid_parse {
                                                                unsafe {
                                                                    let entry = RoleEntry {
                                                                        name: heapless::String::from(new_role),
                                                                        pubkey: new_pk,
                                                                        cert_sig: new_cert,
                                                                    };
                                                                    // replace if exists
                                                                    let mut replaced = false;
                                                                    for e in ROLES.iter_mut() {
                                                                        if e.name == entry.name {
                                                                            *e = entry.clone();
                                                                            replaced = true;
                                                                            break;
                                                                        }
                                                                    }
                                                                    if !replaced {
                                                                        let _ = ROLES.push(entry);
                                                                    }
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
                                                    } else {
                                                        if cmd.starts_with("COLOR green") {
                                                            allowed = true;
                                                            color_name = "Green";
                                                        } else if cmd.starts_with("COLOR yellow") {
                                                            if role == "User" || role == "Admin" || role == "Supervisor" { allowed = true; }
                                                            color_name = "Yellow";
                                                        } else if cmd.starts_with("COLOR red") {
                                                            if role == "Admin" || role == "Supervisor" { allowed = true; }
                                                            color_name = "Red";
                                                        }
                                                        
                                                        lcd.set_cursor_pos((0, 1));
                                                        let mut status_str = heapless::String::<16>::new();
                                                        use core::fmt::Write;
                                                        
                                                        if allowed {
                                                            response_msg = "Command Executed";
                                                            let _ = write!(&mut status_str, "{:<6} Pass   ", color_name);
                                                            lcd.write_str_to_cur(&status_str);
                                                            
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
                                                        } else {
                                                            response_msg = "Permission Denied";
                                                            let _ = write!(&mut status_str, "{:<6} Reject ", color_name);
                                                            lcd.write_str_to_cur(&status_str);
                                                        }
                                                    }
                                                } else {
                                                    response_msg = "Signature verification failed";
                                                }
                                            } else {
                                                response_msg = "Invalid Role Pubkey";
                                            }
                                        } else {
                                            response_msg = "Role not found or Certificate tampered";
                                        }
                                    } else {
                                        response_msg = "Invalid Signature Format";
                                    }"""

content = content.replace(old_verify, new_verify)

with open("target-esp32s3/src/main.rs", "w") as f:
    f.write(content)
print("Patched target-esp32s3/src/main.rs")
