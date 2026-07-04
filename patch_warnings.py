import re

with open("target-esp32s3/src/main.rs", "r") as f:
    content = f.read()

# Fix static mut references
content = content.replace("for entry in ROLES.iter() {", "for entry in unsafe { &*core::ptr::addr_of!(ROLES) }.iter() {")
content = content.replace("for e in ROLES.iter_mut() {", "for e in unsafe { &mut *core::ptr::addr_of_mut!(ROLES) }.iter_mut() {")
content = content.replace("let _ = ROLES.push(entry);", "let _ = unsafe { &mut *core::ptr::addr_of_mut!(ROLES) }.push(entry);")
content = content.replace("&ROLES)", "unsafe { &*core::ptr::addr_of!(ROLES) })")

# Fix allowed/color_name block structure
# Find the ADD_ROLE block end
add_role_block = """                                                                response_msg = "Role Added Securely";
                                                                allowed = true;
                                                                color_name = "System";
                                                            } else {
                                                                response_msg = "Invalid Role Data Format";
                                                            }
                                                        } else {
                                                            response_msg = "Malformed ADD_ROLE command";
                                                        }
                                                    } else {
                                                        if cmd.starts_with("COLOR green") {"""

fixed_add_role = """                                                                response_msg = "Role Added Securely";
                                                                allowed = true;
                                                                color_name = "System";
                                                            } else {
                                                                response_msg = "Invalid Role Data Format";
                                                            }
                                                        } else {
                                                            response_msg = "Malformed ADD_ROLE command";
                                                        }
                                                    } else if cmd.starts_with("COLOR green") {"""

content = content.replace(add_role_block, fixed_add_role)

# Now we need to remove the extra indent and brace for the else block that we merged into else if
old_actuation = """                                                        }
                                                        
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
                                                    }"""

new_actuation = """                                                    }
                                                    
                                                    lcd.set_cursor_pos((0, 1));
                                                    let mut status_str = heapless::String::<16>::new();
                                                    use core::fmt::Write;
                                                    
                                                    if allowed {
                                                        if response_msg == "Invalid Crypto Envelope" {
                                                            response_msg = "Command Executed";
                                                        }
                                                        let _ = write!(&mut status_str, "{:<6} Pass   ", color_name);
                                                        lcd.write_str_to_cur(&status_str);
                                                        
                                                        if cmd.starts_with("COLOR red") {
                                                            data = [colors::RED; 8];
                                                        } else if cmd.starts_with("COLOR yellow") {
                                                            data = [colors::YELLOW; 8];
                                                        } else if cmd.starts_with("COLOR green") {
                                                            data = [colors::GREEN; 8];
                                                        } else if cmd.starts_with("ADD_ROLE ") {
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
                                                    }"""

content = content.replace(old_actuation, new_actuation)

with open("target-esp32s3/src/main.rs", "w") as f:
    f.write(content)

