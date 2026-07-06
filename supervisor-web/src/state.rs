//! App update logic (message handling), split out of the Component impl.
//!
//! A child module of the crate root, so it can call App's private helper
//! methods (e.g. arm_seed_timeout) directly.

use crate::{crypto, webauthn, App, Msg};
use ed25519_dalek::SigningKey;
use gloo_storage::{LocalStorage, Storage};
use shared::terminology::*;
use shared::Role;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

pub fn update(app: &mut App, ctx: &Context<App>, msg: Msg) -> bool {
        match msg {
            Msg::UpdateUserId(id) => {
                app.user_id = id.clone();
                let _ = LocalStorage::set("user_id", id);
                true
            }
            Msg::UpdateIp(ip) => {
                app.esp32_ip = ip.clone();
                let _ = LocalStorage::set("esp32_ip", ip);
                true
            }
            Msg::UpdateEspPubkey(key) => {
                app.esp32_pubkey = key.clone();
                let _ = LocalStorage::set("esp32_pubkey", key);
                true
            }
            Msg::UpdateEspSigPubkey(key) => {
                app.esp32_sig_pubkey = key.clone();
                let _ = LocalStorage::set("esp32_sig_pubkey", key);
                true
            }
            Msg::Register => {
                let link = ctx.link().clone();
                let user_id = app.user_id.clone();
                spawn_local(async move {
                    match webauthn::register(&user_id).await {
                        Ok((seed, role)) => link.send_message(Msg::Authenticated(seed, role)),
                        Err(e) => link.send_message(Msg::AuthError(e)),
                    }
                });
                false
            }
            Msg::Authenticate => {
                let link = ctx.link().clone();
                spawn_local(async move {
                    match webauthn::authenticate().await {
                        Ok((seed, role)) => link.send_message(Msg::Authenticated(seed, role)),
                        Err(e) => link.send_message(Msg::AuthError(e)),
                    }
                });
                false
            }
            Msg::Authenticated(seed, _role) => {
                let signing_key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
                let verifying_key = signing_key.verifying_key();
                app.pubkey_hex = Some(hex::encode(verifying_key.as_bytes()));
                app.seed = Some(zeroize::Zeroizing::new(seed));
                app.arm_seed_timeout(ctx);
                app.active_role = None; // Force user to fetch role from ESP32
                app.error = None;
                app.is_fetching_role = true;
                ctx.link().send_message(Msg::SendCommand(CMD_WHOAMI.to_string()));
                true
            }
            Msg::AuthError(err) => {
                app.error = Some(err);
                true
            }
            Msg::SeedExpired => {
                // Idle window elapsed: wipe the cached seed (Zeroizing clears the
                // bytes on drop). The next command will prompt a biometric re-auth.
                app.seed = None;
                app.seed_timeout = None;
                app.error = Some("Session key expired and was wiped from memory. Re-authenticate to send commands.".to_string());
                true
            }
            Msg::Logout => {
                app.seed = None;
                app.pubkey_hex = None;
                app.active_role = None;
                app.error = None;
                app.last_response = None;
                app.is_fetching_role = false;
                app.parsed_roles = None;
                app.command_color = None;
                app.active_timeout = None;
                app.seed_timeout = None;
                true
            }
            Msg::CommandResponse(resp) => {
                app.is_fetching_role = false;
                if let Some(role) = Role::from_wire(&resp) {
                    app.active_role = Some(role);
                    app.last_response = None;
                } else if resp.starts_with("ROLES:") {
                    let mut roles = Vec::new();
                    let payload = resp.strip_prefix("ROLES:").unwrap();
                    for part in payload.split(',') {
                        if part.is_empty() { continue; }
                        if let Some((name, pk)) = part.split_once(':') {
                            roles.push((name.to_string(), pk.to_string()));
                        }
                    }
                    app.parsed_roles = Some(roles);
                    app.last_response = Some(resp);
                } else {
                    app.parsed_roles = None;
                    app.last_response = Some(resp);
                }
                true
            }
            Msg::ClearColor => {
                app.command_color = None;
                app.active_timeout = None;
                true
            }
            Msg::StartCommandWithColor(cmd, color) => {
                app.command_color = Some(color);
                
                let link = ctx.link().clone();
                let timeout = gloo_timers::callback::Timeout::new(shared::terminology::COMMAND_LED_TIMEOUT_MS as u32, move || {
                    link.send_message(Msg::ClearColor);
                });
                app.active_timeout = Some(timeout);
                
                ctx.link().send_message(Msg::SendCommand(cmd));
                true
            }
            Msg::UpdateNewRoleName(name) => {
                app.new_role_name = name;
                true
            }
            Msg::UpdateNewRolePubkey(pk) => {
                app.new_role_pubkey = pk;
                true
            }
            Msg::UpdateSupervisorPubkey(pk) => {
                app.supervisor_pubkey = pk.clone();
                let _ = LocalStorage::set("supervisor_pubkey", pk);
                true
            }
            Msg::AddRole => {
                if let Some(seed) = &app.seed {
                    if app.pubkey_hex.as_deref() == Some(&app.supervisor_pubkey) {
                        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
                        let cert_msg = format!("ROLE:{};PUBKEY:{}", app.new_role_name, app.new_role_pubkey);
                        use ed25519_dalek::Signer;
                        let cert_sig = signing_key.sign(cert_msg.as_bytes());
                        let cert_sig_hex = hex::encode(cert_sig.to_bytes());
                        let cmd = format!("{}{name} {pk} {sig}", CMD_ADD_ROLE, name=app.new_role_name, pk=app.new_role_pubkey, sig=cert_sig_hex);
                        ctx.link().send_message(Msg::SendCommand(cmd));
                    }
                }
                false
            }
            Msg::SendCommand(cmd_str) => {
                let has_seed = app.seed.is_some();
                if let Some(seed) = &app.seed {
                    let seed_clone = seed.clone();
                    let ip_clone = app.esp32_ip.clone();
                    let hex_pub = app.esp32_pubkey.clone();
                    let sig_pub_hex = app.esp32_sig_pubkey.clone();
                    
                    let mut esp_pub_bytes = [0u8; 32];
                    if hex_pub.len() == 64 {
                        for i in 0..32 {
                            esp_pub_bytes[i] = u8::from_str_radix(&hex_pub[i*2..i*2+2], 16).unwrap_or(0);
                        }
                    } else {
                        app.error = Some("Invalid ESP32 ROM Public Key length".to_string());
                        return true;
                    }
                    
                    let window = web_sys::window().unwrap();
                    let link = ctx.link().clone();
                    spawn_local(async move {
                        let timestamp = js_sys::Date::now() as u64;
                        let (payload, ephemeral_secret) =
                            crypto::encrypt_command(seed_clone.as_slice(), &cmd_str, &esp_pub_bytes, timestamp);

                        let url = format!("http://localhost:8000/proxy.php?ip={}", ip_clone);
                        let opts = web_sys::RequestInit::new();
                        opts.set_method("POST");
                        opts.set_mode(web_sys::RequestMode::Cors);
                        opts.set_body(&JsValue::from_str(&payload));
                        let request = web_sys::Request::new_with_str_and_init(&url, &opts).unwrap();

                        match wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request)).await {
                            Ok(resp_value) => {
                                use wasm_bindgen::JsCast;
                                if let Ok(resp) = resp_value.dyn_into::<web_sys::Response>() {
                                    if resp.ok() {
                                        match wasm_bindgen_futures::JsFuture::from(resp.text().unwrap()).await {
                                            Ok(text_val) => {
                                                if let Some(text) = text_val.as_string() {
                                                    match crypto::verify_response(&text, &ephemeral_secret, &sig_pub_hex, timestamp) {
                                                        Ok(msg) => link.send_message(Msg::CommandResponse(msg)),
                                                        Err(e) => link.send_message(Msg::CommandResponse(e)),
                                                    }
                                                }
                                            }
                                            Err(_) => web_sys::console::log_1(&"Command sent successfully, but couldn't read response body.".into()),
                                        }
                                    } else {
                                        link.send_message(Msg::CommandResponse(format!("Connection error: proxy returned HTTP {}. Check the device IP and that it is reachable, then retry.", resp.status())));
                                    }
                                }
                            }
                            Err(e) => link.send_message(Msg::CommandResponse(format!("Connection error: could not reach the proxy ({:?}). Check the proxy and device IP, then retry.", e))),
                        }
                    });
                } else {
                    app.error = Some("No keys generated. Click 'Register WebAuthn' first.".to_string());
                }
                // Sliding idle window: active use keeps the seed alive; inactivity wipes it.
                if has_seed {
                    app.arm_seed_timeout(ctx);
                }
                true
            }
        }
}
