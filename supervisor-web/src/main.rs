use yew::prelude::*;
use wasm_bindgen::prelude::*;
use js_sys;
use wasm_bindgen_futures::spawn_local;
use ed25519_dalek::SigningKey;
use shared::terminology::*;
use shared::Role;
use hex;
use gloo_storage::{LocalStorage, Storage};

mod crypto;
mod webauthn;
mod view;

// The PRF-derived seed is cached only briefly: any window this long without a
// command wipes it from memory, forcing a (fast, biometric) re-derivation.
const SEED_TTL_MS: u32 = 60_000;

enum Msg {
    UpdateUserId(String),
    Register,
    Authenticate,
    Authenticated(Vec<u8>, String),
    AuthError(String),
    UpdateIp(String),
    UpdateEspPubkey(String),
    UpdateEspSigPubkey(String),
    SendCommand(String),
    UpdateNewRoleName(String),
    UpdateNewRolePubkey(String),
    UpdateSupervisorPubkey(String),
    AddRole,
    Logout,
    SeedExpired,
    CommandResponse(String),
    ClearColor,
    StartCommandWithColor(String, String), // Command, Color
}

struct App {
    user_id: String,
    active_role: Option<Role>,
    // PRF-derived key material. Zeroizing wipes the bytes on drop instead of
    // leaving them in freed WASM heap; held only for a short idle window.
    seed: Option<zeroize::Zeroizing<Vec<u8>>>,
    error: Option<String>,
    pubkey_hex: Option<String>,
    esp32_ip: String,
    esp32_pubkey: String,
    esp32_sig_pubkey: String,
    supervisor_pubkey: String,
    new_role_name: String,
    new_role_pubkey: String,
    last_response: Option<String>,
    is_fetching_role: bool,
    parsed_roles: Option<Vec<(String, String)>>,
    command_color: Option<String>,
    active_timeout: Option<gloo_timers::callback::Timeout>,
    seed_timeout: Option<gloo_timers::callback::Timeout>,
}

impl App {
    // (Re)arm the sliding idle timeout that wipes the cached seed.
    fn arm_seed_timeout(&mut self, ctx: &Context<Self>) {
        let link = ctx.link().clone();
        self.seed_timeout = Some(gloo_timers::callback::Timeout::new(SEED_TTL_MS, move || {
            link.send_message(Msg::SeedExpired);
        }));
    }

    // The connection target and all trust anchors (incl. the supervisor pubkey)
    // must be provisioned before the device can be used. Forces the config panel
    // open for first-time setup.
    fn config_needs_setup(&self) -> bool {
        self.esp32_ip.trim().is_empty()
            || self.esp32_pubkey.len() != 64
            || self.esp32_sig_pubkey.len() != 64
            || self.supervisor_pubkey.len() != 64
    }

    // The authenticated user is the supervisor iff their own public key matches
    // the provisioned supervisor pubkey. Local check -- no device round-trip.
    fn is_local_supervisor(&self) -> bool {
        self.supervisor_pubkey.len() == 64
            && self.pubkey_hex.as_deref() == Some(self.supervisor_pubkey.as_str())
    }
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        let user_id = LocalStorage::get::<String>("user_id").unwrap_or_default();
        let esp32_ip = LocalStorage::get::<String>("esp32_ip").unwrap_or_default();
        // Trust anchors (the ESP ROM/signing pubkeys and the supervisor pubkey)
        // default to empty: they must be provisioned explicitly, never silently
        // trusted from a value baked into the build. Once entered they persist in
        // LocalStorage.
        let esp32_pubkey = LocalStorage::get::<String>("esp32_pubkey").unwrap_or_default();
        let esp32_sig_pubkey = LocalStorage::get::<String>("esp32_sig_pubkey").unwrap_or_default();
        let supervisor_pubkey = LocalStorage::get::<String>("supervisor_pubkey").unwrap_or_default();
        
        Self {
            user_id,
            active_role: None,
            seed: None,
            error: None,
            pubkey_hex: None,
            esp32_ip,
            esp32_pubkey,
            esp32_sig_pubkey,
            supervisor_pubkey,
            new_role_name: String::new(),
            new_role_pubkey: String::new(),
            last_response: None,
            is_fetching_role: false,
            parsed_roles: None,
            command_color: None,
            active_timeout: None,
            seed_timeout: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::UpdateUserId(id) => {
                self.user_id = id.clone();
                let _ = LocalStorage::set("user_id", id);
                true
            }
            Msg::UpdateIp(ip) => {
                self.esp32_ip = ip.clone();
                let _ = LocalStorage::set("esp32_ip", ip);
                true
            }
            Msg::UpdateEspPubkey(key) => {
                self.esp32_pubkey = key.clone();
                let _ = LocalStorage::set("esp32_pubkey", key);
                true
            }
            Msg::UpdateEspSigPubkey(key) => {
                self.esp32_sig_pubkey = key.clone();
                let _ = LocalStorage::set("esp32_sig_pubkey", key);
                true
            }
            Msg::Register => {
                let link = ctx.link().clone();
                let user_id = self.user_id.clone();
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
                self.pubkey_hex = Some(hex::encode(verifying_key.as_bytes()));
                self.seed = Some(zeroize::Zeroizing::new(seed));
                self.arm_seed_timeout(ctx);
                self.active_role = None; // Force user to fetch role from ESP32
                self.error = None;
                self.is_fetching_role = true;
                ctx.link().send_message(Msg::SendCommand(CMD_WHOAMI.to_string()));
                true
            }
            Msg::AuthError(err) => {
                self.error = Some(err);
                true
            }
            Msg::SeedExpired => {
                // Idle window elapsed: wipe the cached seed (Zeroizing clears the
                // bytes on drop). The next command will prompt a biometric re-auth.
                self.seed = None;
                self.seed_timeout = None;
                self.error = Some("Session key expired and was wiped from memory. Re-authenticate to send commands.".to_string());
                true
            }
            Msg::Logout => {
                self.seed = None;
                self.pubkey_hex = None;
                self.active_role = None;
                self.error = None;
                self.last_response = None;
                self.is_fetching_role = false;
                self.parsed_roles = None;
                self.command_color = None;
                self.active_timeout = None;
                self.seed_timeout = None;
                true
            }
            Msg::CommandResponse(resp) => {
                self.is_fetching_role = false;
                if let Some(role) = Role::from_wire(&resp) {
                    self.active_role = Some(role);
                    self.last_response = None;
                } else if resp.starts_with("ROLES:") {
                    let mut roles = Vec::new();
                    let payload = resp.strip_prefix("ROLES:").unwrap();
                    for part in payload.split(',') {
                        if part.is_empty() { continue; }
                        if let Some((name, pk)) = part.split_once(':') {
                            roles.push((name.to_string(), pk.to_string()));
                        }
                    }
                    self.parsed_roles = Some(roles);
                    self.last_response = Some(resp);
                } else {
                    self.parsed_roles = None;
                    self.last_response = Some(resp);
                }
                true
            }
            Msg::ClearColor => {
                self.command_color = None;
                self.active_timeout = None;
                true
            }
            Msg::StartCommandWithColor(cmd, color) => {
                self.command_color = Some(color);
                
                let link = ctx.link().clone();
                let timeout = gloo_timers::callback::Timeout::new(shared::terminology::COMMAND_LED_TIMEOUT_MS as u32, move || {
                    link.send_message(Msg::ClearColor);
                });
                self.active_timeout = Some(timeout);
                
                ctx.link().send_message(Msg::SendCommand(cmd));
                true
            }
            Msg::UpdateNewRoleName(name) => {
                self.new_role_name = name;
                true
            }
            Msg::UpdateNewRolePubkey(pk) => {
                self.new_role_pubkey = pk;
                true
            }
            Msg::UpdateSupervisorPubkey(pk) => {
                self.supervisor_pubkey = pk.clone();
                let _ = LocalStorage::set("supervisor_pubkey", pk);
                true
            }
            Msg::AddRole => {
                if let Some(seed) = &self.seed {
                    if self.pubkey_hex.as_deref() == Some(&self.supervisor_pubkey) {
                        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
                        let cert_msg = format!("ROLE:{};PUBKEY:{}", self.new_role_name, self.new_role_pubkey);
                        use ed25519_dalek::Signer;
                        let cert_sig = signing_key.sign(cert_msg.as_bytes());
                        let cert_sig_hex = hex::encode(cert_sig.to_bytes());
                        let cmd = format!("{}{name} {pk} {sig}", CMD_ADD_ROLE, name=self.new_role_name, pk=self.new_role_pubkey, sig=cert_sig_hex);
                        ctx.link().send_message(Msg::SendCommand(cmd));
                    }
                }
                false
            }
            Msg::SendCommand(cmd_str) => {
                let has_seed = self.seed.is_some();
                if let Some(seed) = &self.seed {
                    let seed_clone = seed.clone();
                    let ip_clone = self.esp32_ip.clone();
                    let hex_pub = self.esp32_pubkey.clone();
                    let sig_pub_hex = self.esp32_sig_pubkey.clone();
                    
                    let mut esp_pub_bytes = [0u8; 32];
                    if hex_pub.len() == 64 {
                        for i in 0..32 {
                            esp_pub_bytes[i] = u8::from_str_radix(&hex_pub[i*2..i*2+2], 16).unwrap_or(0);
                        }
                    } else {
                        self.error = Some("Invalid ESP32 ROM Public Key length".to_string());
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
                    self.error = Some("No keys generated. Click 'Register WebAuthn' first.".to_string());
                }
                // Sliding idle window: active use keeps the seed alive; inactivity wipes it.
                if has_seed {
                    self.arm_seed_timeout(ctx);
                }
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        crate::view::render(self, ctx)
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
