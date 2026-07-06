//! Reactive app state (a `Copy` bundle of signals) and all the logic that used
//! to live in the Yew `Msg` / `update` loop. Event handlers call these methods
//! directly and mutate signals; only the exact DOM nodes bound to a changed
//! signal re-render.

use crate::{crypto, webauthn};
use ed25519_dalek::{Signer, SigningKey};
use gloo_storage::{LocalStorage, Storage};
use gloo_timers::callback::Timeout;
use leptos::prelude::*;
use shared::terminology::*;
use shared::Role;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use zeroize::Zeroizing;

/// The PRF-derived seed is cached only briefly: any window this long without a
/// command wipes it from memory, forcing a (fast, biometric) re-derivation.
const SEED_TTL_MS: u32 = 60_000;

/// Every field is a signal, so the whole struct is `Copy` and can be handed to
/// view fns and async tasks freely.
#[derive(Clone, Copy)]
pub struct AppState {
    pub user_id: RwSignal<String>,
    pub active_role: RwSignal<Option<Role>>,
    /// PRF-derived key material; `Zeroizing` wipes the bytes on drop.
    pub seed: RwSignal<Option<Zeroizing<Vec<u8>>>>,
    pub error: RwSignal<Option<String>>,
    pub pubkey_hex: RwSignal<Option<String>>,
    pub esp32_ip: RwSignal<String>,
    pub esp32_pubkey: RwSignal<String>,
    pub esp32_sig_pubkey: RwSignal<String>,
    pub supervisor_pubkey: RwSignal<String>,
    pub new_role_name: RwSignal<String>,
    pub new_role_pubkey: RwSignal<String>,
    pub last_response: RwSignal<Option<String>>,
    pub is_fetching_role: RwSignal<bool>,
    pub parsed_roles: RwSignal<Option<Vec<(String, String)>>>,
    pub command_color: RwSignal<Option<String>>,
    /// Generation counters: bumping one invalidates any in-flight timeout, which
    /// gives us a sliding window without holding a (non-Send) Timeout handle.
    seed_gen: RwSignal<u32>,
    color_gen: RwSignal<u32>,
}

impl AppState {
    pub fn new() -> Self {
        // Trust anchors default to empty: provisioned explicitly, never baked in.
        AppState {
            user_id: RwSignal::new(LocalStorage::get("user_id").unwrap_or_default()),
            active_role: RwSignal::new(None),
            seed: RwSignal::new(None),
            error: RwSignal::new(None),
            pubkey_hex: RwSignal::new(None),
            esp32_ip: RwSignal::new(LocalStorage::get("esp32_ip").unwrap_or_default()),
            esp32_pubkey: RwSignal::new(LocalStorage::get("esp32_pubkey").unwrap_or_default()),
            esp32_sig_pubkey: RwSignal::new(LocalStorage::get("esp32_sig_pubkey").unwrap_or_default()),
            supervisor_pubkey: RwSignal::new(LocalStorage::get("supervisor_pubkey").unwrap_or_default()),
            new_role_name: RwSignal::new(String::new()),
            new_role_pubkey: RwSignal::new(String::new()),
            last_response: RwSignal::new(None),
            is_fetching_role: RwSignal::new(false),
            parsed_roles: RwSignal::new(None),
            command_color: RwSignal::new(None),
            seed_gen: RwSignal::new(0),
            color_gen: RwSignal::new(0),
        }
    }

    // ---- reactive derived state (read in the view) ----

    /// The connection target and all trust anchors must be provisioned before
    /// the device can be used; forces the config panel open for first-time setup.
    pub fn config_needs_setup(&self) -> bool {
        self.esp32_ip.get().trim().is_empty()
            || self.esp32_pubkey.get().len() != 64
            || self.esp32_sig_pubkey.get().len() != 64
            || self.supervisor_pubkey.get().len() != 64
    }

    /// The user is the supervisor iff their own public key matches the
    /// provisioned supervisor pubkey. Local check -- no device round-trip.
    pub fn is_local_supervisor(&self) -> bool {
        let sup = self.supervisor_pubkey.get();
        let pk = self.pubkey_hex.get();
        sup.len() == 64 && pk.as_deref() == Some(sup.as_str())
    }

    // ---- persisted field setters ----

    pub fn set_user_id(self, v: String) {
        self.user_id.set(v.clone());
        let _ = LocalStorage::set("user_id", v);
    }
    pub fn set_ip(self, v: String) {
        self.esp32_ip.set(v.clone());
        let _ = LocalStorage::set("esp32_ip", v);
    }
    pub fn set_esp_pubkey(self, v: String) {
        self.esp32_pubkey.set(v.clone());
        let _ = LocalStorage::set("esp32_pubkey", v);
    }
    pub fn set_esp_sig_pubkey(self, v: String) {
        self.esp32_sig_pubkey.set(v.clone());
        let _ = LocalStorage::set("esp32_sig_pubkey", v);
    }
    pub fn set_supervisor_pubkey(self, v: String) {
        self.supervisor_pubkey.set(v.clone());
        let _ = LocalStorage::set("supervisor_pubkey", v);
    }

    // ---- auth ----

    pub fn register(self) {
        let user_id = self.user_id.get_untracked();
        spawn_local(async move {
            match webauthn::register(&user_id).await {
                Ok((seed, role)) => self.set_authenticated(seed, role),
                Err(e) => self.error.set(Some(e)),
            }
        });
    }

    pub fn authenticate(self) {
        spawn_local(async move {
            match webauthn::authenticate().await {
                Ok((seed, role)) => self.set_authenticated(seed, role),
                Err(e) => self.error.set(Some(e)),
            }
        });
    }

    fn set_authenticated(self, seed: Vec<u8>, _role: String) {
        let signing_key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
        self.pubkey_hex.set(Some(hex::encode(signing_key.verifying_key().as_bytes())));
        self.seed.set(Some(Zeroizing::new(seed)));
        self.arm_seed_timeout();
        self.active_role.set(None); // force a role fetch from the ESP32
        self.error.set(None);
        self.is_fetching_role.set(true);
        self.send_command(CMD_WHOAMI.to_string());
    }

    pub fn logout(self) {
        self.seed_gen.update(|g| *g = g.wrapping_add(1)); // cancel any pending idle-wipe
        self.seed.set(None);
        self.pubkey_hex.set(None);
        self.active_role.set(None);
        self.error.set(None);
        self.last_response.set(None);
        self.is_fetching_role.set(false);
        self.parsed_roles.set(None);
        self.command_color.set(None);
    }

    /// (Re)arm the sliding idle timeout that wipes the cached seed.
    fn arm_seed_timeout(self) {
        let g = self.seed_gen.get_untracked().wrapping_add(1);
        self.seed_gen.set(g);
        Timeout::new(SEED_TTL_MS, move || {
            if self.seed_gen.get_untracked() == g {
                self.seed.set(None);
                self.error.set(Some(
                    "Session key expired and was wiped from memory. Re-authenticate to send commands."
                        .to_string(),
                ));
            }
        })
        .forget();
    }

    // ---- roles ----

    pub fn add_role(self) {
        let Some(seed) = self.seed.get_untracked() else {
            return;
        };
        let pk_hex = self.pubkey_hex.get_untracked();
        let sup = self.supervisor_pubkey.get_untracked();
        if pk_hex.as_deref() != Some(sup.as_str()) {
            return;
        }
        let signing_key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
        let name = self.new_role_name.get_untracked();
        let pk = self.new_role_pubkey.get_untracked();
        let cert_msg = format!("ROLE:{};PUBKEY:{}", name, pk);
        let cert_sig = signing_key.sign(cert_msg.as_bytes());
        let cert_sig_hex = hex::encode(cert_sig.to_bytes());
        let cmd = format!("{}{} {} {}", CMD_ADD_ROLE, name, pk, cert_sig_hex);
        self.send_command(cmd);
    }

    // ---- commands ----

    /// Set the command LED color, schedule its (sliding) clear, then send.
    pub fn start_command_with_color(self, cmd: String, color: String) {
        self.command_color.set(Some(color));
        let g = self.color_gen.get_untracked().wrapping_add(1);
        self.color_gen.set(g);
        Timeout::new(COMMAND_LED_TIMEOUT_MS as u32, move || {
            if self.color_gen.get_untracked() == g {
                self.command_color.set(None);
            }
        })
        .forget();
        self.send_command(cmd);
    }

    pub fn send_command(self, cmd: String) {
        let Some(seed) = self.seed.get_untracked() else {
            self.error.set(Some("No keys generated. Click 'Register WebAuthn' first.".to_string()));
            return;
        };
        let ip = self.esp32_ip.get_untracked();
        let hex_pub = self.esp32_pubkey.get_untracked();
        let sig_pub_hex = self.esp32_sig_pubkey.get_untracked();

        let mut esp_pub_bytes = [0u8; 32];
        if hex_pub.len() == 64 {
            for i in 0..32 {
                esp_pub_bytes[i] = u8::from_str_radix(&hex_pub[i * 2..i * 2 + 2], 16).unwrap_or(0);
            }
        } else {
            self.error.set(Some("Invalid ESP32 ROM Public Key length".to_string()));
            return;
        }

        let window = web_sys::window().unwrap();
        spawn_local(async move {
            let timestamp = js_sys::Date::now() as u64;
            let (payload, ephemeral_secret) =
                crypto::encrypt_command(seed.as_slice(), &cmd, &esp_pub_bytes, timestamp);

            let url = format!("http://localhost:8000/proxy.php?ip={}", ip);
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
                                            Ok(msg) => self.handle_response(msg),
                                            Err(e) => self.handle_response(e),
                                        }
                                    }
                                }
                                Err(_) => web_sys::console::log_1(
                                    &"Command sent successfully, but couldn't read response body.".into(),
                                ),
                            }
                        } else {
                            self.handle_response(format!(
                                "Connection error: proxy returned HTTP {}. Check the device IP and that it is reachable, then retry.",
                                resp.status()
                            ));
                        }
                    }
                }
                Err(e) => self.handle_response(format!(
                    "Connection error: could not reach the proxy ({:?}). Check the proxy and device IP, then retry.",
                    e
                )),
            }
        });

        // Sliding idle window: active use keeps the seed alive.
        self.arm_seed_timeout();
    }

    fn handle_response(self, resp: String) {
        self.is_fetching_role.set(false);
        if let Some(role) = Role::from_wire(&resp) {
            self.active_role.set(Some(role));
            self.last_response.set(None);
        } else if let Some(payload) = resp.strip_prefix("ROLES:") {
            let mut roles = Vec::new();
            for part in payload.split(',') {
                if part.is_empty() {
                    continue;
                }
                if let Some((name, pk)) = part.split_once(':') {
                    roles.push((name.to_string(), pk.to_string()));
                }
            }
            self.parsed_roles.set(Some(roles));
            self.last_response.set(Some(resp));
        } else {
            self.parsed_roles.set(None);
            self.last_response.set(Some(resp));
        }
    }
}
