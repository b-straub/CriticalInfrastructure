use yew::prelude::*;
use wasm_bindgen::prelude::*;
use js_sys;
use wasm_bindgen_futures::spawn_local;
use ed25519_dalek::{SigningKey, Signer};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use shared::terminology::*;
use rand_core::OsRng;
use hex;
use gloo_storage::{LocalStorage, Storage};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn create_passkey_prf(user_id: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn get_passkey_prf() -> Result<JsValue, JsValue>;
}

enum Msg {
    UpdateUserId(String),
    Register,
    Authenticate,
    Authenticated(Vec<u8>, String),
    AuthError(String),
    UpdateIp(String),
    UpdateEspPubkey(String),
    SendCommand(String),
    UpdateNewRoleName(String),
    UpdateNewRolePubkey(String),
    UpdateSupervisorPubkey(String),
    AddRole,
    Logout,
    CommandResponse(String),
}

struct App {
    user_id: String,
    active_role: Option<String>,
    seed: Option<Vec<u8>>,
    error: Option<String>,
    pubkey_hex: Option<String>,
    esp32_ip: String,
    esp32_pubkey: String,
    supervisor_pubkey: String,
    new_role_name: String,
    new_role_pubkey: String,
    last_response: Option<String>,
    is_fetching_role: bool,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        let user_id = LocalStorage::get::<String>("user_id").unwrap_or_else(|_| "supervisor@prfmail.de".to_string());
        let esp32_ip = LocalStorage::get::<String>("esp32_ip").unwrap_or_else(|_| "192.168.178.132".to_string());
        let esp32_pubkey = LocalStorage::get::<String>("esp32_pubkey").unwrap_or_else(|_| "b755ced64d4a27ce32afcf199f18a3ed1f31897028b0ff6e55191ea449db2644".to_string());
        let supervisor_pubkey = LocalStorage::get::<String>("supervisor_pubkey").unwrap_or_else(|_| "ccdef32d7cde52d7bf6c7dbde887dc9d25414e9ff57bb5aee5d5da65e5f6e439".to_string());
        
        Self {
            user_id,
            active_role: None,
            seed: None,
            error: None,
            pubkey_hex: None,
            esp32_ip,
            esp32_pubkey,
            supervisor_pubkey,
            new_role_name: String::new(),
            new_role_pubkey: String::new(),
            last_response: None,
            is_fetching_role: false,
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
            Msg::Register => {
                let link = ctx.link().clone();
                let user_id = self.user_id.clone();
                spawn_local(async move {
                    match create_passkey_prf(&user_id).await {
                        Ok(val) => {
                            let seed_array = js_sys::Uint8Array::new(&js_sys::Reflect::get(&val, &JsValue::from_str("seed")).unwrap());
                            let seed = seed_array.to_vec();
                            let role_str = js_sys::Reflect::get(&val, &JsValue::from_str("role")).unwrap().as_string().unwrap();
                            link.send_message(Msg::Authenticated(seed, role_str));
                        }
                        Err(err) => {
                            let msg = if let Some(e) = err.as_string() { e } else if let Some(m) = js_sys::Reflect::get(&err, &JsValue::from_str("message")).ok().and_then(|v| v.as_string()) { m } else { format!("{:?}", err) };
                            link.send_message(Msg::AuthError(msg));
                        }
                    }
                });
                false
            }
            Msg::Authenticate => {
                let link = ctx.link().clone();
                spawn_local(async move {
                    match get_passkey_prf().await {
                        Ok(val) => {
                            let seed_array = js_sys::Uint8Array::new(&js_sys::Reflect::get(&val, &JsValue::from_str("seed")).unwrap());
                            let seed = seed_array.to_vec();
                            let role_str = js_sys::Reflect::get(&val, &JsValue::from_str("role")).unwrap().as_string().unwrap();
                            link.send_message(Msg::Authenticated(seed, role_str));
                        }
                        Err(err) => {
                            let msg = if let Some(e) = err.as_string() { e } else if let Some(m) = js_sys::Reflect::get(&err, &JsValue::from_str("message")).ok().and_then(|v| v.as_string()) { m } else { format!("{:?}", err) };
                            link.send_message(Msg::AuthError(msg));
                        }
                    }
                });
                false
            }
            Msg::Authenticated(seed, _role) => {
                let signing_key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
                let verifying_key = signing_key.verifying_key();
                self.pubkey_hex = Some(hex::encode(verifying_key.as_bytes()));
                self.seed = Some(seed);
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
            Msg::Logout => {
                self.seed = None;
                self.pubkey_hex = None;
                self.active_role = None;
                self.error = None;
                self.last_response = None;
                self.is_fetching_role = false;
                true
            }
            Msg::CommandResponse(resp) => {
                self.is_fetching_role = false;
                if ["Admin", "Supervisor", "Operator", "Observer"].contains(&resp.as_str()) {
                    self.active_role = Some(resp);
                    self.last_response = None;
                } else {
                    self.last_response = Some(resp);
                }
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
                if let Some(seed) = &self.seed {
                    let seed_clone = seed.clone();
                    let ip_clone = self.esp32_ip.clone();
                    let hex_pub = self.esp32_pubkey.clone();
                    
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
                        let signed_payload = format!("{}|{}", timestamp, cmd_str);
                        let signing_key = SigningKey::from_bytes(seed_clone.as_slice().try_into().unwrap());
                        let signature = signing_key.sign(signed_payload.as_bytes());
                        let sig_hex = hex::encode(signature.to_bytes());
                        
                        let plaintext = format!("{};{};{}", timestamp, cmd_str, sig_hex);
                        
                        use aes_gcm::{Aes256Gcm, Key, Nonce};
                        use aes_gcm::aead::{AeadInPlace, KeyInit};
                        use rand_core::RngCore;
                        use sha2::{Sha256, Digest};
                        
                        // Generate Ephemeral X25519 Key
                        let mut eph_seed = [0u8; 32];
                        OsRng.fill_bytes(&mut eph_seed);
                        let ephemeral_secret = StaticSecret::from(eph_seed);
                        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
                        
                        let esp_pub = X25519PublicKey::from(esp_pub_bytes);
                        let shared_secret = ephemeral_secret.diffie_hellman(&esp_pub);
                        
                        let tx_key_hash = Sha256::digest(shared_secret.as_bytes());
                        let tx_key = Key::<Aes256Gcm>::from_slice(&tx_key_hash);
                        
                        let mut iv = [0u8; 12];
                        OsRng.fill_bytes(&mut iv);
                        let nonce = Nonce::from_slice(&iv);
                        
                        let mut ciphertext = plaintext.into_bytes();
                        let cipher = Aes256Gcm::new(tx_key);
                        
                        let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut ciphertext).unwrap();
                        ciphertext.extend_from_slice(&tag);
                        
                        let payload = format!("{};{};{}", hex::encode(ephemeral_pub.as_bytes()), hex::encode(iv), hex::encode(ciphertext));
                        
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
                                        let text_promise = resp.text().unwrap();
                                        match wasm_bindgen_futures::JsFuture::from(text_promise).await {
                                            Ok(text_val) => {
                                                if let Some(text) = text_val.as_string() {
                                                    let mut parts = text.split(';');
                                                    let resp_eph_pub_hex = parts.next().unwrap_or("");
                                                    let resp_iv_hex = parts.next().unwrap_or("");
                                                    let resp_cipher_hex = parts.next().unwrap_or("");
                                                    
                                                    let mut valid_crypto = true;
                                                    
                                                    let mut resp_eph_pub_bytes = [0u8; 32];
                                                    if resp_eph_pub_hex.len() == 64 {
                                                        for i in 0..32 {
                                                            resp_eph_pub_bytes[i] = u8::from_str_radix(&resp_eph_pub_hex[i*2..i*2+2], 16).unwrap_or(0);
                                                        }
                                                    } else { valid_crypto = false; }
                                                    
                                                    let mut resp_iv = [0u8; 12];
                                                    if resp_iv_hex.len() == 24 {
                                                        for i in 0..12 {
                                                            resp_iv[i] = u8::from_str_radix(&resp_iv_hex[i*2..i*2+2], 16).unwrap_or(0);
                                                        }
                                                    } else { valid_crypto = false; }
                                                    
                                                    let mut resp_cipher = Vec::new();
                                                    if resp_cipher_hex.len() % 2 == 0 {
                                                        for i in 0..(resp_cipher_hex.len()/2) {
                                                            resp_cipher.push(u8::from_str_radix(&resp_cipher_hex[i*2..i*2+2], 16).unwrap_or(0));
                                                        }
                                                    } else { valid_crypto = false; }
                                                    
                                                    if valid_crypto && resp_cipher.len() >= 16 {
                                                        let resp_eph_pub = X25519PublicKey::from(resp_eph_pub_bytes);
                                                        let dec_shared_secret = ephemeral_secret.diffie_hellman(&resp_eph_pub);
                                                        let rx_key_hash = sha2::Sha256::digest(dec_shared_secret.as_bytes());
                                                        let dec_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&rx_key_hash));
                                                        
                                                        let len = resp_cipher.len();
                                                        let (msg, tag_bytes) = resp_cipher.split_at_mut(len - 16);
                                                        let resp_tag = aes_gcm::Tag::from_slice(tag_bytes);
                                                        let resp_nonce = Nonce::from_slice(&resp_iv);
                                                        
                                                        if dec_cipher.decrypt_in_place_detached(resp_nonce, b"", msg, resp_tag).is_ok() {
                                                            if let Ok(plaintext) = core::str::from_utf8(msg) {
                                                                web_sys::console::log_1(&format!("ESP32 Verified Response: {}", plaintext).into());
                                                                link.send_message(Msg::CommandResponse(plaintext.to_string()));
                                                            }
                                                        } else {
                                                            web_sys::console::log_1(&"Failed to decrypt ESP32 response!".into());
                                                            link.send_message(Msg::CommandResponse("Failed to decrypt ESP32 response!".to_string()));
                                                        }
                                                    } else {
                                                        web_sys::console::log_1(&"Invalid encrypted response envelope!".into());
                                                        link.send_message(Msg::CommandResponse("Invalid encrypted response envelope!".to_string()));
                                                    }
                                                }
                                            }
                                            Err(_) => web_sys::console::log_1(&"Command sent successfully, but couldn't read response body.".into()),
                                        }
                                    } else {
                                        web_sys::console::log_1(&format!("Proxy returned error: HTTP {}", resp.status()).into());
                                    }
                                }
                            }
                            Err(e) => web_sys::console::log_1(&format!("Failed to send command: {:?}", e).into()),
                        }
                    });
                } else {
                    self.error = Some("No keys generated. Click 'Register WebAuthn' first.".to_string());
                }
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div class="container" style="max-width: 900px; margin: 0 auto; font-family: 'Inter', system-ui, sans-serif; background: #121212; color: #f5f5f5; padding: 30px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
                <style>
                    { "
                        body { background: #0a0a0a; display: flex; justify-content: center; padding-top: 50px; margin: 0; }
                        h2 { font-weight: 600; font-size: 24px; border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 25px; }
                        input:focus, select:focus { outline: none; border-color: #ffa000; box-shadow: 0 0 5px rgba(255, 160, 0, 0.5); }
                        button { transition: opacity 0.2s, transform 0.1s; }
                        button:active:not(:disabled) { transform: scale(0.98); }
                        button:hover:not(:disabled) { opacity: 0.9; }
                    " }
                </style>
                <h2>{ "Critical Infrastructure Dashboard" }</h2>
                
                if self.seed.is_none() {
                    <p>{ "Authenticate with your FIDO2 Passkey to unlock the dashboard." }</p>
                    <div style="margin-bottom: 20px; display: flex; align-items: center;">
                        <label style="margin-right: 10px;">{ "User ID:" }</label>
                        <input type="text" value={self.user_id.clone()} oninput={ctx.link().callback(|e: InputEvent| {
                            let target = e.target().unwrap();
                            let value = js_sys::Reflect::get(&target, &wasm_bindgen::JsValue::from_str("value")).unwrap().as_string().unwrap();
                            Msg::UpdateUserId(value)
                        })} style="padding: 5px; font-size: 16px; width: 250px; background: #333; color: white; border: 1px solid #555;" />
                    </div>
                    <button onclick={ctx.link().callback(|_| Msg::Authenticate)}>
                        { "Login with Passkey" }
                    </button>
                    <button onclick={ctx.link().callback(|_| Msg::Register)} style="margin-left: 10px; background: #607d8b;">
                        { "Register New Passkey" }
                    </button>
                } else {
                    <div style="background: #2e7d32; padding: 10px 15px; border-radius: 6px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                        <div>
                            <strong style="font-size: 1.1em;">
                                { if self.is_fetching_role {
                                    format!("Authenticated: Fetching role from ESP32...")
                                } else {
                                    format!("Authenticated: {}", self.active_role.as_deref().unwrap_or("Role Fetch Failed / Unknown"))
                                } }
                            </strong>
                            <div style="font-size: 0.85em; margin-top: 5px; opacity: 0.9; font-family: monospace;">
                                { "Public Key: " }{ self.pubkey_hex.as_ref().unwrap() }
                            </div>
                        </div>
                        <button onclick={ctx.link().callback(|_| Msg::Logout)} style="background: #d32f2f; color: white; padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            { "Logout" }
                        </button>
                    </div>
                    
                    if !self.is_fetching_role && (self.active_role.as_deref() == Some("Supervisor") || self.active_role.is_none()) {
                        <div style="margin-top: 20px; display: flex; flex-direction: column; gap: 15px; max-width: 800px; padding: 15px; background: #1e1e1e; border: 1px dashed #555; border-radius: 6px;">
                            <h4 style="margin: 0; color: #888;">{ "Connection Configuration" }</h4>
                            <div style="display: flex; flex-direction: column;">
                                <label style="color: #ccc; font-size: 14px; margin-bottom: 5px; font-weight: bold;">{ "ESP32 IP Address:" }</label>
                                <input type="text"
                                    value={self.esp32_ip.clone()}
                                    oninput={ctx.link().callback(|e: InputEvent| {
                                        let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                        Msg::UpdateIp(input.value())
                                    })}
                                    style="background: #333; border: 1px solid #555; color: #fff; padding: 10px; border-radius: 4px; width: 100%; max-width: 300px; box-sizing: border-box; font-size: 16px;"
                                />
                            </div>
                            <div style="display: flex; flex-direction: column; width: 100%;">
                                <label style="color: #ccc; font-size: 14px; margin-bottom: 5px; font-weight: bold;">{ "ESP32 ROM Pubkey:" }</label>
                                <input type="text"
                                    value={self.esp32_pubkey.clone()}
                                    oninput={ctx.link().callback(|e: InputEvent| {
                                        let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                        Msg::UpdateEspPubkey(input.value())
                                    })}
                                    style="background: #333; border: 1px solid #555; color: #fff; padding: 10px; border-radius: 4px; width: 100%; box-sizing: border-box; font-size: 16px; font-family: monospace;"
                                />
                            </div>
                            <div style="display: flex; flex-direction: column; width: 100%;">
                                <label style="color: #ccc; font-size: 14px; margin-bottom: 5px; font-weight: bold;">{ "Supervisor Pubkey:" }</label>
                                <input type="text"
                                    value={self.supervisor_pubkey.clone()}
                                    oninput={ctx.link().callback(|e: InputEvent| {
                                        let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                        Msg::UpdateSupervisorPubkey(input.value())
                                    })}
                                    style="background: #333; border: 1px solid #555; color: #fff; padding: 10px; border-radius: 4px; width: 100%; box-sizing: border-box; font-size: 16px; font-family: monospace;"
                                />
                            </div>
                        </div>
                    }

                    <hr style="border-color: #333; margin: 30px 0;" />
                    
                    if let Some(resp) = &self.last_response {
                        <div style="background: #2a2a2a; border-left: 4px solid #4caf50; padding: 15px; margin-bottom: 20px; border-radius: 4px; word-break: break-all;">
                            <strong style="color: #4caf50; display: block; margin-bottom: 5px;">{ "Last ESP32 Response:" }</strong>
                            <code style="font-family: monospace; color: #fff;">{ resp }</code>
                        </div>
                    }

                    if self.active_role.is_none() && !self.is_fetching_role {
                        <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px;">
                            <button onclick={ctx.link().callback(|_| Msg::SendCommand(CMD_WHOAMI.to_string()))} style="background: #9c27b0; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                { "Retry Fetch Role" }
                            </button>
                        </div>
                    }

                    if let Some(role) = &self.active_role {
                        if role == "Supervisor" {
                            <div style="background: #1e1e1e; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #444;">
                                <h3 style="margin-top: 0; color: #ffa000;">{ "Supervisor CA Tools" }</h3>
                                <p style="font-size: 14px; margin-bottom: 10px;">{ "Provision a new RAM Role securely onto the ESP32." }</p>
                                <div style="display: flex; gap: 15px; align-items: flex-end; flex-wrap: wrap;">
                                    <div style="display: flex; flex-direction: column; min-width: 150px;">
                                        <label style="color: #ccc; font-size: 14px; margin-bottom: 5px; font-weight: bold;">{ "New Role Name:" }</label>
                                        <select
                                            value={self.new_role_name.clone()}
                                            onchange={ctx.link().callback(|e: Event| {
                                                let select = e.target_unchecked_into::<web_sys::HtmlSelectElement>();
                                                Msg::UpdateNewRoleName(select.value())
                                            })}
                                            style="background: #333; border: 1px solid #555; color: #fff; padding: 0 10px; border-radius: 4px; width: 100%; height: 36px; box-sizing: border-box; mragin: 0;"
                                        >
                                            <option value="" disabled=true selected={self.new_role_name.is_empty()}>{ "Select Role..." }</option>
                                            <option value={ROLE_ADMIN} selected={self.new_role_name == ROLE_ADMIN}>{ ROLE_ADMIN }</option>
                                            <option value={ROLE_OPERATOR} selected={self.new_role_name == ROLE_OPERATOR}>{ ROLE_OPERATOR }</option>
                                            <option value={ROLE_OBSERVER} selected={self.new_role_name == ROLE_OBSERVER}>{ ROLE_OBSERVER }</option>
                                        </select>
                                    </div>
                                    <div style="display: flex; flex-direction: column; flex-grow: 1; min-width: 300px;">
                                        <label style="color: #ccc; font-size: 14px; margin-bottom: 5px; font-weight: bold;">{ "Role Ed25519 PubKey:" }</label>
                                        <input type="text"
                                            value={self.new_role_pubkey.clone()}
                                            oninput={ctx.link().callback(|e: InputEvent| {
                                                let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                Msg::UpdateNewRolePubkey(input.value())
                                            })}
                                            placeholder="64-char hex string"
                                            style="background: #333; border: 1px solid #555; color: #fff; padding: 0 10px; border-radius: 4px; width: 100%; height: 36px; box-sizing: border-box; font-family: monospace; margin: 0;"
                                        />
                                    </div>
                                    <button 
                                        onclick={ctx.link().callback(|_| Msg::AddRole)}
                                        disabled={self.new_role_name.is_empty() || self.new_role_pubkey.len() != 64}
                                        style={if self.new_role_name.is_empty() || self.new_role_pubkey.len() != 64 {
                                            "background: #555; color: #888; font-weight: bold; padding: 0 20px; height: 36px; border-radius: 4px; border: none; cursor: not-allowed; white-space: nowrap; box-sizing: border-box; margin: 0;"
                                        } else {
                                            "background: #ffa000; color: #000; font-weight: bold; padding: 0 20px; height: 36px; border-radius: 4px; border: none; cursor: pointer; white-space: nowrap; transition: background 0.3s ease; box-sizing: border-box; margin: 0;"
                                        }}
                                    >
                                        { "Add Role Securely" }
                                    </button>
                                    <button 
                                        onclick={
                                            let role_name = self.new_role_name.clone();
                                            ctx.link().callback(move |_| Msg::SendCommand(format!("{} {}", CMD_REVOKE_ROLE, role_name)))
                                        }
                                        disabled={self.new_role_name.is_empty()}
                                        style={if self.new_role_name.is_empty() {
                                            "background: #555; color: #888; font-weight: bold; padding: 0 20px; height: 36px; border-radius: 4px; border: none; cursor: not-allowed; white-space: nowrap; box-sizing: border-box; margin: 0;"
                                        } else {
                                            "background: #f44336; color: #fff; font-weight: bold; padding: 0 20px; height: 36px; border-radius: 4px; border: none; cursor: pointer; white-space: nowrap; transition: background 0.3s ease; box-sizing: border-box; margin: 0;"
                                        }}
                                    >
                                        { "Revoke Role" }
                                    </button>
                                </div>
                                <div style="margin-top: 15px;">
                                    <button onclick={ctx.link().callback(|_| Msg::SendCommand(CMD_LIST_ROLES.to_string()))} style="background: #2196f3; padding: 8px 16px; height: 36px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold; box-sizing: border-box;">
                                        { "List Roles" }
                                    </button>
                                </div>
                            </div>
                        } else {
                            <h3>{ "System Controls" }</h3>
                            <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px;">
                                <button onclick={ctx.link().callback(|_| Msg::SendCommand(CMD_READ_SENSOR.to_string()))} style="background: #4caf50; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                    { "Read Sensors (10s Green)" }
                                </button>
                                
                                if role == "Operator" || role == "Admin" {
                                    <button onclick={ctx.link().callback(|_| Msg::SendCommand(format!("{}20.0", CMD_SET_THRESHOLD)))} style="background: #ff9800; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                        { "Set Threshold (20C) (10s Yellow)" }
                                    </button>
                                    <button onclick={ctx.link().callback(|_| Msg::SendCommand(format!("{}30.0", CMD_SET_THRESHOLD)))} style="background: #ff9800; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                        { "Set Threshold (30C) (10s Yellow)" }
                                    </button>
                                }
                                
                                if role == "Admin" {
                                    <button onclick={ctx.link().callback(|_| Msg::SendCommand(CMD_CLEAR_ALARM.to_string()))} style="background: #2196f3; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                        { "Clear Alarm (10s Red)" }
                                    </button>
                                    <button onclick={ctx.link().callback(|_| Msg::SendCommand(CMD_COLOR_RED.to_string()))} style="background: #f44336; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                        { "Test Red (10s)" }
                                    </button>
                                }
                            </div>
                        }
                    }
                    
                    if let Some(err) = &self.error {
                        <div class="error">{ err }</div>
                    }
                }
            </div>
        }
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
