use yew::prelude::*;
use wasm_bindgen::prelude::*;
use js_sys;
use wasm_bindgen_futures::spawn_local;
use ed25519_dalek::{SigningKey, Signer};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
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
    AddRole,
}

struct App {
    user_id: String,
    active_role: Option<String>,
    seed: Option<Vec<u8>>,
    error: Option<String>,
    pubkey_hex: Option<String>,
    esp32_ip: String,
    esp32_pubkey: String,
    new_role_name: String,
    new_role_pubkey: String,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        let user_id = LocalStorage::get::<String>("user_id").unwrap_or_else(|_| "supervisor@prfmail.de".to_string());
        let esp32_ip = LocalStorage::get::<String>("esp32_ip").unwrap_or_else(|_| "192.168.178.132".to_string());
        let esp32_pubkey = LocalStorage::get::<String>("esp32_pubkey").unwrap_or_else(|_| "b755ced64d4a27ce32afcf199f18a3ed1f31897028b0ff6e55191ea449db2644".to_string());
        
        Self {
            user_id,
            active_role: None,
            seed: None,
            error: None,
            pubkey_hex: None,
            esp32_ip,
            esp32_pubkey,
            new_role_name: String::new(),
            new_role_pubkey: String::new(),
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
            Msg::Authenticated(seed, role) => {
                let signing_key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
                let verifying_key = signing_key.verifying_key();
                self.pubkey_hex = Some(hex::encode(verifying_key.as_bytes()));
                self.seed = Some(seed);
                self.active_role = Some(role);
                self.error = None;
                true
            }
            Msg::AuthError(err) => {
                self.error = Some(err);
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
            Msg::AddRole => {
                if let Some(seed) = &self.seed {
                    if self.active_role.as_deref() == Some("Supervisor") {
                        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
                        let cert_msg = format!("ROLE:{};PUBKEY:{}", self.new_role_name, self.new_role_pubkey);
                        use ed25519_dalek::Signer;
                        let cert_sig = signing_key.sign(cert_msg.as_bytes());
                        let cert_sig_hex = hex::encode(cert_sig.to_bytes());
                        let cmd = format!("ADD_ROLE {} {} {}", self.new_role_name, self.new_role_pubkey, cert_sig_hex);
                        ctx.link().send_message(Msg::SendCommand(cmd));
                    }
                }
                false
            }
            Msg::SendCommand(cmd_str) => {
                if let (Some(seed), Some(_role)) = (&self.seed, &self.active_role) {
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
                                                                let error_text = if plaintext.contains("Decryption Failed") || plaintext.contains("tampered") || plaintext.contains("Invalid") {
                                                                    Some(plaintext.to_string())
                                                                } else {
                                                                    None
                                                                };
                                                            }
                                                        } else {
                                                            web_sys::console::log_1(&"Failed to decrypt ESP32 response!".into());
                                                        }
                                                    } else {
                                                        web_sys::console::log_1(&"Invalid encrypted response envelope!".into());
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
            <div class="container">
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
                    <div style="background: #2e7d32; padding: 10px; border-radius: 6px; margin-bottom: 20px;">
                        <strong>{ format!("Authenticated as {}", self.active_role.as_ref().unwrap()) }</strong>
                        <div style="font-size: 0.8em; margin-top: 5px;">
                            { "Public Key: " }{ self.pubkey_hex.as_ref().unwrap() }
                        </div>
                    </div>
                    
                    if self.active_role.as_deref() == Some("Supervisor") {
                        <div style="background: #1e1e1e; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #444;">
                            <h3 style="margin-top: 0; color: #ffa000;">{ "Supervisor CA Tools" }</h3>
                            <p style="font-size: 14px; margin-bottom: 10px;">{ "Provision a new RAM Role securely onto the ESP32. The certificate signature proves you authorized this Role & PubKey pairing." }</p>
                            <div style="display: flex; gap: 10px; align-items: flex-end;">
                                <div style="display: flex; flex-direction: column;">
                                    <label style="color: #ccc; font-size: 14px;">{ "New Role Name:" }</label>
                                    <input type="text"
                                        value={self.new_role_name.clone()}
                                        oninput={ctx.link().callback(|e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                            Msg::UpdateNewRoleName(input.value())
                                        })}
                                        placeholder="e.g. Guest"
                                        style="background: #333; border: 1px solid #555; color: #fff; padding: 8px; border-radius: 4px; width: 150px;"
                                    />
                                </div>
                                <div style="display: flex; flex-direction: column;">
                                    <label style="color: #ccc; font-size: 14px;">{ "New Role Ed25519 PubKey:" }</label>
                                    <input type="text"
                                        value={self.new_role_pubkey.clone()}
                                        oninput={ctx.link().callback(|e: InputEvent| {
                                            let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                            Msg::UpdateNewRolePubkey(input.value())
                                        })}
                                        placeholder="64-char hex string"
                                        style="background: #333; border: 1px solid #555; color: #fff; padding: 8px; border-radius: 4px; width: 350px;"
                                    />
                                </div>
                                <button onclick={ctx.link().callback(|_| Msg::AddRole)} style="background: #ffa000; color: #000; font-weight: bold; padding: 8px 15px; height: 35px;">
                                    { "Add Role Securely" }
                                </button>
                            </div>
                        </div>
                    }

                    <div style="margin-top: 20px; display: flex; gap: 20px; align-items: center;">
                        <div style="display: flex; flex-direction: column;">
                            <label style="color: #fff; font-size: 16px; margin-bottom: 5px;">{ "ESP32 IP Address:" }</label>
                            <input type="text"
                                value={self.esp32_ip.clone()}
                                oninput={ctx.link().callback(|e: InputEvent| {
                                    let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                    Msg::UpdateIp(input.value())
                                })}
                                style="background: #333; border: 1px solid #555; color: #fff; padding: 10px; border-radius: 4px; width: 100%; max-width: 300px; box-sizing: border-box; font-size: 16px;"
                            />
                        </div>
                        <div style="display: flex; flex-direction: column; width: 100%; max-width: 650px;">
                            <label style="color: #fff; font-size: 16px; margin-bottom: 5px;">{ "ESP32 ROM Pubkey:" }</label>
                            <input type="text"
                                value={self.esp32_pubkey.clone()}
                                oninput={ctx.link().callback(|e: InputEvent| {
                                    let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                    Msg::UpdateEspPubkey(input.value())
                                })}
                                style="background: #333; border: 1px solid #555; color: #fff; padding: 10px; border-radius: 4px; width: 100%; box-sizing: border-box; font-size: 16px; font-family: monospace;"
                            />
                        </div>
                    </div>
                    
                    <h3>{ "System Controls" }</h3>
                    <button onclick={ctx.link().callback(|_| Msg::SendCommand("COLOR green".to_string()))} style="background: #4caf50; margin-right: 10px;">
                        { "System Normal (Green)" }
                    </button>
                    <button onclick={ctx.link().callback(|_| Msg::SendCommand("COLOR yellow".to_string()))} style="background: #ff9800; margin-right: 10px;">
                        { "Warning (Yellow)" }
                    </button>
                    <button onclick={ctx.link().callback(|_| Msg::SendCommand("COLOR red".to_string()))} style="background: #f44336; margin-right: 10px;">
                        { "Critical Alarm (Red)" }
                    </button>
                    <button onclick={ctx.link().callback(|_| Msg::SendCommand("CLEAR alarm".to_string()))} style="background: #2196f3;">
                        { "Clear Active Alarm" }
                    </button>
                }

                if let Some(err) = &self.error {
                    <div class="error">{ err }</div>
                }
            </div>
        }
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
