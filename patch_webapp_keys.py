with open("supervisor-web/src/main.rs", "r") as f:
    content = f.read()

# Add x25519_dalek to imports
imports = """use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};"""
content = content.replace("use ed25519_dalek::{SigningKey, Signer, VerifyingKey};", imports)

# Update SendCommand logic
old_send = """                    let mut esp_pub_bytes = [0u8; 32];
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
                        let signing_key = SigningKey::from_bytes(seed_clone.as_slice().try_into().unwrap());
                        let signature = signing_key.sign(cmd_str.as_bytes());
                        let sig_hex = hex::encode(signature.to_bytes());
                        
                        let plaintext = format!("{};{};{}", role_clone, cmd_str, sig_hex);
                        
                        use aes_gcm::{Aes256Gcm, Key, Nonce};
                        use aes_gcm::aead::{AeadInPlace, KeyInit};
                        use rand_core::RngCore;
                        
                        let mut iv = [0u8; 12];
                        OsRng.fill_bytes(&mut iv);
                        let nonce = Nonce::from_slice(&iv);
                        
                        let mut ciphertext = plaintext.into_bytes();
                        let key = Key::<Aes256Gcm>::from_slice(&esp_pub_bytes);
                        let cipher = Aes256Gcm::new(key);
                        
                        let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut ciphertext).unwrap();
                        ciphertext.extend_from_slice(&tag);
                        
                        let payload = format!("{};{}", hex::encode(iv), hex::encode(ciphertext));"""

new_send = """                    let mut esp_pub_bytes = [0u8; 32];
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
                        let signing_key = SigningKey::from_bytes(seed_clone.as_slice().try_into().unwrap());
                        let signature = signing_key.sign(cmd_str.as_bytes());
                        let sig_hex = hex::encode(signature.to_bytes());
                        
                        let plaintext = format!("{};{};{}", role_clone, cmd_str, sig_hex);
                        
                        use aes_gcm::{Aes256Gcm, Key, Nonce};
                        use aes_gcm::aead::{AeadInPlace, KeyInit};
                        use rand_core::RngCore;
                        
                        // Generate Ephemeral X25519 Key
                        let mut eph_seed = [0u8; 32];
                        OsRng.fill_bytes(&mut eph_seed);
                        let ephemeral_secret = StaticSecret::from(eph_seed);
                        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
                        
                        let esp_pub = X25519PublicKey::from(esp_pub_bytes);
                        let shared_secret = ephemeral_secret.diffie_hellman(&esp_pub);
                        
                        let mut iv = [0u8; 12];
                        OsRng.fill_bytes(&mut iv);
                        let nonce = Nonce::from_slice(&iv);
                        
                        let mut ciphertext = plaintext.into_bytes();
                        let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
                        let cipher = Aes256Gcm::new(key);
                        
                        let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut ciphertext).unwrap();
                        ciphertext.extend_from_slice(&tag);
                        
                        let payload = format!("{};{};{}", hex::encode(ephemeral_pub.as_bytes()), hex::encode(iv), hex::encode(ciphertext));"""

content = content.replace(old_send, new_send)

# Update receiving logic
old_recv = """                                                    let mut parts = text.split(';');
                                                    let resp_iv_hex = parts.next().unwrap_or("");
                                                    let resp_cipher_hex = parts.next().unwrap_or("");
                                                    
                                                    let mut valid_crypto = true;
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
                                                        let len = resp_cipher.len();
                                                        let (msg, tag_bytes) = resp_cipher.split_at_mut(len - 16);
                                                        let resp_tag = aes_gcm::Tag::from_slice(tag_bytes);
                                                        let resp_nonce = Nonce::from_slice(&resp_iv);
                                                        
                                                        if cipher.decrypt_in_place_detached(resp_nonce, b"", msg, resp_tag).is_ok() {"""

new_recv = """                                                    let mut parts = text.split(';');
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
                                                        let dec_key = Key::<Aes256Gcm>::from_slice(dec_shared_secret.as_bytes());
                                                        let dec_cipher = Aes256Gcm::new(dec_key);
                                                        
                                                        let len = resp_cipher.len();
                                                        let (msg, tag_bytes) = resp_cipher.split_at_mut(len - 16);
                                                        let resp_tag = aes_gcm::Tag::from_slice(tag_bytes);
                                                        let resp_nonce = Nonce::from_slice(&resp_iv);
                                                        
                                                        if dec_cipher.decrypt_in_place_detached(resp_nonce, b"", msg, resp_tag).is_ok() {"""
content = content.replace(old_recv, new_recv)

with open("supervisor-web/src/main.rs", "w") as f:
    f.write(content)
