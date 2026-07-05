with open("target-esp32s3/src/main.rs", "r") as f:
    content = f.read()

# 1. Add rng usage for init and flash generation
old_init = """    let timg1 = TimerGroup::new(peripherals.TIMG1);
    let rng = Rng::new(peripherals.RNG);
    let init = static_cell::make_static!(esp_wifi::init(timg1.timer0, rng).unwrap());"""

new_init = """    let timg1 = TimerGroup::new(peripherals.TIMG1);
    let mut rng = Rng::new(peripherals.RNG);
    
    let mut flash = FlashStorage::new();
    let mut seed_buf = [0u8; 4096];
    let mut esp_seed = [0u8; 32];
    let mut has_seed = false;
    
    if flash.read(0x210000, &mut seed_buf).is_ok() {
        let is_empty = seed_buf[0..32].iter().all(|&b| b == 0xFF || b == 0x00);
        if !is_empty {
            esp_seed.copy_from_slice(&seed_buf[0..32]);
            has_seed = true;
        }
    }
    
    if !has_seed {
        for chunk in esp_seed.chunks_mut(4) {
            let rand_val = rng.random();
            chunk.copy_from_slice(&rand_val.to_le_bytes());
        }
        let mut write_buf = [0u8; 4096];
        write_buf[0..32].copy_from_slice(&esp_seed);
        let _ = flash.write(0x210000, &write_buf);
    }
    
    let esp_x25519_secret = x25519_dalek::StaticSecret::from(esp_seed);
    let esp_x25519_pub = x25519_dalek::PublicKey::from(&esp_x25519_secret);
    
    let mut hex_x25519 = heapless::String::<64>::new();
    use core::fmt::Write;
    for b in esp_x25519_pub.as_bytes() { let _ = write!(&mut hex_x25519, "{:02x}", b); }
    info!("ESP32 X25519 PubKey: {}", hex_x25519);
    
    // We can still pass rng to esp_wifi because we didn't consume it
    let init = static_cell::make_static!(esp_wifi::init(timg1.timer0, rng).unwrap());"""

content = content.replace(old_init, new_init)

# 2. Update TCP parsing to expect EPHEMERAL_PUB;IV;CIPHERTEXT and compute shared secret
old_tcp = """                    let mut parts = payload.split(';');
                    let iv_hex = parts.next().unwrap_or("");
                    let ciphertext_hex = parts.next().unwrap_or("");
                    
                    let mut valid_crypto = true;"""

new_tcp = """                    let mut parts = payload.split(';');
                    let ephemeral_pub_hex = parts.next().unwrap_or("");
                    let iv_hex = parts.next().unwrap_or("");
                    let ciphertext_hex = parts.next().unwrap_or("");
                    
                    let mut valid_crypto = true;
                    let mut ephemeral_pub_bytes = [0u8; 32];
                    if ephemeral_pub_hex.len() == 64 {
                        for i in 0..32 {
                            if let Ok(b) = u8::from_str_radix(&ephemeral_pub_hex[i*2..i*2+2], 16) {
                                ephemeral_pub_bytes[i] = b;
                            } else { valid_crypto = false; }
                        }
                    } else { valid_crypto = false; }
"""
content = content.replace(old_tcp, new_tcp)

# 3. Update AES key generation
old_aes = """                        #[allow(deprecated)]
                        let key = Key::<Aes256Gcm>::from_slice(&supervisor_key);
                        let cipher = Aes256Gcm::new(key);
                        #[allow(deprecated)]"""

new_aes = """                        let ephemeral_pub = x25519_dalek::PublicKey::from(ephemeral_pub_bytes);
                        let shared_secret = esp_x25519_secret.diffie_hellman(&ephemeral_pub);
                        
                        #[allow(deprecated)]
                        let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
                        let cipher = Aes256Gcm::new(key);
                        #[allow(deprecated)]"""
content = content.replace(old_aes, new_aes)

# 4. Update the response encryption to generate its own ephemeral key and derive the shared secret
old_resp_aes = """                    #[allow(deprecated)]
                    use aes_gcm::{Aes256Gcm, Key, Nonce};
                    #[allow(deprecated)]
                    use aes_gcm::aead::{AeadInPlace, KeyInit};
                    
                    #[allow(deprecated)]
                    let key = Key::<Aes256Gcm>::from_slice(&supervisor_key);
                    let cipher = Aes256Gcm::new(key);
                    
                    let mut iv = [0u8; 12];
                    let ticks = embassy_time::Instant::now().as_ticks();"""

new_resp_aes = """                    #[allow(deprecated)]
                    use aes_gcm::{Aes256Gcm, Key, Nonce};
                    #[allow(deprecated)]
                    use aes_gcm::aead::{AeadInPlace, KeyInit};
                    
                    // ESP32 generates ephemeral X25519 for the response
                    let ticks = embassy_time::Instant::now().as_ticks();
                    let mut resp_ephemeral_seed = [0u8; 32];
                    for i in 0..8 {
                        resp_ephemeral_seed[i] = ((ticks >> (i * 8)) & 0xFF) as u8;
                        resp_ephemeral_seed[i+8] = ((ticks >> (i * 8)) & 0xFF) as u8 ^ 0xAA;
                    }
                    let resp_ephemeral_secret = x25519_dalek::StaticSecret::from(resp_ephemeral_seed);
                    let resp_ephemeral_pub = x25519_dalek::PublicKey::from(&resp_ephemeral_secret);
                    
                    // The WebApp must have sent an ephemeral pubkey that we used earlier.
                    // Wait, the WebApp's ephemeral pubkey was used for the request.
                    // We can just use the exact same shared secret we just computed, 
                    // OR we compute a new one using the WebApp's ephemeral pubkey.
                    // Actually, if we use the WebApp's ephemeral pubkey, we just re-use the `shared_secret`.
                    // But wait, `shared_secret` is out of scope here.
                    // Let's just recompute it, or rely on the `ephemeral_pub` we parsed!
                    
                    let ephemeral_pub = x25519_dalek::PublicKey::from(ephemeral_pub_bytes);
                    let resp_shared_secret = resp_ephemeral_secret.diffie_hellman(&ephemeral_pub);
                    
                    #[allow(deprecated)]
                    let key = Key::<Aes256Gcm>::from_slice(resp_shared_secret.as_bytes());
                    let cipher = Aes256Gcm::new(key);
                    
                    let mut iv = [0u8; 12];
                    for i in 0..8 {"""

content = content.replace(old_resp_aes, new_resp_aes)

# 5. Make sure ephemeral_pub_bytes is available in the outer scope
# By moving it up
# Already handled by adding it where payload is split, which is inside the loop. But we need it for response encryption.
# In the original, payload processing was:
# let mut ephemeral_pub_bytes = [0u8; 32]; ...
# Which is in the loop, so it IS available later in the response block!

# 6. Prepend the response with our ephemeral public key
old_final_resp = """                        let mut cipher_hex_out = heapless::String::<512>::new();
                        for b in ciphertext.as_slice() {
                            let _ = write!(&mut cipher_hex_out, "{:02x}", b);
                        }
                        
                        let _ = write!(&mut final_response, "{};{}", iv_hex_out, cipher_hex_out);"""

new_final_resp = """                        let mut cipher_hex_out = heapless::String::<512>::new();
                        for b in ciphertext.as_slice() {
                            let _ = write!(&mut cipher_hex_out, "{:02x}", b);
                        }
                        
                        let mut resp_eph_pub_hex = heapless::String::<64>::new();
                        for b in resp_ephemeral_pub.as_bytes() {
                            let _ = write!(&mut resp_eph_pub_hex, "{:02x}", b);
                        }
                        
                        let _ = write!(&mut final_response, "{};{};{}", resp_eph_pub_hex, iv_hex_out, cipher_hex_out);"""

content = content.replace(old_final_resp, new_final_resp)

with open("target-esp32s3/src/main.rs", "w") as f:
    f.write(content)
