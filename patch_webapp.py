import re

with open("supervisor-web/src/main.rs", "r") as f:
    content = f.read()

# Replace Msg enum
content = content.replace("SendCommand(&'static str),", """SendCommand(String),
    UpdateNewRoleName(String),
    UpdateNewRolePubkey(String),
    AddRole,""")

# Add new fields to App struct
content = content.replace("esp32_pubkey: String,", """esp32_pubkey: String,
    new_role_name: String,
    new_role_pubkey: String,""")

# Initialize new fields in Component::create
content = content.replace("esp32_pubkey,", """esp32_pubkey,
            new_role_name: String::new(),
            new_role_pubkey: String::new(),""")

# Add match arms
match_arms = """            Msg::UpdateNewRoleName(name) => {
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
            Msg::SendCommand(cmd_str) => {"""
content = content.replace("Msg::SendCommand(cmd_str) => {", match_arms)

# Update UI callbacks
content = content.replace("Msg::SendCommand(\"COLOR green\")", "Msg::SendCommand(\"COLOR green\".to_string())")
content = content.replace("Msg::SendCommand(\"COLOR yellow\")", "Msg::SendCommand(\"COLOR yellow\".to_string())")
content = content.replace("Msg::SendCommand(\"COLOR red\")", "Msg::SendCommand(\"COLOR red\".to_string())")
content = content.replace("Msg::SendCommand(\"CLEAR alarm\")", "Msg::SendCommand(\"CLEAR alarm\".to_string())")

# Add Supervisor UI panel
panel_ui = """
                    <div style="margin-top: 20px; display: flex; gap: 20px; align-items: center;">
                        <div style="display: flex; flex-direction: column;">
                            <label style="color: #fff; font-size: 16px; margin-bottom: 5px;">{ "ESP32 IP Address:" }</label>"""

new_panel_ui = """
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
                            <label style="color: #fff; font-size: 16px; margin-bottom: 5px;">{ "ESP32 IP Address:" }</label>"""

content = content.replace(panel_ui, new_panel_ui)

with open("supervisor-web/src/main.rs", "w") as f:
    f.write(content)

print("WebApp patched")
