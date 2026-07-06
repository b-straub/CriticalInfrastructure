//! The dashboard UI (Yew view), separated from app state and logic.
//!
//! A child module of the crate root, so it can read `App`'s fields and
//! call its helper methods directly.

use yew::prelude::*;
use shared::terminology::*;
use shared::Role;
use crate::{App, Msg};

pub fn render(app: &App, ctx: &Context<App>) -> Html {
        let is_alarm = app.last_response.as_ref().map(|r| r.contains("(ALARM!)")).unwrap_or(false);
        let bg_color = if is_alarm {
            "#b71c1c" // Flashing red (solid red for simplicity in static CSS, or animation if possible)
        } else if let Some(color) = &app.command_color {
            match color.as_str() {
                "green" => "#1b5e20",
                "yellow" => "#f57f17",
                "red" => "#b71c1c",
                _ => "#2a2a2a"
            }
        } else {
            "#2a2a2a"
        };
        
        let border_color = if is_alarm { "#ff5252" } else { "#4caf50" };

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
                
                if app.seed.is_none() {
                    <p>{ "Authenticate with your FIDO2 Passkey to unlock the dashboard." }</p>
                    <div style="margin-bottom: 20px; display: flex; align-items: center;">
                        <label style="margin-right: 10px;">{ "User ID:" }</label>
                        <input type="text" placeholder="your user id / email" value={app.user_id.clone()} oninput={ctx.link().callback(|e: InputEvent| {
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
                                { if app.is_fetching_role {
                                    format!("Authenticated: Fetching role from ESP32...")
                                } else {
                                    format!("Authenticated: {}", app.active_role.map(|r| r.as_str()).unwrap_or("Role Fetch Failed / Unknown"))
                                } }
                            </strong>
                            <div style="font-size: 0.85em; margin-top: 5px; opacity: 0.9; font-family: monospace;">
                                { "Public Key: " }{ app.pubkey_hex.as_ref().unwrap() }
                            </div>
                        </div>
                        <button onclick={ctx.link().callback(|_| Msg::Logout)} style="background: #d32f2f; color: white; padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            { "Logout" }
                        </button>
                    </div>
                    
                    if !app.is_fetching_role && (app.is_local_supervisor() || app.config_needs_setup()) {
                        { connection_config(app, ctx) }
                    }

                    if !app.is_fetching_role && !app.is_local_supervisor() && !app.config_needs_setup() && app.active_role.is_none() {
                        <div style="background: #4a2c00; border-left: 4px solid #ffa000; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                            <strong style="color: #ffa000;">{ "Cannot verify the device" }</strong>
                            <p style="margin: 5px 0 0 0; color: #ddd;">{ "The connection is configured, but the device could not be reached or its response could not be verified. Trust anchors are managed by the supervisor \u{2014} please clarify the connection details with your supervisor." }</p>
                        </div>
                    }

                    <hr style="border-color: #333; margin: 30px 0;" />
                    
                    if let Some(resp) = &app.last_response {
                        <div style={format!("background: {}; border-left: 4px solid {}; padding: 15px; margin-bottom: 20px; border-radius: 4px; word-break: break-all; transition: background 0.3s ease;", bg_color, border_color)}>
                            <strong style={format!("color: {}; display: block; margin-bottom: 5px;", border_color)}>{ "Last ESP32 Response:" }</strong>
                            <code style="font-family: monospace; color: #fff;">{ resp }</code>
                        </div>
                    }

                    if app.active_role.is_none() && !app.is_fetching_role {
                        <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px;">
                            <button onclick={ctx.link().callback(|_| Msg::SendCommand(CMD_WHOAMI.to_string()))} style="background: #9c27b0; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                { "Retry Fetch Role" }
                            </button>
                        </div>
                    }

                    if let Some(role) = app.active_role {
                        if role == Role::Supervisor {
                            { supervisor_tools(app, ctx) }
                        } else {
                            <h3>{ format!("System Controls (Role: {})", role.as_str()) }</h3>
                            <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px;">
                                <button onclick={ctx.link().callback(|_| Msg::StartCommandWithColor(CMD_READ_SENSOR.to_string(), "green".to_string()))} style="background: #4caf50; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                    { format!("Read Sensors ({}s Green)", shared::terminology::COMMAND_LED_TIMEOUT_MS / 1000) }
                                </button>
                                
                                if role == Role::Operator || role == Role::Admin {
                                    <>
                                        <button onclick={ctx.link().callback(|_| Msg::StartCommandWithColor(format!("{}20.0", CMD_SET_THRESHOLD), "yellow".to_string()))} style="background: #ff9800; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                            { format!("Set Threshold (20C) ({}s Yellow)", shared::terminology::COMMAND_LED_TIMEOUT_MS / 1000) }
                                        </button>
                                        <button onclick={ctx.link().callback(|_| Msg::StartCommandWithColor(format!("{}30.0", CMD_SET_THRESHOLD), "yellow".to_string()))} style="background: #ff9800; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                            { format!("Set Threshold (30C) ({}s Yellow)", shared::terminology::COMMAND_LED_TIMEOUT_MS / 1000) }
                                        </button>
                                    </>
                                }
                                
                                if role == Role::Admin {
                                    <>
                                        <button onclick={ctx.link().callback(|_| Msg::StartCommandWithColor(CMD_CLEAR_ALARM.to_string(), "red".to_string()))} style="background: #2196f3; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                            { format!("Clear Alarm ({}s Red)", shared::terminology::COMMAND_LED_TIMEOUT_MS / 1000) }
                                        </button>
                                        <button onclick={ctx.link().callback(|_| Msg::StartCommandWithColor(CMD_COLOR_RED.to_string(), "red".to_string()))} style="background: #f44336; padding: 10px 20px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold;">
                                            { "Test Alarm" }
                                        </button>
                                    </>
                                }
                            </div>
                        }
                    }
                    
                    if let Some(err) = &app.error {
                        <div class="error">{ err }</div>
                    }
                }
            </div>
        }
}

fn supervisor_tools(app: &App, ctx: &Context<App>) -> Html {
    html! {
                            <div style="background: #1e1e1e; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #444;">
                                <h3 style="margin-top: 0; color: #ffa000;">{ "Supervisor CA Tools" }</h3>
                                <p style="font-size: 14px; margin-bottom: 10px;">{ "Provision a new RAM Role securely onto the ESP32." }</p>
                                <div style="display: flex; gap: 15px; align-items: flex-end; flex-wrap: wrap;">
                                    <div style="display: flex; flex-direction: column; min-width: 150px;">
                                        <label style="color: #ccc; font-size: 14px; margin-bottom: 5px; font-weight: bold;">{ "New Role Name:" }</label>
                                        <select
                                            value={app.new_role_name.clone()}
                                            onchange={ctx.link().callback(|e: Event| {
                                                let select = e.target_unchecked_into::<web_sys::HtmlSelectElement>();
                                                Msg::UpdateNewRoleName(select.value())
                                            })}
                                            style="background: #333; border: 1px solid #555; color: #fff; padding: 0 10px; border-radius: 4px; width: 100%; height: 36px; box-sizing: border-box; mragin: 0;"
                                        >
                                            <option value="" disabled=true selected={app.new_role_name.is_empty()}>{ "Select Role..." }</option>
                                            <option value={ROLE_ADMIN} selected={app.new_role_name == ROLE_ADMIN}>{ ROLE_ADMIN }</option>
                                            <option value={ROLE_OPERATOR} selected={app.new_role_name == ROLE_OPERATOR}>{ ROLE_OPERATOR }</option>
                                            <option value={ROLE_OBSERVER} selected={app.new_role_name == ROLE_OBSERVER}>{ ROLE_OBSERVER }</option>
                                        </select>
                                    </div>
                                    <div style="display: flex; flex-direction: column; flex-grow: 1; min-width: 300px;">
                                        <label style="color: #ccc; font-size: 14px; margin-bottom: 5px; font-weight: bold;">{ "Role Ed25519 PubKey:" }</label>
                                        <input type="text"
                                            value={app.new_role_pubkey.clone()}
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
                                        disabled={app.new_role_name.is_empty() || app.new_role_pubkey.len() != 64}
                                        style={if app.new_role_name.is_empty() || app.new_role_pubkey.len() != 64 {
                                            "background: #555; color: #888; font-weight: bold; padding: 0 20px; height: 36px; border-radius: 4px; border: none; cursor: not-allowed; white-space: nowrap; box-sizing: border-box; margin: 0;"
                                        } else {
                                            "background: #ffa000; color: #000; font-weight: bold; padding: 0 20px; height: 36px; border-radius: 4px; border: none; cursor: pointer; white-space: nowrap; transition: background 0.3s ease; box-sizing: border-box; margin: 0;"
                                        }}
                                    >
                                        { "Add / Update Securely" }
                                    </button>
                                    <button 
                                        onclick={
                                            let role_name = app.new_role_name.clone();
                                            ctx.link().callback(move |_| Msg::SendCommand(format!("{} {}", CMD_REVOKE_ROLE, role_name)))
                                        }
                                        disabled={app.new_role_name.is_empty()}
                                        style={if app.new_role_name.is_empty() {
                                            "background: #555; color: #888; font-weight: bold; padding: 0 20px; height: 36px; border-radius: 4px; border: none; cursor: not-allowed; white-space: nowrap; box-sizing: border-box; margin: 0;"
                                        } else {
                                            "background: #f44336; color: #fff; font-weight: bold; padding: 0 20px; height: 36px; border-radius: 4px; border: none; cursor: pointer; white-space: nowrap; transition: background 0.3s ease; box-sizing: border-box; margin: 0;"
                                        }}
                                    >
                                        { "Revoke Role" }
                                    </button>
                                </div>
                                    <button onclick={ctx.link().callback(|_| Msg::SendCommand(CMD_LIST_ROLES.to_string()))} style="background: #2196f3; padding: 8px 16px; height: 36px; border: none; border-radius: 4px; color: white; cursor: pointer; font-weight: bold; box-sizing: border-box; margin-top: 15px;">
                                        { "List Roles" }
                                    </button>
                                
                                if let Some(roles) = &app.parsed_roles {
                                    <div style="margin-top: 20px; background: #222; border-radius: 6px; overflow: hidden; border: 1px solid #444;">
                                        <table style="width: 100%; border-collapse: collapse; text-align: left; color: #eee;">
                                            <thead style="background: #333;">
                                                <tr>
                                                    <th style="padding: 10px; border-bottom: 2px solid #555;">{ "Role Name" }</th>
                                                    <th style="padding: 10px; border-bottom: 2px solid #555;">{ "Public Key (Ed25519)" }</th>
                                                    <th style="padding: 10px; border-bottom: 2px solid #555; width: 100px;">{ "Actions" }</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                { for roles.iter().map(|(name, pk)| {
                                                    let n1 = name.clone();
                                                    let n2 = name.clone();
                                                    html! {
                                                        <tr style="border-bottom: 1px solid #444;">
                                                            <td style="padding: 10px; font-weight: bold; color: #ff9800;">{ name }</td>
                                                            <td style="padding: 10px; font-family: monospace; font-size: 12px; word-break: break-all;">{ pk }</td>
                                                            <td style="padding: 10px;">
                                                                <div style="display: flex; gap: 5px;">
                                                                    <button
                                                                        onclick={
                                                                            let ctx_clone = ctx.link().clone();
                                                                            let n_clone = n1.clone();
                                                                            let pk_clone = pk.clone();
                                                                            ctx.link().callback(move |_| {
                                                                                ctx_clone.send_message(Msg::UpdateNewRoleName(n_clone.clone()));
                                                                                Msg::UpdateNewRolePubkey(pk_clone.clone())
                                                                            })
                                                                        }
                                                                        style="background: #ff9800; color: white; border: none; border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 12px; font-weight: bold;"
                                                                    >
                                                                        { "Edit" }
                                                                    </button>
                                                                    <button
                                                                        onclick={ctx.link().callback(move |_| Msg::SendCommand(format!("{} {}", CMD_REVOKE_ROLE, n2)))}
                                                                        style="background: #f44336; color: white; border: none; border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 12px; font-weight: bold;"
                                                                    >
                                                                        { "Revoke" }
                                                                    </button>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    }
                                                })}
                                            </tbody>
                                        </table>
                                        if roles.is_empty() {
                                            <div style="padding: 20px; text-align: center; color: #888; font-style: italic;">
                                                { "No roles assigned. Use the form above to add a role." }
                                            </div>
                                        }
                                    </div>
                                }
                            </div>
    }
}

fn connection_config(app: &App, ctx: &Context<App>) -> Html {
    html! {
                        <div style="margin-top: 20px; display: flex; flex-direction: column; gap: 15px; max-width: 800px; padding: 15px; background: #1e1e1e; border: 1px dashed #555; border-radius: 6px;">
                            <h4 style="margin: 0; color: #888;">{ "Connection Configuration" }</h4>
                            <div style="display: flex; flex-direction: column;">
                                <label style="color: #ccc; font-size: 14px; margin-bottom: 5px; font-weight: bold;">{ "ESP32 IP Address:" }</label>
                                <input type="text"
                                    placeholder="device IP address"
                                    value={app.esp32_ip.clone()}
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
                                    placeholder="64 hex chars — from device boot log"
                                    value={app.esp32_pubkey.clone()}
                                    oninput={ctx.link().callback(|e: InputEvent| {
                                        let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                        Msg::UpdateEspPubkey(input.value())
                                    })}
                                    style="background: #333; border: 1px solid #555; color: #fff; padding: 10px; border-radius: 4px; width: 100%; box-sizing: border-box; font-size: 16px; font-family: monospace;"
                                />
                            </div>
                            <div style="display: flex; flex-direction: column; width: 100%;">
                                <label style="color: #ccc; font-size: 14px; margin-bottom: 5px; font-weight: bold;">{ "ESP32 Sig Pubkey:" }</label>
                                <input type="text"
                                    placeholder="64 hex chars — from device boot log"
                                    value={app.esp32_sig_pubkey.clone()}
                                    oninput={ctx.link().callback(|e: InputEvent| {
                                        let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                        Msg::UpdateEspSigPubkey(input.value())
                                    })}
                                    style="background: #333; border: 1px solid #555; color: #fff; padding: 10px; border-radius: 4px; width: 100%; box-sizing: border-box; font-size: 16px; font-family: monospace;"
                                />
                            </div>
                            <div style="display: flex; flex-direction: column; width: 100%;">
                                <label style="color: #ccc; font-size: 14px; margin-bottom: 5px; font-weight: bold;">{ "Supervisor Pubkey:" }</label>
                                <input type="text"
                                    placeholder="64 hex chars — supervisor public key"
                                    value={app.supervisor_pubkey.clone()}
                                    oninput={ctx.link().callback(|e: InputEvent| {
                                        let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                        Msg::UpdateSupervisorPubkey(input.value())
                                    })}
                                    style="background: #333; border: 1px solid #555; color: #fff; padding: 10px; border-radius: 4px; width: 100%; box-sizing: border-box; font-size: 16px; font-family: monospace;"
                                />
                            </div>
                        </div>
    }
}
