//! The dashboard UI (Leptos view). Structure only — styling lives in style.css,
//! reactivity comes from the signals in `AppState`.

use crate::state::AppState;
use leptos::prelude::*;
use shared::terminology::*;
use shared::Role;

pub fn app_view(state: AppState) -> impl IntoView {
    view! {
        <div class="container">
            <h2>{ "Critical Infrastructure Dashboard" }</h2>
            {move || {
                if state.seed.get().is_none() {
                    login(state).into_any()
                } else {
                    dashboard(state).into_any()
                }
            }}
        </div>
    }
}

fn login(state: AppState) -> impl IntoView {
    view! {
        <p>{ "Authenticate with your FIDO2 Passkey to unlock the dashboard." }</p>
        <div class="field-row">
            <label class="inline-label">{ "User ID:" }</label>
            <input
                type="text"
                class="login-input"
                placeholder="your user id / email"
                prop:value=move || state.user_id.get()
                on:input=move |ev| state.set_user_id(event_target_value(&ev))
            />
        </div>
        <button on:click=move |_| state.authenticate()>{ "Login with Passkey" }</button>
        <button class="btn-secondary" on:click=move |_| state.register()>
            { "Register New Passkey" }
        </button>
    }
}

fn dashboard(state: AppState) -> impl IntoView {
    view! {
        <div class="auth-bar">
            <div>
                <strong class="auth-status">
                    {move || {
                        if state.is_fetching_role.get() {
                            "Authenticated: Fetching role from ESP32...".to_string()
                        } else {
                            format!(
                                "Authenticated: {}",
                                state.active_role.get().map(|r| r.as_str()).unwrap_or("Role Fetch Failed / Unknown"),
                            )
                        }
                    }}
                </strong>
                <div class="auth-pubkey">
                    { "Public Key: " }
                    {move || state.pubkey_hex.get().unwrap_or_default()}
                </div>
            </div>
            <button class="btn-logout" on:click=move |_| state.logout()>{ "Logout" }</button>
        </div>

        {move || {
            (!state.is_fetching_role.get() && (state.is_local_supervisor() || state.config_needs_setup()))
                .then(|| connection_config(state))
        }}

        {move || {
            (!state.is_fetching_role.get()
                && !state.is_local_supervisor()
                && !state.config_needs_setup()
                && state.active_role.get().is_none())
                .then(|| {
                    view! {
                        <div class="notice">
                            <strong class="notice-title">{ "Cannot verify the device" }</strong>
                            <p class="notice-body">
                                { "The connection is configured, but the device could not be reached or its response could not be verified. Trust anchors are managed by the supervisor \u{2014} please clarify the connection details with your supervisor." }
                            </p>
                        </div>
                    }
                })
        }}

        <hr class="divider" />

        {move || {
            state.last_response.get().map(|resp| {
                view! {
                    <div
                        class="response-box"
                        style=move || {
                            let (bg, border) = resp_colors(state);
                            format!("background:{};border-left-color:{};", bg, border)
                        }
                    >
                        <strong
                            class="response-title"
                            style=move || format!("color:{};", resp_colors(state).1)
                        >
                            { "Last ESP32 Response:" }
                        </strong>
                        <code class="response-code">{resp}</code>
                    </div>
                }
            })
        }}

        {move || {
            (state.active_role.get().is_none() && !state.is_fetching_role.get())
                .then(|| {
                    view! {
                        <div class="btn-row">
                            <button
                                class="cmd-btn btn-retry"
                                on:click=move |_| state.send_command(CMD_WHOAMI.to_string())
                            >
                                { "Retry Fetch Role" }
                            </button>
                        </div>
                    }
                })
        }}

        {move || {
            state.active_role.get().map(|role| {
                if role == Role::Supervisor {
                    supervisor_tools(state).into_any()
                } else {
                    system_controls(state, role).into_any()
                }
            })
        }}

        {move || state.error.get().map(|err| view! { <div class="error">{err}</div> })}
    }
}

fn connection_config(state: AppState) -> impl IntoView {
    view! {
        <div class="config-panel">
            <h4 class="config-title">{ "Connection Configuration" }</h4>
            <div class="field-col">
                <label class="field-label">{ "ESP32 IP Address:" }</label>
                <input
                    type="text"
                    class="field-input field-input--ip"
                    placeholder="device IP address"
                    prop:value=move || state.esp32_ip.get()
                    on:input=move |ev| state.set_ip(event_target_value(&ev))
                />
            </div>
            <div class="field-col">
                <label class="field-label">{ "ESP32 ROM Pubkey:" }</label>
                <input
                    type="text"
                    class="field-input field-input--mono"
                    placeholder="64 hex chars — from device boot log"
                    prop:value=move || state.esp32_pubkey.get()
                    on:input=move |ev| state.set_esp_pubkey(event_target_value(&ev))
                />
            </div>
            <div class="field-col">
                <label class="field-label">{ "ESP32 Sig Pubkey:" }</label>
                <input
                    type="text"
                    class="field-input field-input--mono"
                    placeholder="64 hex chars — from device boot log"
                    prop:value=move || state.esp32_sig_pubkey.get()
                    on:input=move |ev| state.set_esp_sig_pubkey(event_target_value(&ev))
                />
            </div>
            <div class="field-col">
                <label class="field-label">{ "Supervisor Pubkey:" }</label>
                <input
                    type="text"
                    class="field-input field-input--mono"
                    placeholder="64 hex chars — supervisor public key"
                    prop:value=move || state.supervisor_pubkey.get()
                    on:input=move |ev| state.set_supervisor_pubkey(event_target_value(&ev))
                />
            </div>
        </div>
    }
}

fn system_controls(state: AppState, role: Role) -> impl IntoView {
    let secs = COMMAND_LED_TIMEOUT_MS / 1000;
    view! {
        <h3>{ format!("System Controls (Role: {})", role.as_str()) }</h3>
        <div class="btn-row">
            <button
                class="cmd-btn cmd-green"
                on:click=move |_| state.start_command_with_color(CMD_READ_SENSOR.to_string(), "green".to_string())
            >
                { format!("Read Sensors ({}s Green)", secs) }
            </button>

            {(role == Role::Operator || role == Role::Admin).then(|| view! {
                <button
                    class="cmd-btn cmd-orange"
                    on:click=move |_| state.start_command_with_color(format!("{}20.0", CMD_SET_THRESHOLD), "yellow".to_string())
                >
                    { format!("Set Threshold (20C) ({}s Yellow)", secs) }
                </button>
                <button
                    class="cmd-btn cmd-orange"
                    on:click=move |_| state.start_command_with_color(format!("{}30.0", CMD_SET_THRESHOLD), "yellow".to_string())
                >
                    { format!("Set Threshold (30C) ({}s Yellow)", secs) }
                </button>
            })}

            {(role == Role::Admin).then(|| view! {
                <button
                    class="cmd-btn cmd-blue"
                    on:click=move |_| state.start_command_with_color(CMD_CLEAR_ALARM.to_string(), "red".to_string())
                >
                    { format!("Clear Alarm ({}s Red)", secs) }
                </button>
                <button
                    class="cmd-btn cmd-red"
                    on:click=move |_| state.start_command_with_color(CMD_COLOR_RED.to_string(), "red".to_string())
                >
                    { "Test Alarm" }
                </button>
            })}
        </div>
    }
}

fn supervisor_tools(state: AppState) -> impl IntoView {
    view! {
        <div class="ca-tools">
            <h3 class="ca-title">{ "Supervisor CA Tools" }</h3>
            <p class="ca-desc">{ "Provision a new RAM Role securely onto the ESP32." }</p>
            <div class="role-form">
                <div class="role-field">
                    <label class="field-label">{ "New Role Name:" }</label>
                    <select
                        class="role-select"
                        prop:value=move || state.new_role_name.get()
                        on:change=move |ev| state.new_role_name.set(event_target_value(&ev))
                    >
                        <option value="" disabled=true>{ "Select Role..." }</option>
                        <option value=ROLE_ADMIN>{ ROLE_ADMIN }</option>
                        <option value=ROLE_OPERATOR>{ ROLE_OPERATOR }</option>
                        <option value=ROLE_OBSERVER>{ ROLE_OBSERVER }</option>
                    </select>
                </div>
                <div class="role-field role-field--grow">
                    <label class="field-label">{ "Role Ed25519 PubKey:" }</label>
                    <input
                        type="text"
                        class="role-input role-input--mono"
                        placeholder="64-char hex string"
                        prop:value=move || state.new_role_pubkey.get()
                        on:input=move |ev| state.new_role_pubkey.set(event_target_value(&ev))
                    />
                </div>
                <button
                    class="btn-add"
                    disabled=move || state.new_role_name.get().is_empty() || state.new_role_pubkey.get().len() != 64
                    on:click=move |_| state.add_role()
                >
                    { "Add / Update Securely" }
                </button>
                <button
                    class="btn-revoke"
                    disabled=move || state.new_role_name.get().is_empty()
                    on:click=move |_| {
                        let name = state.new_role_name.get();
                        state.send_command(format!("{} {}", CMD_REVOKE_ROLE, name));
                    }
                >
                    { "Revoke Role" }
                </button>
            </div>
            <button
                class="btn-list"
                on:click=move |_| state.send_command(CMD_LIST_ROLES.to_string())
            >
                { "List Roles" }
            </button>

            {move || {
                state.parsed_roles.get().map(|roles| {
                    let rows = roles
                        .iter()
                        .map(|(name, pk)| {
                            let name_edit = name.clone();
                            let pk_edit = pk.clone();
                            let name_revoke = name.clone();
                            view! {
                                <tr>
                                    <td class="role-name">{name.clone()}</td>
                                    <td class="role-pk">{pk.clone()}</td>
                                    <td>
                                        <div class="row-btns">
                                            <button
                                                class="btn-edit"
                                                on:click=move |_| {
                                                    state.new_role_name.set(name_edit.clone());
                                                    state.new_role_pubkey.set(pk_edit.clone());
                                                }
                                            >
                                                { "Edit" }
                                            </button>
                                            <button
                                                class="btn-revoke-sm"
                                                on:click=move |_| state.send_command(format!("{} {}", CMD_REVOKE_ROLE, name_revoke))
                                            >
                                                { "Revoke" }
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            }
                        })
                        .collect_view();
                    let empty = roles.is_empty().then(|| view! {
                        <div class="role-empty">{ "No roles assigned. Use the form above to add a role." }</div>
                    });
                    view! {
                        <div class="role-table-wrap">
                            <table class="role-table">
                                <thead>
                                    <tr>
                                        <th>{ "Role Name" }</th>
                                        <th>{ "Public Key (Ed25519)" }</th>
                                        <th class="col-actions">{ "Actions" }</th>
                                    </tr>
                                </thead>
                                <tbody>{rows}</tbody>
                            </table>
                            {empty}
                        </div>
                    }
                })
            }}
        </div>
    }
}

/// (background, border) colors for the response box, reactive to alarm state and
/// the active command color.
fn resp_colors(state: AppState) -> (String, &'static str) {
    let is_alarm = state.last_response.get().map(|r| r.contains("(ALARM!)")).unwrap_or(false);
    let bg = if is_alarm {
        "#b71c1c".to_string()
    } else if let Some(color) = state.command_color.get() {
        match color.as_str() {
            "green" => "#1b5e20",
            "yellow" => "#f57f17",
            "red" => "#b71c1c",
            _ => "#2a2a2a",
        }
        .to_string()
    } else {
        "#2a2a2a".to_string()
    };
    let border = if is_alarm { "#ff5252" } else { "#4caf50" };
    (bg, border)
}
