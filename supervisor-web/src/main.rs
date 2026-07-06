//! Supervisor dashboard entry point. State/logic live in `state`, the UI in
//! `view`; the crypto (`crypto`) and passkey (`webauthn`) layers are shared,
//! framework-agnostic Rust.

mod crypto;
mod state;
mod view;
mod webauthn;

use state::AppState;

fn main() {
    leptos::mount::mount_to_body(|| view::app_view(AppState::new()));
}
