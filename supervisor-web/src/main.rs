use yew::prelude::*;
use shared::Role;
use gloo_storage::{LocalStorage, Storage};

mod crypto;
mod state;
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
        state::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        crate::view::render(self, ctx)
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
