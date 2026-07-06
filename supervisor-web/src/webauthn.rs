//! WebAuthn passkey + PRF: derive the supervisor/role key material from the
//! authenticator. Decoupled from the Yew app — returns parsed results.

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn create_passkey_prf(user_id: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn get_passkey_prf() -> Result<JsValue, JsValue>;
}

/// The 32-byte PRF `seed` and the `role` string returned by the JS glue.
fn parse_result(val: JsValue) -> (Vec<u8>, String) {
    let seed_array =
        js_sys::Uint8Array::new(&js_sys::Reflect::get(&val, &JsValue::from_str("seed")).unwrap());
    let seed = seed_array.to_vec();
    let role = js_sys::Reflect::get(&val, &JsValue::from_str("role"))
        .unwrap()
        .as_string()
        .unwrap();
    (seed, role)
}

fn parse_error(err: JsValue) -> String {
    if let Some(e) = err.as_string() {
        e
    } else if let Some(m) = js_sys::Reflect::get(&err, &JsValue::from_str("message"))
        .ok()
        .and_then(|v| v.as_string())
    {
        m
    } else {
        format!("{:?}", err)
    }
}

/// Register a new passkey and evaluate PRF. `Ok((seed, role))` or an error msg.
pub async fn register(user_id: &str) -> Result<(Vec<u8>, String), String> {
    match create_passkey_prf(user_id).await {
        Ok(val) => Ok(parse_result(val)),
        Err(err) => Err(parse_error(err)),
    }
}

/// Authenticate an existing passkey and evaluate PRF.
pub async fn authenticate() -> Result<(Vec<u8>, String), String> {
    match get_passkey_prf().await {
        Ok(val) => Ok(parse_result(val)),
        Err(err) => Err(parse_error(err)),
    }
}
