//! JS-friendly verification result for the local artifact verifier.

use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Clone, Debug, Serialize)]
pub struct WasmVerifyResult {
    pub ok: bool,
    pub error: Option<String>,
    pub profile: &'static str,
    pub plonky3_version: &'static str,
}

impl WasmVerifyResult {
    pub fn success() -> Self {
        Self {
            ok: true,
            error: None,
            profile: hc_plonky3::COMPATIBILITY_PROFILE,
            plonky3_version: hc_plonky3::PLONKY3_VERSION,
        }
    }

    pub fn failure(error: String) -> Self {
        Self {
            ok: false,
            error: Some(error),
            profile: hc_plonky3::COMPATIBILITY_PROFILE,
            plonky3_version: hc_plonky3::PLONKY3_VERSION,
        }
    }

    pub(crate) fn to_js(&self) -> JsValue {
        serde_wasm_bindgen::to_value(self).unwrap_or(JsValue::NULL)
    }
}
