//! WASM verifier for `ProofBundleV1` artifacts.
//!
//! The replacement surface intentionally exposes local verification only. It
//! contains no legacy receipt decoder and no hosted proving/verification API.

#![forbid(unsafe_code)]

pub mod types;

use hc_plonky3::contracts::{ProofBundleV1, MAX_BUNDLE_JSON_BYTES};
use types::WasmVerifyResult;
use wasm_bindgen::prelude::*;

/// Core JSON verification logic, callable from WASM and native tests.
pub fn verify_bundle_json(json: &str) -> WasmVerifyResult {
    if json.len() > MAX_BUNDLE_JSON_BYTES {
        return WasmVerifyResult::failure("proof bundle exceeds the size limit".into());
    }
    let bundle: ProofBundleV1 = match serde_json::from_str(json) {
        Ok(bundle) => bundle,
        Err(error) => {
            return WasmVerifyResult::failure(format!("invalid ProofBundleV1 JSON: {error}"));
        }
    };
    match bundle.verify() {
        Ok(()) => WasmVerifyResult::success(),
        Err(error) => WasmVerifyResult::failure(error.to_string()),
    }
}

/// Verify a complete `ProofBundleV1` JSON artifact using the pinned official
/// Plonky3 verifier.
#[wasm_bindgen]
pub fn verify_bundle(json: &str) -> JsValue {
    verify_bundle_json(json).to_js()
}

#[wasm_bindgen]
pub fn version() -> String {
    format!(
        "{}:{}:{}",
        env!("CARGO_PKG_VERSION"),
        hc_plonky3::COMPATIBILITY_PROFILE,
        hc_plonky3::PLONKY3_VERSION
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_and_legacy_json() {
        let invalid = verify_bundle_json("not valid json");
        assert!(!invalid.ok);
        assert!(invalid.error.unwrap().contains("ProofBundleV1"));

        let legacy = verify_bundle_json(r#"{"version":3,"bytes":[]}"#);
        assert!(!legacy.ok);
    }

    #[test]
    fn version_pins_profile_and_dependency() {
        let value = version();
        assert!(value.contains(hc_plonky3::COMPATIBILITY_PROFILE));
        assert!(value.contains(hc_plonky3::PLONKY3_VERSION));
    }
}
