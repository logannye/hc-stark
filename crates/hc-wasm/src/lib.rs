//! WASM verifier for hc-stark proofs.
//!
//! Provides a thin wasm-bindgen wrapper around the native verifier so that
//! STARK proofs can be verified in the browser or any WASM runtime.
//!
//! # Usage from JavaScript
//!
//! ```js
//! import init, { verify, verify_json } from "hc-wasm";
//!
//! await init();
//!
//! // Option 1: pass a JSON proof string directly.
//! const result = verify_json(proofJsonString);
//! console.log(result.ok, result.error);
//!
//! // Option 2: pass a structured { version, bytes } object.
//! const result2 = verify({ version: 3, bytes: proofBytes });
//! console.log(result2.ok, result2.error);
//! ```

#![forbid(unsafe_code)]

pub mod types;

use types::{WasmProofInput, WasmVerifyResult};
use wasm_bindgen::prelude::*;

/// Core verification logic, callable from both WASM and native code.
pub fn verify_proof(input: WasmProofInput) -> WasmVerifyResult {
    let proof_bytes = hc_sdk::types::ProofBytes {
        version: input.version,
        bytes: input.bytes,
    };

    let result = hc_sdk::proof::verify_proof_bytes(&proof_bytes, true);
    if result.ok {
        WasmVerifyResult::success(input.version)
    } else {
        WasmVerifyResult::failure(result.error.unwrap_or_else(|| "unknown error".into()))
    }
}

/// Core JSON verification logic, callable from both WASM and native code.
pub fn verify_proof_json(json: &str) -> WasmVerifyResult {
    let parsed: WasmProofInput = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(err) => {
            return WasmVerifyResult::failure(format!("invalid proof JSON: {err}"));
        }
    };
    verify_proof(parsed)
}

/// Verify a STARK proof from a structured input.
///
/// Accepts a JS object matching `{ version: number, bytes: Uint8Array }`.
/// Returns `{ ok: boolean, error?: string, version?: number }`.
#[wasm_bindgen]
pub fn verify(input: JsValue) -> JsValue {
    let parsed: WasmProofInput = match serde_wasm_bindgen::from_value(input) {
        Ok(v) => v,
        Err(err) => {
            return WasmVerifyResult::failure(format!("invalid proof input: {err}")).to_js();
        }
    };
    verify_proof(parsed).to_js()
}

/// Verify a STARK proof from a JSON string.
///
/// The JSON must be a serialized proof in the SDK format (the same format
/// produced by `hc-cli prove --output proof.json`).
///
/// Returns `{ ok: boolean, error?: string, version?: number }`.
#[wasm_bindgen]
pub fn verify_json(json: &str) -> JsValue {
    verify_proof_json(json).to_js()
}

/// Returns the library version string.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_rejects_empty_input() {
        let input = WasmProofInput {
            version: 3,
            bytes: vec![],
        };
        let result = verify_proof(input);
        assert!(!result.ok);
        assert!(result.error.is_some());
    }

    #[test]
    fn verify_rejects_garbage_bytes() {
        let input = WasmProofInput {
            version: 3,
            bytes: b"not a proof".to_vec(),
        };
        let result = verify_proof(input);
        assert!(!result.ok);
    }

    #[test]
    fn verify_json_rejects_invalid_json() {
        let result = verify_proof_json("not valid json");
        assert!(!result.ok);
        assert!(result
            .error
            .as_deref()
            .unwrap()
            .contains("invalid proof JSON"));
    }

    #[test]
    fn verify_json_rejects_empty_bytes() {
        let json = r#"{"version":3,"bytes":[]}"#;
        let result = verify_proof_json(json);
        assert!(!result.ok);
    }

    #[test]
    fn version_returns_package_version() {
        let v = version();
        assert!(!v.is_empty());
        assert!(v.contains('.'));
    }
}
