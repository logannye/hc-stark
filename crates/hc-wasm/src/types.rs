//! JS-friendly wrapper types for the WASM verifier.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Result of proof verification, returned to JavaScript.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmVerifyResult {
    /// Whether verification succeeded.
    pub ok: bool,
    /// Human-readable error message on failure, null on success.
    pub error: Option<String>,
    /// Proof format version that was verified.
    pub version: Option<u32>,
}

impl WasmVerifyResult {
    pub fn success(version: u32) -> Self {
        Self {
            ok: true,
            error: None,
            version: Some(version),
        }
    }

    pub fn failure(error: String) -> Self {
        Self {
            ok: false,
            error: Some(error),
            version: None,
        }
    }

    pub(crate) fn to_js(&self) -> JsValue {
        serde_wasm_bindgen::to_value(self).unwrap_or(JsValue::NULL)
    }
}

/// Proof payload accepted from JavaScript.
///
/// Matches the SDK's `ProofBytes` format: a version tag plus the raw
/// serialized proof bytes (JSON-encoded internally).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmProofInput {
    /// Proof format version.
    pub version: u32,
    /// Serialized proof bytes (JSON).
    pub bytes: Vec<u8>,
}
