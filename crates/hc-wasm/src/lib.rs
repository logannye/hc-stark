//! WASM verifier for `ProofBundleV1` artifacts.
//!
//! The replacement surface intentionally exposes local verification only. It
//! contains no legacy receipt decoder and no hosted proving/verification API.

#![forbid(unsafe_code)]

pub mod estimate;
pub mod types;

use hc_plonky3::contracts::{ProofBundleV1, MAX_BUNDLE_JSON_BYTES};
use types::WasmVerifyResult;
use wasm_bindgen::prelude::*;

pub use estimate::{estimate_request, EstimateFailure};

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

/// Estimate from a JSON `EstimateRequestV1`. Returns a JSON
/// `EstimateResponseV1` on success, or the standard error envelope (the same
/// shape `hc-cli`'s `protocol::write_error` emits, via
/// `EngineErrorEnvelopeV1`) on failure. Never panics across the WASM
/// boundary: every fallible step here returns a value instead of
/// unwrapping, and this function calls no I/O (no `println!`/`eprintln!`,
/// which would panic on a `wasm32-unknown-unknown` target with no real
/// stdio).
#[wasm_bindgen]
pub fn estimate_json(input: &str) -> String {
    match serde_json::from_str::<tinyzkp_contracts::EstimateRequestV1>(input) {
        Err(_) => error_envelope(tinyzkp_contracts::ReasonCodeV1::ManifestContractInvalid),
        Ok(request) => match estimate_request(request) {
            Ok(response) => serde_json::to_string(&response)
                .unwrap_or_else(|_| error_envelope(tinyzkp_contracts::ReasonCodeV1::InternalError)),
            Err(failure) => error_envelope(failure.reason_code()),
        },
    }
}

/// Build the same JSON error envelope shape `hc-cli`'s
/// `protocol::write_error` writes to stdout (`EngineErrorEnvelopeV1` /
/// `tinyzkp_contracts::ErrorEnvelopeV1`), so an API error and a CLI error
/// are indistinguishable on the wire. `resumable`/`checkpoint_present` are
/// always `false` here: estimation never resumes and never checkpoints.
fn error_envelope(code: tinyzkp_contracts::ReasonCodeV1) -> String {
    let envelope = tinyzkp_contracts::EngineErrorEnvelopeV1::new(
        hc_plonky3::release_identity(),
        tinyzkp_contracts::ReasonV1::new(code),
        false,
        false,
    );
    serde_json::to_string(&envelope).unwrap_or_else(|_| {
        r#"{"schema_version":1,"engine_release_identity":"unknown","ok":false,"error":{"class":"internal_error","exit_code":70,"reason":{"code":"internal_error","class":"internal_error","summary":"The local program encountered an internal error.","remediation":"generate_support_report","docs_url":"/troubleshooting#internal_error","required_bytes":null,"available_bytes":null,"limit_bytes":null,"expected_platform":null,"detected_platform":null,"expected_profile":null,"detected_profile":null},"resumable":false,"checkpoint_present":false}}"#.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SP1_SHAPED: &str = r#"{
      "schema_version": 1, "field": "babybear", "extension_degree": 4,
      "logical_rows": 4194304, "trace_width": 180, "max_constraint_degree": 3,
      "public_values": 8, "has_next_row_columns": true,
      "features": {"uses_lookups": true, "uses_buses": false,
        "uses_permutations": false, "uses_multi_table": true,
        "uses_preprocessed_columns": false, "uses_periodic_columns": false,
        "uses_recursion": false, "uses_gpu": false},
      "ram_budget_bytes": 2147483648
    }"#;

    /// The JSON export must return exactly what the typed core returns.
    /// `estimate_request` lives in THIS crate (see the placement note below);
    /// `hc-cli` calls it too, so the CLI and the API cannot diverge.
    #[test]
    fn wasm_export_matches_the_shared_core() {
        let request: tinyzkp_contracts::EstimateRequestV1 =
            serde_json::from_str(SP1_SHAPED).unwrap();
        let direct = estimate_request(request).unwrap();
        let via_wasm: tinyzkp_contracts::EstimateResponseV1 =
            serde_json::from_str(&estimate_json(SP1_SHAPED)).unwrap();
        assert_eq!(direct, via_wasm);
    }

    /// An unprovable config must still return numbers — the product thesis.
    #[test]
    fn unprovable_config_still_returns_estimates() {
        let r: tinyzkp_contracts::EstimateResponseV1 =
            serde_json::from_str(&estimate_json(SP1_SHAPED)).unwrap();
        assert!(!r.provable_today);
        assert!(!r.blocking_reasons.is_empty());
        assert!(r.estimates.bounded.peak_resident_bytes > 0);
        assert!(
            r.estimates.conventional.peak_resident_bytes > r.estimates.bounded.peak_resident_bytes
        );
    }

    /// Errors must be structured, never a panic across the WASM boundary.
    #[test]
    fn malformed_input_returns_a_structured_error_not_a_panic() {
        let out = estimate_json("{ not json");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], serde_json::json!(false));
        assert!(v["error"]["reason"]["code"].is_string());
        assert_ne!(v["error"]["reason"]["code"], "internal_error");
    }

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
