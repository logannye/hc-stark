#![no_main]

use hc_plonky3::contracts::{AirProofBundleV1, MAX_AIR_BUNDLE_JSON_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Large valid proof fixtures remain covered by deterministic tests. Keep
    // malformed JSON and proof decoding bounded during release fuzz smoke.
    if data.len() > MAX_AIR_BUNDLE_JSON_BYTES.min(2 * 1024 * 1024) {
        return;
    }
    if let Ok(bundle) = serde_json::from_slice::<AirProofBundleV1>(data) {
        let _ = bundle.verify();
    }
});
