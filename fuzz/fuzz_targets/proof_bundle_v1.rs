#![no_main]

use hc_plonky3::contracts::{ProofBundleV1, MAX_BUNDLE_JSON_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Keep malformed-input fuzzing bounded. Valid large proof fixtures are
    // covered by deterministic integration tests and seeded corpora.
    if data.len() > MAX_BUNDLE_JSON_BYTES.min(2 * 1024 * 1024) {
        return;
    }
    if let Ok(bundle) = serde_json::from_slice::<ProofBundleV1>(data) {
        let _ = bundle.verify();
    }
});
