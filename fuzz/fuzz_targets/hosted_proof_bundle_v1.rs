#![no_main]

use hc_plonky3::contracts::{HostedProofBundleV1, MAX_AIR_BUNDLE_JSON_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_AIR_BUNDLE_JSON_BYTES.min(2 * 1024 * 1024) { return; }
    if let Ok(bundle) = serde_json::from_slice::<HostedProofBundleV1>(data) {
        let _ = bundle.verify();
    }
});

