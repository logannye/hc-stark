#![no_main]

use hc_plonky3::contracts::{AirPackageV1, TraceManifestV1, MAX_TRACE_MANIFEST_JSON_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_TRACE_MANIFEST_JSON_BYTES.min(2 * 1024 * 1024) { return; }
    if let Ok((air, manifest)) = serde_json::from_slice::<(AirPackageV1, TraceManifestV1)>(data) {
        let _ = manifest.validate_for_air(&air);
        let _ = manifest.digest();
    }
});

