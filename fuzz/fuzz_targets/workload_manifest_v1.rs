#![no_main]

use hc_plonky3::contracts::{WorkloadManifestV1, MAX_MANIFEST_JSON_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_MANIFEST_JSON_BYTES {
        return;
    }
    if let Ok(manifest) = serde_json::from_slice::<WorkloadManifestV1>(data) {
        let _ = manifest.validate();
        let _ = manifest.digest();
        let _ = manifest.workload();
    }
});
