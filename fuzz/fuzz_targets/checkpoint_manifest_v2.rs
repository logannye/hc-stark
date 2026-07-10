#![no_main]

use hc_stream::CheckpointManifestV2;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(manifest) = serde_json::from_slice::<CheckpointManifestV2>(data) {
        let _ = manifest.validate_structure();
    }
});
