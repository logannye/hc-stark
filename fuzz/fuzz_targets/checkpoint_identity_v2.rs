#![no_main]

use hc_stream::{CheckpointIdentityV2, CheckpointManifestV2};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(manifest) = serde_json::from_slice::<CheckpointManifestV2>(data) {
        let identity = CheckpointIdentityV2 {
            backend_hash: manifest.backend_hash,
            profile_hash: manifest.profile_hash,
            release_hash: manifest.release_hash,
            dependency_lock_hash: manifest.dependency_lock_hash,
            workload_hash: manifest.workload_hash,
            input_hash: manifest.input_hash,
            resource_policy_hash: manifest.resource_policy_hash,
        };
        let _ = manifest.validate_identity(identity);
        let mut stale = identity;
        stale.release_hash[0] ^= 1;
        let _ = manifest.validate_identity(stale);
    }
});
