#![no_main]

use hc_stream::{validate_scratch_artifact, ArtifactDigest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Ok(file) = tempfile::NamedTempFile::new() else {
        return;
    };
    if std::fs::write(file.path(), data).is_err() {
        return;
    }
    let digest = ArtifactDigest {
        rows: u64::from(data.first().copied().unwrap_or(0)).saturating_add(1),
        columns: usize::from(data.get(1).copied().unwrap_or(0)).saturating_add(1),
        element_width: usize::from(data.get(2).copied().unwrap_or(0)).saturating_add(1),
        blake3: *blake3::hash(data).as_bytes(),
    };
    let _ = validate_scratch_artifact(file.path(), digest);
});
