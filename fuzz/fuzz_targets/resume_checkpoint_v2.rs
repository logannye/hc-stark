#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let path = directory.path().join("checkpoint.json");
    if std::fs::write(&path, data).is_ok() {
        let _ = hc_plonky3::resume_resource_bounded(&path);
    }
});
