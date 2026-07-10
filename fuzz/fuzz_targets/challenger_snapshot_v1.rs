#![no_main]

use hc_plonky3::ChallengerSnapshotV1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 {
        return;
    }
    if let Ok(snapshot) = ChallengerSnapshotV1::decode(data) {
        let _ = snapshot.restore();
        let _ = snapshot.encode();
    }
});
