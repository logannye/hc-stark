#![no_main]

use hc_plonky3::{contracts::{AirPackageV1, MAX_AIR_JSON_BYTES}, DeclarativeAir};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_AIR_JSON_BYTES.min(2 * 1024 * 1024) { return; }
    if let Ok(air) = serde_json::from_slice::<AirPackageV1>(data) {
        let _ = air.validate();
        let _ = air.digest();
        let _ = DeclarativeAir::new(air);
    }
});

