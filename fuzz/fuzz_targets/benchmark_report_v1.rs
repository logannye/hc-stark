#![no_main]

use hc_plonky3::contracts::{BenchmarkReportV1, MAX_REPORT_JSON_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_REPORT_JSON_BYTES {
        return;
    }
    if let Ok(report) = serde_json::from_slice::<BenchmarkReportV1>(data) {
        let _ = report.validate();
    }
});
