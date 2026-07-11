#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    if data.len() > 2 * 1024 * 1024 { return; }
    if let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(data) {
        if object.len() > 64 { return; }
        for required in ["air", "local_proof", "manifest", "public_inputs", "lease_epoch"] {
            let _ = object.get(required);
        }
    }
});
