#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Read;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 { return; }
    if let Ok(decoder) = zstd::stream::read::Decoder::new(data) {
        let mut output = Vec::new();
        let _ = decoder.take(2 * 1024 * 1024).read_to_end(&mut output);
    }
});

