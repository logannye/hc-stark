#![no_main]

use libfuzzer_sys::fuzz_target;

use hc_sdk::{
    proof::decode_proof_bytes,
    types::ProofBytes,
};

fuzz_target!(|data: &[u8]| {
    // Treat input as "opaque proof bytes" with a plausible version.
    // We mainly want to ensure decoding never panics and handles bad inputs safely.
    let proof = ProofBytes {
        version: 4,
        bytes: data.to_vec(),
    };
    let _ = decode_proof_bytes(&proof);
});


