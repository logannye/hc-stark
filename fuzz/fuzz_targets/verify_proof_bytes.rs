#![no_main]

use libfuzzer_sys::fuzz_target;

use hc_sdk::types::ProofBytes;

fuzz_target!(|data: &[u8]| {
    // Try verifying arbitrary bytes as a proof.
    // The verifier must never panic, only return Ok/Err.
    for version in [1, 2, 3, 4] {
        let proof = ProofBytes {
            version,
            bytes: data.to_vec(),
        };
        let _ = hc_sdk::proof::verify_proof_bytes(&proof, true);
    }
});
