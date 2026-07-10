#![no_main]

use hc_plonky3::{
    InternalProofBundle, ResourceBoundedUniStarkProver, WorkloadKind, COMPATIBILITY_PROFILE,
    PLONKY3_VERSION,
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_PROOF_BYTES: usize = 2 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    // Construct a valid envelope around arbitrary bytes. Unlike the JSON
    // bundle target, this always reaches the pinned official Plonky3 proof
    // decoder (and the verifier whenever decoding succeeds).
    if data.len() > MAX_FUZZ_PROOF_BYTES {
        return;
    }
    let bundle = InternalProofBundle {
        schema_version: 1,
        compatibility_profile: COMPATIBILITY_PROFILE.to_owned(),
        plonky3_version: PLONKY3_VERSION.to_owned(),
        workload: WorkloadKind::Fibonacci {
            initial_a: 0,
            initial_b: 1,
        },
        logical_rows: 8,
        public_values: vec![0, 1, 21],
        proof_bytes: data.to_vec(),
        proof_digest: *blake3::hash(data).as_bytes(),
    };
    let _ = ResourceBoundedUniStarkProver::verify(&bundle);
});
