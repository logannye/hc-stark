#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Structured fuzzing: take valid-looking JSON and mutate it.
    // Ensures the verifier handles malformed but structurally plausible proofs.
    if data.len() < 2 {
        return;
    }

    // Strategy 1: Raw bytes as JSON.
    if let Ok(json_str) = std::str::from_utf8(data) {
        let proof = hc_sdk::types::ProofBytes {
            version: 3,
            bytes: json_str.as_bytes().to_vec(),
        };
        let _ = hc_sdk::proof::verify_proof_bytes(&proof, true);
    }

    // Strategy 2: Create a minimal valid-ish JSON structure and inject fuzz data.
    let version = data[0] as u32;
    let fuzz_value = if data.len() > 8 {
        u64::from_le_bytes(data[1..9].try_into().unwrap_or([0; 8]))
    } else {
        0
    };

    let json = format!(
        r#"{{"version":{},"commitment_scheme":"stark","trace_commitment":{{"type":"stark","root":"{}"}},"composition_commitment":{{"type":"stark","root":"{}"}},"fri_layer_roots":[],"fri_final_layer":[],"fri_final_root":"{}","initial_acc":{},"final_acc":{},"metrics":{{"trace_blocks_loaded":0,"fri_blocks_loaded":0,"composition_blocks_loaded":0,"fri_query_batches":0,"fri_queries_answered":0,"fri_query_duration_ms":0}},"trace_length":{}}}"#,
        version,
        "0".repeat(64),
        "0".repeat(64),
        "0".repeat(64),
        fuzz_value,
        fuzz_value.wrapping_add(1),
        data.len()
    );

    let proof = hc_sdk::types::ProofBytes {
        version,
        bytes: json.into_bytes(),
    };
    let _ = hc_sdk::proof::verify_proof_bytes(&proof, true);
});
