use std::path::{Path, PathBuf};

use hc_core::field::{prime_field::GoldilocksField, FieldElement};
use hc_sdk::proof::{encode_proof_bytes, read_proof_json};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn to_verifier_proof(
    output: &hc_prover::queries::ProverOutput<GoldilocksField>,
) -> hc_verifier::Proof<GoldilocksField> {
    hc_verifier::Proof::<GoldilocksField> {
        version: output.version,
        trace_commitment: output.trace_commitment.clone(),
        composition_commitment: output.composition_commitment.clone(),
        fri_proof: output.fri_proof.clone(),
        initial_acc: output.public_inputs.initial_acc,
        final_acc: output.public_inputs.final_acc,
        query_response: output.query_response.clone(),
        trace_length: output.trace_length,
        params: output.params,
    }
}

#[test]
fn tampering_trace_root_rejects() {
    let output = read_proof_json(fixture_path("v3_toy_stark_proof.json").as_path()).unwrap();
    let mut proof = to_verifier_proof(&output);
    let hc_prover::Commitment::Stark { ref mut root } = proof.trace_commitment else {
        panic!("expected stark commitment");
    };
    let mut bytes = root.as_bytes().to_vec();
    bytes[0] ^= 0x01;
    *root = hc_hash::HashDigest::from_slice(&bytes).unwrap();

    assert!(hc_verifier::verify(&proof).is_err());
}

#[test]
fn tampering_first_merkle_path_node_rejects() {
    let output = read_proof_json(fixture_path("v3_toy_stark_proof.json").as_path()).unwrap();
    let mut proof = to_verifier_proof(&output);
    let qr = proof
        .query_response
        .as_mut()
        .expect("fixture has query response");

    // v3 verification uses the trace opening selected by `index` (a map), and proofs may include
    // duplicate indices. To ensure we tamper the opening that is actually checked, tamper *all*
    // trace query witnesses.
    for tq in &mut qr.trace_queries {
        let hc_prover::queries::TraceWitness::Merkle(path) = &mut tq.witness else {
            continue;
        };
        let mut nodes = path.nodes().to_vec();
        if let Some(first) = nodes.get_mut(0) {
            let mut bytes = first.sibling.as_bytes().to_vec();
            bytes[0] ^= 0x01;
            first.sibling = hc_hash::HashDigest::from_slice(&bytes).unwrap();
            *path = hc_commit::merkle::MerklePath::new(nodes);
        }
    }
    assert!(hc_verifier::verify(&proof).is_err());
}

#[test]
fn tampering_fri_final_layer_rejects() {
    let output = read_proof_json(fixture_path("v3_toy_stark_proof.json").as_path()).unwrap();
    let mut proof = to_verifier_proof(&output);
    proof.fri_proof.final_layer[0] =
        proof.fri_proof.final_layer[0] + <GoldilocksField as FieldElement>::ONE;
    assert!(hc_verifier::verify(&proof).is_err());
}

#[test]
fn structured_json_mutation_rejects() {
    // Mutate the serialized proof bytes in a structured way: flip a nibble in the JSON payload,
    // keep the envelope version constant, and ensure verification fails.
    let output = read_proof_json(fixture_path("v3_toy_stark_proof.json").as_path()).unwrap();
    let mut bytes = encode_proof_bytes(&output).unwrap();
    // Flip in the middle to avoid trivially corrupting the JSON header most of the time.
    if !bytes.bytes.is_empty() {
        let idx = bytes.bytes.len() / 2;
        bytes.bytes[idx] ^= 0x0f;
    }
    let result = hc_sdk::proof::verify_proof_bytes(&bytes, false);
    assert!(!result.ok);
}
