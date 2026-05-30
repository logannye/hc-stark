use std::path::{Path, PathBuf};

use hc_core::field::prime_field::GoldilocksField;
use hc_sdk::{
    proof::{decode_proof_bytes, encode_proof_bytes, read_proof_json, verify_proof_bytes},
    types::ProofBytes,
};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Build a lower-level `hc_verifier::Proof` from a decoded v3 `ProverOutput`.
/// The production `verify_proof_bytes` endpoint now rejects all pre-v5 proofs
/// (Phase 1A D5 cutover), so v3 fixtures are verified through the lower-level,
/// no-production-floor `hc_verifier::verify` to keep the v3 verify logic
/// test-covered.
fn v3_lower_level_proof(
    out: &hc_prover::queries::ProverOutput<GoldilocksField>,
) -> hc_verifier::Proof<GoldilocksField> {
    hc_verifier::Proof {
        version: out.version,
        trace_commitment: out.trace_commitment.clone(),
        composition_commitment: out.composition_commitment.clone(),
        fri_proof: out.fri_proof.clone(),
        initial_acc: out.public_inputs.initial_acc,
        final_acc: out.public_inputs.final_acc,
        query_response: out.query_response.clone(),
        trace_length: out.trace_length,
        params: out.params,
    }
}

/// PHASE 1A D5 cutover: the production `verify_proof_bytes` endpoint REJECTS
/// the v3 fixture (legacy version), but the v3 verify LOGIC still accepts it
/// via the lower-level `hc_verifier::verify`. This keeps v3 verification
/// test-covered while the live service refuses pre-v5 proofs.
#[test]
fn golden_v3_fixture_rejected_by_endpoint_but_verifies_lower_level() {
    let output =
        read_proof_json(fixture_path("v3_toy_stark_proof.json").as_path()).expect("read fixture");
    assert!(output.version >= 3, "expected v3+ fixture");
    assert!(output.version < 5, "expected a legacy (<v5) fixture");

    // Production endpoint: rejected by the legacy-version floor.
    let bytes = encode_proof_bytes(&output).expect("encode proof bytes");
    let denied = verify_proof_bytes(&bytes, false);
    assert!(!denied.ok, "production endpoint must reject the v3 fixture");
    assert!(
        denied
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("legacy proof version"),
        "unexpected error: {:?}",
        denied.error
    );

    // Lower-level verifier: v3 verify logic still accepts the fixture.
    let lower = v3_lower_level_proof(&output);
    assert!(
        hc_verifier::verify(&lower).is_ok(),
        "v3 verify logic must remain functional via the lower-level verifier"
    );
}

/// Phase-1A: the legacy v2 KZG fixture is rejected by `verify_proof_bytes`.
/// After the D5 cutover it is rejected by the version floor (version < 5)
/// before any commitment-scheme inspection — with or without `allow_legacy_v2`.
#[test]
fn golden_v2_kzg_fixture_is_rejected_by_version_floor() {
    let output =
        read_proof_json(fixture_path("v2_kzg_proof.json").as_path()).expect("read fixture");
    assert!(output.version < 3, "expected legacy v2 fixture");
    let bytes = encode_proof_bytes(&output).expect("encode proof bytes");

    for allow in [false, true] {
        let result = verify_proof_bytes(&bytes, allow);
        assert!(
            !result.ok,
            "legacy v2 KZG proof must be rejected (allow_legacy_v2={allow})"
        );
        let err = result.error.as_deref().unwrap_or_default();
        assert!(
            err.contains("legacy proof version"),
            "expected legacy-version rejection, got: {err}"
        );
    }
}

/// The envelope/payload version-mismatch detection in the lower-level
/// `decode_proof_bytes` is preserved. (The production endpoint no longer
/// reaches this check for v3, since it rejects pre-v5 by version first; the v5
/// equivalent is covered by `decode_proof_v5`'s mismatch test.)
#[test]
fn proof_envelope_version_mismatch_is_rejected_by_decoder() {
    let output =
        read_proof_json(fixture_path("v3_toy_stark_proof.json").as_path()).expect("read fixture");
    let good = encode_proof_bytes(&output).expect("encode proof bytes");
    let bad = ProofBytes {
        version: good.version.saturating_sub(1),
        bytes: good.bytes.clone(),
    };
    let err = decode_proof_bytes(&bad).expect_err("version mismatch must be detected");
    assert!(
        err.to_string().contains("version mismatch"),
        "unexpected error: {err}"
    );
}
