use std::path::{Path, PathBuf};

use hc_sdk::{
    proof::{encode_proof_bytes, read_proof_json, verify_proof_bytes},
    types::ProofBytes,
};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn golden_v3_fixture_decodes_and_verifies() {
    let output =
        read_proof_json(fixture_path("v3_toy_stark_proof.json").as_path()).expect("read fixture");
    assert!(output.version >= 3, "expected v3+ fixture");
    let bytes = encode_proof_bytes(&output).expect("encode proof bytes");
    let result = verify_proof_bytes(&bytes, false);
    assert!(result.ok, "verify failed: {:?}", result.error);
}

/// Phase-1A Task 9 (audit finding G2 follow-on): the legacy v2 KZG fixture
/// must now be rejected by the soundness gate in `verify_proof_bytes`.
/// `verify_kzg` uses a hardcoded trusted-setup seed and the legacy path
/// accepts proofs with `query_response = None` unconditionally — so KZG-scheme
/// proofs are blocked at the SDK boundary regardless of `allow_legacy_v2`.
#[test]
fn golden_v2_kzg_fixture_is_blocked_by_soundness_gate() {
    let output =
        read_proof_json(fixture_path("v2_kzg_proof.json").as_path()).expect("read fixture");
    assert!(output.version < 3, "expected legacy v2 fixture");
    let bytes = encode_proof_bytes(&output).expect("encode proof bytes");

    // With allow_legacy_v2=false: the v2 age-gate fires before the KZG gate.
    let denied = verify_proof_bytes(&bytes, false);
    assert!(!denied.ok, "KZG v2 proof must be rejected");
    // Either the v2 gate or the KZG gate error is acceptable — both mean rejected.
    let err_false = denied.error.as_deref().unwrap_or_default();
    assert!(
        err_false.contains("allow_legacy_v2")
            || err_false.contains("KZG")
            || err_false.contains("kzg"),
        "expected v2-gate or KZG-gate error, got: {err_false}"
    );

    // With allow_legacy_v2=true: the v2 gate is bypassed; the KZG gate fires.
    let blocked = verify_proof_bytes(&bytes, true);
    assert!(
        !blocked.ok,
        "KZG-scheme proof must be rejected even with allow_legacy_v2=true (soundness gate)"
    );
    let err_true = blocked.error.as_deref().unwrap_or_default();
    assert!(
        err_true.contains("KZG") || err_true.contains("kzg") || err_true.contains("not accepted"),
        "error must mention KZG gate (allow_legacy_v2=true), got: {err_true}"
    );
}

#[test]
fn proof_envelope_version_mismatch_is_rejected() {
    let output =
        read_proof_json(fixture_path("v3_toy_stark_proof.json").as_path()).expect("read fixture");
    let good = encode_proof_bytes(&output).expect("encode proof bytes");
    let bad = ProofBytes {
        version: good.version.saturating_sub(1),
        bytes: good.bytes.clone(),
    };
    let result = verify_proof_bytes(&bad, true);
    assert!(!result.ok);
    assert!(
        result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("version mismatch"),
        "unexpected error: {:?}",
        result.error
    );
}
