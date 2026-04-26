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

#[test]
fn golden_v2_fixture_requires_allow_legacy() {
    let output =
        read_proof_json(fixture_path("v2_kzg_proof.json").as_path()).expect("read fixture");
    assert!(output.version < 3, "expected legacy v2 fixture");
    let bytes = encode_proof_bytes(&output).expect("encode proof bytes");

    let denied = verify_proof_bytes(&bytes, false);
    assert!(!denied.ok);
    assert!(
        denied
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("allow_legacy_v2"),
        "unexpected error: {:?}",
        denied.error
    );

    let allowed = verify_proof_bytes(&bytes, true);
    assert!(allowed.ok, "verify failed: {:?}", allowed.error);
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
