use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use serde_json::json;
use tempfile::tempdir;

#[test]
fn release_identity_is_machine_readable_and_profile_pinned() {
    let output = cargo_bin_cmd!("hc-cli")
        .env("HC_RELEASE_SHA", "abc123")
        .arg("release")
        .output()
        .unwrap();
    assert!(output.status.success());
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(payload["service"], "cli");
    assert_eq!(payload["release_sha"], "abc123");
    assert_eq!(payload["plonky3_version"], "0.6.1");
    assert_eq!(payload["compatibility_profile"], "tinyzkp-p3-goldilocks-v1");
}

fn write_fibonacci_manifest(dir: &std::path::Path) -> std::path::PathBuf {
    let manifest = dir.join("manifest.json");
    let scratch = dir.join("scratch");
    let payload = json!({
        "schema_version": 1,
        "workload_id": "fibonacci",
        "backend": "plonky3",
        "profile": "tinyzkp-p3-goldilocks-v1",
        "input_generator": {"kind": "fibonacci", "initial_a": 0, "initial_b": 1},
        "logical_rows": 8,
        "deterministic_seed": 0,
        "resource_policy": {
            "mode": "scratch",
            "max_resident_bytes": 134217728,
            "max_scratch_bytes": 1073741824,
            "scratch_dir": scratch,
            "max_threads": 1,
            "checkpoint_policy": "delete_on_success"
        },
        "expected_verifier": "p3_uni_stark_0.6.1"
    });
    std::fs::write(&manifest, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    manifest
}

#[test]
fn production_generic_commands_fail_with_migration_guidance() {
    for command in ["prove", "verify"] {
        cargo_bin_cmd!("hc-cli")
            .arg(command)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "legacy TinyZKP proving and verification are disabled",
            ));
    }
}

#[test]
fn plonky3_prove_and_official_verify_round_trip() {
    let dir = tempdir().unwrap();
    let manifest = write_fibonacci_manifest(dir.path());
    let bundle = dir.path().join("proof-bundle.json");

    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "prove",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "verified official Plonky3 proof bundle",
        ));

    cargo_bin_cmd!("hc-cli")
        .args(["plonky3", "verify", "--bundle", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("official p3-uni-stark verifier"));
}

#[test]
fn proof_bundle_mutation_is_rejected_before_verification() {
    let dir = tempdir().unwrap();
    let manifest = write_fibonacci_manifest(dir.path());
    let bundle = dir.path().join("proof-bundle.json");
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "prove",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut payload: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&bundle).unwrap()).unwrap();
    payload["proof_digest_hex"] = json!("00".repeat(32));
    std::fs::write(&bundle, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();

    cargo_bin_cmd!("hc-cli")
        .args(["plonky3", "verify", "--bundle", bundle.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "proof encoding or digest mismatch",
        ));
}

#[test]
fn schemas_are_exported_from_rust_contracts() {
    let dir = tempdir().unwrap();
    cargo_bin_cmd!("hc-cli")
        .args(["schema", "--output-dir", dir.path().to_str().unwrap()])
        .assert()
        .success();
    for file in [
        "workload-manifest-v1.schema.json",
        "proof-bundle-v1.schema.json",
        "benchmark-report-v1.schema.json",
    ] {
        assert!(dir.path().join(file).is_file());
    }
}
