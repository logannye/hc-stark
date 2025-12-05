#![allow(deprecated)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn prove_and_verify_roundtrip() {
    let dir = tempdir().expect("tempdir");
    let proof_path = dir.path().join("proof.json");
    Command::cargo_bin("hc-cli")
        .expect("binary exists")
        .args(["prove", "--output", proof_path.to_str().expect("path utf8")])
        .assert()
        .success()
        .stdout(predicate::str::contains("trace commitment"));

    Command::cargo_bin("hc-cli")
        .expect("binary exists")
        .args(["verify", "--input", proof_path.to_str().expect("path utf8")])
        .assert()
        .success()
        .stdout(predicate::str::contains("proof verified"));
}

#[test]
fn prove_with_kzg_commitment() {
    let dir = tempdir().expect("tempdir");
    let proof_path = dir.path().join("proof_kzg.json");
    Command::cargo_bin("hc-cli")
        .expect("binary exists")
        .args([
            "prove",
            "--output",
            proof_path.to_str().expect("path utf8"),
            "--commitment",
            "kzg",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("trace commitment: kzg:"));

    Command::cargo_bin("hc-cli")
        .expect("binary exists")
        .args(["verify", "--input", proof_path.to_str().expect("path utf8")])
        .assert()
        .success()
        .stdout(predicate::str::contains("proof verified"));
}

#[test]
fn bench_respects_auto_profile() {
    let dir = tempdir().expect("tempdir");
    let bench_dir = dir.path();
    Command::cargo_bin("hc-cli")
        .expect("binary exists")
        .current_dir(bench_dir)
        .args([
            "bench",
            "--scenario",
            "prover",
            "--iterations",
            "1",
            "--auto-block-size",
            "--trace-length",
            "256",
            "--profile",
            "memory",
        ])
        .assert()
        .success();

    let latest = bench_dir.join("benchmarks/latest.json");
    assert!(latest.exists(), "benchmarks/latest.json should be created");
    let contents = std::fs::read_to_string(latest).expect("read latest");
    assert!(
        contents.contains("\"scenario\": \"prover\""),
        "bench output should mention scenario"
    );
}
