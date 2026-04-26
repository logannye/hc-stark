#![allow(deprecated)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
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
fn proof_file_is_succinctish() {
    let dir = tempdir().expect("tempdir");
    let proof_path = dir.path().join("proof.json");
    Command::cargo_bin("hc-cli")
        .expect("binary exists")
        .args(["prove", "--output", proof_path.to_str().expect("path utf8")])
        .assert()
        .success();

    let metadata = std::fs::metadata(&proof_path).expect("stat proof");
    // This is a coarse guardrail that catches accidental reintroduction of full-vector
    // oracle serialization (O(T)) for the toy trace used by the CLI.
    // With query_count=80 (production default for 128-bit security),
    // proofs are larger than with the legacy query_count=30.
    assert!(
        metadata.len() < 500_000,
        "proof.json unexpectedly large: {} bytes",
        metadata.len()
    );
}

#[test]
fn verify_rejects_tampered_proof_file() {
    let dir = tempdir().expect("tempdir");
    let proof_path = dir.path().join("proof.json");
    Command::cargo_bin("hc-cli")
        .expect("binary exists")
        .args(["prove", "--output", proof_path.to_str().expect("path utf8")])
        .assert()
        .success();

    // Flip a byte in the serialized proof JSON.
    let mut bytes = std::fs::read(&proof_path).expect("read proof");
    assert!(!bytes.is_empty(), "proof file should not be empty");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x5a;
    let mut f = std::fs::File::create(&proof_path).expect("rewrite proof");
    f.write_all(&bytes).expect("write tampered bytes");

    Command::cargo_bin("hc-cli")
        .expect("binary exists")
        .args(["verify", "--input", proof_path.to_str().expect("path utf8")])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
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
