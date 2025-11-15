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
        .stdout(predicate::str::contains("trace root"));

    Command::cargo_bin("hc-cli")
        .expect("binary exists")
        .args(["verify", "--input", proof_path.to_str().expect("path utf8")])
        .assert()
        .success()
        .stdout(predicate::str::contains("proof verified"));
}
