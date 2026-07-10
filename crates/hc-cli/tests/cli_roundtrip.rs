use assert_cmd::cargo::cargo_bin_cmd;
use hc_plonky3::{CancellationToken, ResourceBoundedUniStarkProver, WorkloadKind};
use hc_stream::{CheckpointPolicy, ResourceMode, ResourcePolicyV1};
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
    assert_eq!(
        payload["dependency_lock_sha256"],
        "7a3e859e9d457006e38737f418fdf16f0e538977c23bf9882b4225d43b3db455"
    );
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

    let prove_output = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "prove",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output",
            bundle.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(prove_output.status.success());
    let events: Vec<serde_json::Value> = String::from_utf8(prove_output.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(events
        .iter()
        .any(|event| event["event"] == "resource_estimate"));
    let final_phase = events
        .iter()
        .find(|event| event["event"] == "phase" && event["phase"] == "proof_assembly")
        .unwrap();
    assert_eq!(final_phase["completed_phases"], final_phase["total_phases"]);
    assert_eq!(final_phase["progress"], 1.0);
    assert!(final_phase["resource_usage"]["scratch_bytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
    #[cfg(target_os = "linux")]
    assert!(final_phase["resource_usage"]["resident_bytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
    assert!(events
        .iter()
        .any(|event| event["event"] == "prove_completed"));

    cargo_bin_cmd!("hc-cli")
        .args(["plonky3", "verify", "--bundle", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("official p3-uni-stark verifier"));
}

#[test]
fn prove_failure_emits_json_without_witness_values() {
    let dir = tempdir().unwrap();
    let manifest = write_fibonacci_manifest(dir.path());
    let mut payload: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    payload["input_generator"]["initial_a"] = json!(1_234_567_890_u64);
    payload["input_generator"]["initial_b"] = json!(9_876_543_210_u64);
    payload["resource_policy"]["max_scratch_bytes"] = json!(1);
    std::fs::write(&manifest, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    let output = dir.path().join("must-not-exist.json");

    let result = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "prove",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
    let events: Vec<serde_json::Value> = String::from_utf8(result.stderr)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    assert!(events.iter().any(|event| event["event"] == "prove_failed"));
    let encoded = serde_json::to_string(&events).unwrap();
    assert!(!encoded.contains("initial_a"));
    assert!(!encoded.contains("initial_b"));
    assert!(!encoded.contains("1234567890"));
    assert!(!encoded.contains("9876543210"));
}

#[test]
fn plonky3_resume_cli_consumes_a_durable_checkpoint() {
    let dir = tempdir().unwrap();
    let scratch = dir.path().join("scratch");
    let policy = ResourcePolicyV1 {
        mode: ResourceMode::Scratch,
        max_resident_bytes: 128 * 1024 * 1024,
        max_scratch_bytes: 1024 * 1024 * 1024,
        scratch_dir: scratch.clone(),
        max_threads: 1,
        checkpoint_policy: CheckpointPolicy::RetainOnFailure,
    };
    let cancellation = CancellationToken::new();
    let observer_token = cancellation.clone();
    let result = ResourceBoundedUniStarkProver::new(policy)
        .unwrap()
        .prove_with_events_and_cancellation(
            WorkloadKind::Fibonacci {
                initial_a: 0,
                initial_b: 1,
            },
            8,
            cancellation,
            move |event| {
                if matches!(
                    event,
                    hc_plonky3::ProverEventV1::Phase {
                        phase: hc_stream::PipelinePhaseV1::Trace,
                        ..
                    }
                ) {
                    observer_token.cancel();
                }
            },
        );
    assert!(result.is_err());
    let job = std::fs::read_dir(&scratch)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let checkpoint = job.join("checkpoint.json");
    assert!(checkpoint.is_file());
    let output = dir.path().join("resumed-bundle.json");

    let resume = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "resume",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        resume.status.success(),
        "{}",
        String::from_utf8_lossy(&resume.stderr)
    );
    let events: Vec<serde_json::Value> = String::from_utf8(resume.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(events
        .iter()
        .any(|event| event["event"] == "resume_started"));
    assert!(events
        .iter()
        .any(|event| event["event"] == "resume_completed"));
    cargo_bin_cmd!("hc-cli")
        .args(["plonky3", "verify", "--bundle", output.to_str().unwrap()])
        .assert()
        .success();
    assert!(
        !job.exists(),
        "successful resume must clean durable artifacts"
    );
}

#[test]
fn doctor_accepts_a_complete_manifest_and_reports_all_pipeline_phases() {
    let dir = tempdir().unwrap();
    let manifest = write_fibonacci_manifest(dir.path());
    let output = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "doctor",
            "--manifest",
            manifest.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let phases = report["estimate"]["phases"].as_array().unwrap();
    assert!(phases.iter().any(|phase| phase["phase"] == "trace_lde"));
    assert!(phases.iter().any(|phase| phase["phase"] == "fri"));
}

#[test]
fn doctor_uses_the_same_auto_and_memory_preflight_as_the_prover() {
    let dir = tempdir().unwrap();
    let manifest = write_fibonacci_manifest(dir.path());
    let mut payload: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    payload["logical_rows"] = json!(1 << 20);
    payload["resource_policy"]["mode"] = json!("auto");
    std::fs::write(&manifest, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();

    let output = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "doctor",
            "--manifest",
            manifest.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["selected_mode"], "scratch");
    assert!(report["estimate"]["phases"]
        .as_array()
        .unwrap()
        .iter()
        .any(|phase| phase["phase"] == "trace_lde"));

    payload["resource_policy"]["mode"] = json!("memory");
    payload["resource_policy"]["max_resident_bytes"] = json!(16 * 1024 * 1024);
    std::fs::write(&manifest, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "doctor",
            "--manifest",
            manifest.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("resident memory"))
        .stderr(predicate::str::contains("\"event\":\"doctor_failed\""))
        .stderr(predicate::str::contains("\"estimate\""));
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

#[test]
fn benchmark_worker_reports_prover_scratch_high_water() {
    let dir = tempdir().unwrap();
    let manifest = write_fibonacci_manifest(dir.path());
    let output = dir.path().join("worker.json");
    cargo_bin_cmd!("hc-cli")
        .args([
            "benchmark-worker",
            "--manifest",
            manifest.to_str().unwrap(),
            "--mode",
            "bounded",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success();
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    assert_eq!(report["verification_succeeded"], true);
    assert!(report["prover_scratch_high_water_bytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
}
