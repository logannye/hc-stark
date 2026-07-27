use assert_cmd::cargo::cargo_bin_cmd;
use hc_plonky3::contracts::{AirPackageV1, AirProofBundleV1, PublicInputsV1, TraceManifestV1};
#[cfg(unix)]
use hc_plonky3::contracts::{ProofBundleV1, WorkloadManifestV1};
use hc_plonky3::{
    CancellationToken, ResourceBoundedUniStarkProver, UploadedTraceWorkload, WorkloadKind,
};
use hc_stream::{CheckpointManifestV2, CheckpointPolicy, ResourceMode, ResourcePolicyV1};
use predicates::prelude::*;
use serde_json::json;
use std::collections::BTreeMap;
#[cfg(unix)]
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Output;
#[cfg(unix)]
use std::process::{Command, Stdio};
use tempfile::tempdir;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}

#[cfg(unix)]
const SIGTERM: i32 = 15;

fn expected_engine_release_identity() -> String {
    option_env!("HC_RELEASE_SHA")
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            std::env::var("HC_RELEASE_SHA")
                .ok()
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "development-unreleased".into())
}

fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, current: &Path, snapshot: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        let mut entries: Vec<_> = std::fs::read_dir(current)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                snapshot.insert(relative, None);
                visit(root, &path, snapshot);
            } else {
                snapshot.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

fn run_checkpoint_inspection(root: &Path, checkpoint: &Path) -> Output {
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "inspect-checkpoint",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--air",
            root.join("inputs/air.json").to_str().unwrap(),
            "--trace-manifest",
            root.join("inputs/trace.json").to_str().unwrap(),
            "--chunks-dir",
            root.join("inputs/chunks").to_str().unwrap(),
            "--public-inputs",
            root.join("inputs/public.json").to_str().unwrap(),
            "--policy",
            root.join("inspect-policy.json").to_str().unwrap(),
        ])
        .output()
        .unwrap()
}

fn assert_checkpoint_inspection_failure(output: &Output, exit: i32, reason: &str) {
    assert_eq!(
        output.status.code(),
        Some(exit),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    assert!(output.stderr.is_empty());
    let failure: tinyzkp_contracts::EngineErrorEnvelopeV1 =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(failure.error.reason.code.as_str(), reason);
    assert!(!failure.error.resumable);
}

#[test]
fn release_identity_is_machine_readable_and_profile_pinned() {
    let expected_release_sha = option_env!("HC_RELEASE_SHA").unwrap_or("abc123");
    let output = cargo_bin_cmd!("hc-cli")
        .env("HC_RELEASE_SHA", "abc123")
        .arg("release")
        .output()
        .unwrap();
    assert!(output.status.success());
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(payload["service"], "cli");
    assert_eq!(payload["release_sha"], expected_release_sha);
    assert_eq!(payload["plonky3_version"], "0.6.1");
    assert_eq!(payload["compatibility_profile"], "tinyzkp-p3-goldilocks-v1");
    assert_eq!(
        payload["dependency_lock_sha256"],
        "e124d2c46bf7e313edc2c4b06ea90633d9a929a430d5d1657d032a581f760990"
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

fn write_customer_air(dir: &std::path::Path) -> std::path::PathBuf {
    let air = dir.join("air.json");
    let payload = json!({
        "schema_version": 1,
        "backend": "plonky3",
        "profile": "tinyzkp-p3-goldilocks-v1",
        "field": "goldilocks",
        "expected_verifier": "p3_uni_stark_0.6.1",
        "trace_width": 1,
        "public_inputs": [],
        "expressions": [
            {"op": "current", "column": 0},
            {"op": "next", "column": 0},
            {"op": "sub", "left": 1, "right": 0}
        ],
        "constraints": [{"kind": "transition", "expression": 2}]
    });
    std::fs::write(&air, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    air
}

fn write_doctor_job(
    dir: &std::path::Path,
    mode: &str,
    ram_budget_bytes: u64,
) -> std::path::PathBuf {
    write_doctor_job_with_rows(dir, mode, ram_budget_bytes, 1024)
}

fn write_doctor_job_with_rows(
    dir: &std::path::Path,
    mode: &str,
    ram_budget_bytes: u64,
    logical_rows: u64,
) -> std::path::PathBuf {
    for relative in ["inputs/chunks", "jobs", "outputs", "scratch"] {
        std::fs::create_dir_all(dir.join(relative)).unwrap();
    }
    let generated_air = write_customer_air(dir);
    let air_bytes = std::fs::read(&generated_air).unwrap();
    let air: AirPackageV1 = serde_json::from_slice(&air_bytes).unwrap();
    std::fs::write(dir.join("inputs/air.json"), air_bytes).unwrap();
    let air_digest: String = air
        .digest()
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let raw_trace = vec![0u8; usize::try_from(logical_rows).unwrap() * 8];
    let compressed = zstd::stream::encode_all(raw_trace.as_slice(), 3).unwrap();
    std::fs::write(dir.join("inputs/chunks/chunk-000000.zst"), &compressed).unwrap();
    let trace_manifest = json!({
        "schema_version": 1,
        "air_digest_hex": air_digest.clone(),
        "trace_digest_hex": format!("{}", blake3::hash(&raw_trace).to_hex()),
        "logical_rows": logical_rows,
        "trace_width": 1,
        "field_encoding": "goldilocks_u64_le",
        "compression": "zstd",
        "chunk_uncompressed_bytes": raw_trace.len(),
        "chunks": [{
            "index": 0,
            "compressed_bytes": compressed.len(),
            "uncompressed_bytes": raw_trace.len(),
            "blake3_hex": format!("{}", blake3::hash(&compressed).to_hex())
        }]
    });
    std::fs::write(
        dir.join("inputs/trace.json"),
        serde_json::to_vec_pretty(&trace_manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("inputs/public.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "air_digest_hex": air_digest,
            "values": []
        }))
        .unwrap(),
    )
    .unwrap();
    let job = dir.join("job.json");
    std::fs::write(
        &job,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
            "workload": {
                "air_package": "air.json",
                "trace_manifest": "trace.json",
                "chunks_dir": "chunks",
                "public_inputs": "public.json",
                "logical_rows": logical_rows,
                "trace_width": 1,
                "max_constraint_degree": 2,
                "field": "goldilocks",
                "extension_degree": 2,
                "permutation": "poseidon2_width_8",
                "verifier": "p3_uni_stark_0.6.1",
                "features": {
                    "uses_lookups": false,
                    "uses_buses": false,
                    "uses_permutations": false,
                    "uses_multi_table": false,
                    "uses_preprocessed_columns": false,
                    "uses_periodic_columns": false,
                    "uses_recursion": false,
                    "uses_gpu": false
                }
            },
            "mode": mode,
            "ram_budget_bytes": ram_budget_bytes,
            "scratch_budget_bytes": 2147483648u64,
            "max_threads": 1,
            "roots": {
                "input_root": "inputs",
                "job_root": "jobs",
                "output_root": "outputs",
                "scratch_root": "scratch"
            },
            "job_dir": "example",
            "output_dir": "example",
            "scratch_dir": "example"
        }))
        .unwrap(),
    )
    .unwrap();
    job
}

fn assert_air_operation_report(
    stdout: &[u8],
    selected_mode: &str,
    expect_scratch_usage: bool,
) -> serde_json::Value {
    assert_eq!(
        stdout.iter().filter(|byte| **byte == b'\n').count(),
        1,
        "stdout must contain exactly one JSON report"
    );
    let report: serde_json::Value = serde_json::from_slice(stdout).unwrap();
    assert_eq!(report.as_object().unwrap().len(), 6);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(
        report["engine_release_identity"],
        expected_engine_release_identity()
    );
    assert_eq!(report["selected_mode"], selected_mode);
    assert!(report["wall_time_millis"]
        .as_u64()
        .is_some_and(|value| value > 0));
    assert!(report["peak_resident_bytes"].is_u64());
    #[cfg(target_os = "linux")]
    assert!(report["peak_resident_bytes"]
        .as_u64()
        .is_some_and(|value| value > 0));
    if expect_scratch_usage {
        assert!(report["scratch_high_water_bytes"]
            .as_u64()
            .is_some_and(|value| value > 0));
    } else {
        assert!(report["scratch_high_water_bytes"].is_u64());
    }
    report
}

#[test]
fn validates_air_and_packs_canonical_fixed_size_trace_chunks() {
    let dir = tempdir().unwrap();
    let air = write_customer_air(dir.path());
    cargo_bin_cmd!("hc-cli")
        .args(["plonky3", "validate-air", "--air", air.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"));

    let trace = dir.path().join("trace.bin");
    let mut bytes = Vec::with_capacity(1024 * 8);
    for row in 0..1024u64 {
        let value = if row == 1023 {
            hc_plonky3::GOLDILOCKS_MODULUS_U64 - 1
        } else {
            row
        };
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    std::fs::write(&trace, bytes).unwrap();
    let packed = dir.path().join("packed");
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "pack-trace",
            "--air",
            air.to_str().unwrap(),
            "--trace",
            trace.to_str().unwrap(),
            "--rows",
            "1024",
            "--output-dir",
            packed.to_str().unwrap(),
            "--chunk-bytes",
            "4096",
        ])
        .assert()
        .success();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(packed.join("trace-manifest-v1.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["chunk_uncompressed_bytes"], 4096);
    assert_eq!(manifest["chunks"].as_array().unwrap().len(), 2);
    assert!(packed.join("chunk-000000.zst").is_file());
    assert!(packed.join("chunk-000001.zst").is_file());
}

#[test]
fn pack_trace_rejects_noncanonical_field_values() {
    let dir = tempdir().unwrap();
    let air = write_customer_air(dir.path());
    let trace = dir.path().join("trace.bin");
    let mut bytes = vec![0u8; 1024 * 8];
    bytes[..8].copy_from_slice(&hc_plonky3::GOLDILOCKS_MODULUS_U64.to_le_bytes());
    std::fs::write(&trace, bytes).unwrap();
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "pack-trace",
            "--air",
            air.to_str().unwrap(),
            "--trace",
            trace.to_str().unwrap(),
            "--rows",
            "1024",
            "--output-dir",
            dir.path().join("packed").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "\"code\":\"manifest_contract_invalid\"",
        ))
        .stderr(predicate::str::is_empty());
}

#[test]
fn declarative_air_cli_proves_estimates_and_officially_verifies() {
    let dir = tempdir().unwrap();
    let air_path = write_customer_air(dir.path());
    let air: AirPackageV1 = serde_json::from_slice(&std::fs::read(&air_path).unwrap()).unwrap();
    let air_digest: String = air
        .digest()
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let trace = dir.path().join("constant-trace.bin");
    std::fs::write(&trace, vec![0u8; 1024 * 8]).unwrap();
    let packed = dir.path().join("packed-proof");
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "pack-trace",
            "--air",
            air_path.to_str().unwrap(),
            "--trace",
            trace.to_str().unwrap(),
            "--rows",
            "1024",
            "--output-dir",
            packed.to_str().unwrap(),
        ])
        .assert()
        .success();
    let public_inputs = dir.path().join("public-inputs.json");
    std::fs::write(
        &public_inputs,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "air_digest_hex": air_digest,
            "values": []
        }))
        .unwrap(),
    )
    .unwrap();
    let policy = dir.path().join("policy.json");
    std::fs::write(
        &policy,
        serde_json::to_vec_pretty(&json!({
            "mode": "scratch",
            "max_resident_bytes": 134217728,
            "max_scratch_bytes": 2147483648u64,
            "scratch_dir": dir.path().join("scratch"),
            "max_threads": 1,
            "checkpoint_policy": "delete_on_success"
        }))
        .unwrap(),
    )
    .unwrap();
    let trace_manifest = packed.join("trace-manifest-v1.json");
    let estimate = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "estimate-air",
            "--air",
            air_path.to_str().unwrap(),
            "--trace-manifest",
            trace_manifest.to_str().unwrap(),
            "--public-inputs",
            public_inputs.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        estimate.status.success(),
        "{}",
        String::from_utf8_lossy(&estimate.stderr)
    );
    let estimate: serde_json::Value = serde_json::from_slice(&estimate.stdout).unwrap();
    assert_eq!(estimate["schema_version"], 1);
    assert_eq!(estimate["selected_mode"], "bounded");
    assert!(estimate["estimates"]["conventional"]["peak_resident_bytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
    assert!(estimate["estimates"]["bounded"]["scratch_high_water_bytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
    let bundle = dir.path().join("air-proof-bundle.json");
    let proved = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "prove-air",
            "--air",
            air_path.to_str().unwrap(),
            "--trace-manifest",
            trace_manifest.to_str().unwrap(),
            "--chunks-dir",
            packed.to_str().unwrap(),
            "--public-inputs",
            public_inputs.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--checkpoint-dir",
            dir.path().join("air-checkpoint").to_str().unwrap(),
            "--output",
            bundle.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        proved.status.success(),
        "{}",
        String::from_utf8_lossy(&proved.stderr)
    );
    assert_air_operation_report(&proved.stdout, "bounded", true);
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "verify-air",
            "--bundle",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"accepted\":true"))
        .stdout(predicate::str::contains(format!(
            "\"engine_release_identity\":\"{}\"",
            expected_engine_release_identity()
        )));

    let conventional_bundle = dir.path().join("air-proof-bundle-conventional.json");
    let conventional = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "prove-air",
            "--air",
            air_path.to_str().unwrap(),
            "--trace-manifest",
            trace_manifest.to_str().unwrap(),
            "--chunks-dir",
            packed.to_str().unwrap(),
            "--public-inputs",
            public_inputs.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--checkpoint-dir",
            dir.path().join("reference-checkpoint").to_str().unwrap(),
            "--output",
            conventional_bundle.to_str().unwrap(),
            "--reference",
        ])
        .output()
        .unwrap();
    assert!(
        conventional.status.success(),
        "{}",
        String::from_utf8_lossy(&conventional.stderr)
    );
    assert_air_operation_report(&conventional.stdout, "conventional", false);
}

#[test]
fn plonky3_air_job_contracts() {
    let dir = tempdir().unwrap();
    let air_path = write_customer_air(dir.path());
    let air: AirPackageV1 = serde_json::from_slice(&std::fs::read(&air_path).unwrap()).unwrap();
    let air_digest: String = air
        .digest()
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let trace = dir.path().join("constant-trace.bin");
    std::fs::write(&trace, vec![0u8; 1024 * 8]).unwrap();
    let packed = dir.path().join("packed-resume");
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "pack-trace",
            "--air",
            air_path.to_str().unwrap(),
            "--trace",
            trace.to_str().unwrap(),
            "--rows",
            "1024",
            "--output-dir",
            packed.to_str().unwrap(),
        ])
        .assert()
        .success();
    let trace_manifest_path = packed.join("trace-manifest-v1.json");
    let trace_manifest: TraceManifestV1 =
        serde_json::from_slice(&std::fs::read(&trace_manifest_path).unwrap()).unwrap();
    let public_inputs_path = dir.path().join("public-inputs-resume.json");
    std::fs::write(
        &public_inputs_path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "air_digest_hex": air_digest,
            "values": []
        }))
        .unwrap(),
    )
    .unwrap();
    let public_inputs: PublicInputsV1 =
        serde_json::from_slice(&std::fs::read(&public_inputs_path).unwrap()).unwrap();
    let policy_path = dir.path().join("policy-contract.json");
    std::fs::write(
        &policy_path,
        serde_json::to_vec_pretty(&json!({
            "mode": "scratch",
            "max_resident_bytes": 134217728,
            "max_scratch_bytes": 2147483648u64,
            "scratch_dir": dir.path().join("scratch-contract"),
            "max_threads": 1,
            "checkpoint_policy": "delete_on_success"
        }))
        .unwrap(),
    )
    .unwrap();
    let estimated = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "estimate-air",
            "--air",
            air_path.to_str().unwrap(),
            "--trace-manifest",
            trace_manifest_path.to_str().unwrap(),
            "--public-inputs",
            public_inputs_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(estimated.status.success());
    let estimate: serde_json::Value = serde_json::from_slice(&estimated.stdout).unwrap();
    assert_eq!(estimate["schema_version"], 1);
    assert_eq!(estimate["selected_mode"], "bounded");
    assert!(estimate["estimates"]["conventional"]["peak_resident_bytes"].is_u64());
    assert!(estimate["estimates"]["bounded"]["peak_resident_bytes"].is_u64());
    assert!(estimate["estimates"]["bounded"]["scratch_high_water_bytes"].is_u64());

    let proved_output = dir.path().join("contract-proof.json");
    let proved = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "prove-air",
            "--air",
            air_path.to_str().unwrap(),
            "--trace-manifest",
            trace_manifest_path.to_str().unwrap(),
            "--chunks-dir",
            packed.to_str().unwrap(),
            "--public-inputs",
            public_inputs_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--checkpoint-dir",
            dir.path().join("contract-checkpoint").to_str().unwrap(),
            "--output",
            proved_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        proved.status.success(),
        "{}",
        String::from_utf8_lossy(&proved.stderr)
    );
    assert_air_operation_report(&proved.stdout, "bounded", true);
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "verify-air",
            "--bundle",
            proved_output.to_str().unwrap(),
        ])
        .assert()
        .success();

    let workload =
        UploadedTraceWorkload::new(air, trace_manifest, public_inputs.values, &packed).unwrap();
    let scratch = dir.path().join("scratch-resume");
    let policy = ResourcePolicyV1 {
        mode: ResourceMode::Scratch,
        max_resident_bytes: 128 * 1024 * 1024,
        max_scratch_bytes: 2 * 1024 * 1024 * 1024,
        scratch_dir: scratch.clone(),
        max_threads: 1,
        checkpoint_policy: CheckpointPolicy::RetainOnFailure,
    };
    let cancellation = CancellationToken::new();
    let observer_token = cancellation.clone();
    let interrupted = hc_plonky3::prove_resource_bounded_observed_with_cancellation(
        &workload,
        &policy,
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
    assert!(matches!(
        interrupted,
        Err(hc_plonky3::BoundedProverError::Cancelled)
    ));
    let job = std::fs::read_dir(&scratch)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let checkpoint = job.join("checkpoint.json");
    let output = dir.path().join("resumed-air-proof.json");
    let resumed = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "resume-air",
            "--air",
            air_path.to_str().unwrap(),
            "--trace-manifest",
            trace_manifest_path.to_str().unwrap(),
            "--chunks-dir",
            packed.to_str().unwrap(),
            "--public-inputs",
            public_inputs_path.to_str().unwrap(),
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let events: Vec<serde_json::Value> = String::from_utf8(resumed.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(events
        .iter()
        .any(|event| event["event"] == "resource_estimate"));
    assert!(events
        .iter()
        .any(|event| event["event"] == "phase" && event["phase"] == "proof_assembly"));
    assert_air_operation_report(&resumed.stdout, "bounded", true);
    let bundle: AirProofBundleV1 =
        serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    bundle.verify().unwrap();
    assert!(!job.exists());
}

#[test]
fn checkpoint_inspection_is_complete_typed_and_read_only() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    write_doctor_job(root, "bounded", 128 * 1024 * 1024);
    let air: AirPackageV1 =
        serde_json::from_slice(&std::fs::read(root.join("inputs/air.json")).unwrap()).unwrap();
    let trace: TraceManifestV1 =
        serde_json::from_slice(&std::fs::read(root.join("inputs/trace.json")).unwrap()).unwrap();
    let public_inputs: PublicInputsV1 =
        serde_json::from_slice(&std::fs::read(root.join("inputs/public.json")).unwrap()).unwrap();
    let workload =
        UploadedTraceWorkload::new(air, trace, public_inputs.values, root.join("inputs/chunks"))
            .unwrap();
    let checkpoint_dir = root.join("inspection-job");
    let policy = ResourcePolicyV1 {
        mode: ResourceMode::Scratch,
        max_resident_bytes: 128 * 1024 * 1024,
        max_scratch_bytes: 2 * 1024 * 1024 * 1024,
        scratch_dir: root.join("engine-scratch"),
        max_threads: 1,
        checkpoint_policy: CheckpointPolicy::RetainOnFailure,
    };
    std::fs::write(
        root.join("inspect-policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let observer_token = cancellation.clone();
    let interrupted =
        hc_plonky3::prove_resource_bounded_observed_with_cancellation_at_checkpoint_dir(
            &workload,
            &policy,
            &checkpoint_dir,
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
    assert!(matches!(
        interrupted,
        Err(hc_plonky3::BoundedProverError::Cancelled)
    ));

    let checkpoint = checkpoint_dir.join("checkpoint.json");
    let original_checkpoint = std::fs::read(&checkpoint).unwrap();
    let original_manifest: CheckpointManifestV2 =
        serde_json::from_slice(&original_checkpoint).unwrap();
    assert!(!original_manifest.artifacts.is_empty());

    let before = snapshot_tree(root);
    let valid = run_checkpoint_inspection(root, &checkpoint);
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert!(valid.stderr.is_empty());
    assert_eq!(
        valid.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let result: tinyzkp_contracts::EngineCheckpointInspectResultV1 =
        serde_json::from_slice(&valid.stdout).unwrap();
    assert!(result.validate(&hc_plonky3::release_identity()));
    let result_value: serde_json::Value = serde_json::from_slice(&valid.stdout).unwrap();
    let keys: std::collections::BTreeSet<_> =
        result_value.as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        [
            "checkpoint_release_identity_match",
            "compatibility_profile",
            "engine_release_identity",
            "schema_version",
            "selected_mode",
            "valid",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    );
    assert_eq!(snapshot_tree(root), before);

    std::fs::write(&checkpoint, b"{").unwrap();
    assert_checkpoint_inspection_failure(
        &run_checkpoint_inspection(root, &checkpoint),
        14,
        "checkpoint_corrupt",
    );

    std::fs::write(
        &checkpoint,
        &original_checkpoint[..original_checkpoint.len() / 2],
    )
    .unwrap();
    assert_checkpoint_inspection_failure(
        &run_checkpoint_inspection(root, &checkpoint),
        14,
        "checkpoint_corrupt",
    );

    let mut stale = original_manifest.clone();
    stale.release_hash = [0x5a; 32];
    std::fs::write(&checkpoint, serde_json::to_vec_pretty(&stale).unwrap()).unwrap();
    assert_checkpoint_inspection_failure(
        &run_checkpoint_inspection(root, &checkpoint),
        14,
        "checkpoint_release_mismatch",
    );

    std::fs::write(&checkpoint, &original_checkpoint).unwrap();

    let policy_path = root.join("inspect-policy.json");
    let original_policy = std::fs::read(&policy_path).unwrap();
    let mut mismatched_policy = policy.clone();
    mismatched_policy.max_scratch_bytes += 1;
    std::fs::write(
        &policy_path,
        serde_json::to_vec_pretty(&mismatched_policy).unwrap(),
    )
    .unwrap();
    assert_checkpoint_inspection_failure(
        &run_checkpoint_inspection(root, &checkpoint),
        14,
        "checkpoint_corrupt",
    );
    std::fs::write(&policy_path, &original_policy).unwrap();

    let artifact_path = checkpoint_dir.join(&original_manifest.artifacts[0].relative_path);
    let original_artifact = std::fs::read(&artifact_path).unwrap();
    let mut corrupt_artifact = original_artifact.clone();
    *corrupt_artifact.last_mut().unwrap() ^= 0x80;
    std::fs::write(&artifact_path, &corrupt_artifact).unwrap();
    assert_checkpoint_inspection_failure(
        &run_checkpoint_inspection(root, &checkpoint),
        14,
        "checkpoint_corrupt",
    );
    std::fs::write(&artifact_path, &original_artifact).unwrap();

    std::fs::remove_file(&checkpoint).unwrap();
    assert_checkpoint_inspection_failure(
        &run_checkpoint_inspection(root, &checkpoint),
        14,
        "checkpoint_missing",
    );
    std::fs::write(&checkpoint, &original_checkpoint).unwrap();

    let chunk_path = root.join("inputs/chunks/chunk-000000.zst");
    let original_chunk = std::fs::read(&chunk_path).unwrap();
    let mut corrupt_chunk = original_chunk.clone();
    *corrupt_chunk.last_mut().unwrap() ^= 0x01;
    std::fs::write(&chunk_path, &corrupt_chunk).unwrap();
    assert_checkpoint_inspection_failure(
        &run_checkpoint_inspection(root, &checkpoint),
        11,
        "manifest_contract_invalid",
    );
    std::fs::write(&chunk_path, &original_chunk).unwrap();

    assert_eq!(snapshot_tree(root), before);
}

#[test]
fn production_generic_commands_fail_with_typed_invalid_input() {
    for command in ["prove", "verify"] {
        cargo_bin_cmd!("hc-cli")
            .arg(command)
            .assert()
            .failure()
            .stdout(predicate::str::contains(
                "\"code\":\"manifest_contract_invalid\"",
            ))
            .stderr(predicate::str::is_empty());
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
        .stdout(predicate::str::contains("\"accepted\":true"));
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

#[cfg(unix)]
#[test]
fn sigterm_retains_resumable_checkpoint_and_resume_is_byte_identical() {
    let dir = tempdir().unwrap();
    let manifest = write_fibonacci_manifest(dir.path());
    let mut payload: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    payload["logical_rows"] = json!(4096);
    payload["resource_policy"]["checkpoint_policy"] = json!("retain_on_failure");
    std::fs::write(&manifest, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    let interrupted_output = dir.path().join("interrupted-bundle.json");

    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("hc-cli"))
        .args([
            "plonky3",
            "prove",
            "--manifest",
            manifest.to_str().unwrap(),
            "--output",
            interrupted_output.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let mut captured = String::new();
    let checkpoint = loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0, "{captured}");
        captured.push_str(&line);
        let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if event["event"] == "phase"
            && event["phase"] == "trace"
            && event["checkpoint_durable"] == true
        {
            let scratch = dir.path().join("scratch");
            let path = std::fs::read_dir(scratch)
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.path().join("checkpoint.json"))
                .find(|candidate| candidate.is_file())
                .expect("durable trace event must correspond to a checkpoint");
            break path;
        }
    };

    // The CLI installs its signal handler before entering the prover. Sending
    // SIGTERM after the first durable phase therefore exercises the real
    // operator cancellation path, not the in-process test cancellation token.
    let signal_result = unsafe { kill(child.id() as i32, SIGTERM) };
    assert_eq!(signal_result, 0);
    let status = child.wait().unwrap();
    reader.read_to_string(&mut captured).unwrap();
    assert!(!status.success(), "{captured}");
    assert!(
        captured.contains("\"event\":\"prove_cancelled\""),
        "{captured}"
    );
    assert!(checkpoint.is_file());
    assert!(!interrupted_output.exists());

    let resumed_output = dir.path().join("resumed-bundle.json");
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "resume",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--output",
            resumed_output.to_str().unwrap(),
        ])
        .assert()
        .success();
    let resumed: ProofBundleV1 =
        serde_json::from_slice(&std::fs::read(&resumed_output).unwrap()).unwrap();
    resumed.verify().unwrap();

    let typed_manifest: WorkloadManifestV1 =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    let reference = ResourceBoundedUniStarkProver::prove_reference(
        WorkloadKind::Fibonacci {
            initial_a: 0,
            initial_b: 1,
        },
        typed_manifest.logical_rows,
    )
    .unwrap();
    let reference =
        ProofBundleV1::from_internal(typed_manifest, reference, "sigterm-test").unwrap();
    assert_eq!(resumed.proof_base64url, reference.proof_base64url);
}

#[cfg(unix)]
#[test]
fn declarative_air_sigterm_uses_exact_checkpoint_dir_and_typed_resume_protocol() {
    let dir = tempdir().unwrap();
    let _job = write_doctor_job_with_rows(dir.path(), "bounded", 128 * 1024 * 1024, 16 * 1024);
    let policy = dir.path().join("policy-exact-checkpoint.json");
    std::fs::write(
        &policy,
        serde_json::to_vec_pretty(&json!({
            "mode": "scratch",
            "max_resident_bytes": 128 * 1024 * 1024,
            "max_scratch_bytes": 2 * 1024 * 1024 * 1024u64,
            "scratch_dir": dir.path().join("engine-scratch"),
            "max_threads": 1,
            "checkpoint_policy": "retain_on_failure"
        }))
        .unwrap(),
    )
    .unwrap();
    let checkpoint_dir = dir.path().join("exact-checkpoint");
    let interrupted_bundle = dir.path().join("interrupted-air-bundle.json");
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("hc-cli"))
        .args([
            "plonky3",
            "prove-air",
            "--air",
            dir.path().join("inputs/air.json").to_str().unwrap(),
            "--trace-manifest",
            dir.path().join("inputs/trace.json").to_str().unwrap(),
            "--chunks-dir",
            dir.path().join("inputs/chunks").to_str().unwrap(),
            "--public-inputs",
            dir.path().join("inputs/public.json").to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--checkpoint-dir",
            checkpoint_dir.to_str().unwrap(),
            "--output",
            interrupted_bundle.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let mut captured_stderr = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0, "{captured_stderr}");
        captured_stderr.push_str(&line);
        let event: tinyzkp_contracts::ProgressEventV1 =
            serde_json::from_str(&line).expect("every progress line must satisfy the public type");
        assert!(event.validate(&expected_engine_release_identity()));
        if event.event == "phase"
            && event.phase.as_deref() == Some("trace")
            && event.checkpoint_durable == Some(true)
        {
            assert!(checkpoint_dir.join("checkpoint.json").is_file());
            break;
        }
    }

    assert_eq!(unsafe { kill(child.id() as i32, SIGTERM) }, 0);
    let status = child.wait().unwrap();
    reader.read_to_string(&mut captured_stderr).unwrap();
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert_eq!(status.code(), Some(13), "{captured_stderr}");
    assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
    let failure: tinyzkp_contracts::EngineErrorEnvelopeV1 =
        serde_json::from_slice(&stdout).unwrap();
    assert_eq!(failure.error.reason.code.as_str(), "interrupted_resumable");
    assert!(failure.error.resumable);
    assert!(failure.error.checkpoint_present);
    assert!(!interrupted_bundle.exists());

    let resumed_bundle = dir.path().join("resumed-air-bundle.json");
    let resumed = cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "resume-air",
            "--air",
            dir.path().join("inputs/air.json").to_str().unwrap(),
            "--trace-manifest",
            dir.path().join("inputs/trace.json").to_str().unwrap(),
            "--chunks-dir",
            dir.path().join("inputs/chunks").to_str().unwrap(),
            "--public-inputs",
            dir.path().join("inputs/public.json").to_str().unwrap(),
            "--checkpoint",
            checkpoint_dir.join("checkpoint.json").to_str().unwrap(),
            "--output",
            resumed_bundle.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_air_operation_report(&resumed.stdout, "bounded", true);
    for line in String::from_utf8_lossy(&resumed.stderr).lines() {
        let event: tinyzkp_contracts::ProgressEventV1 = serde_json::from_str(line).unwrap();
        assert!(event.validate(&expected_engine_release_identity()));
    }
    cargo_bin_cmd!("hc-cli")
        .args([
            "plonky3",
            "verify-air",
            "--bundle",
            resumed_bundle.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn root_doctor_emits_one_complete_report_and_only_typed_progress() {
    let dir = tempdir().unwrap();
    let manifest = write_doctor_job(dir.path(), "auto", 4 * 1024 * 1024 * 1024);
    let absolute = cargo_bin_cmd!("hc-cli")
        .args(["doctor", "--job", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(absolute.status.code(), Some(11));
    assert_eq!(
        absolute
            .stdout
            .iter()
            .filter(|byte| **byte == b'\n')
            .count(),
        1
    );
    let failure: tinyzkp_contracts::EngineErrorEnvelopeV1 =
        serde_json::from_slice(&absolute.stdout).unwrap();
    assert_eq!(failure.error.reason.code.as_str(), "unsafe_path");

    let output = cargo_bin_cmd!("hc-cli")
        .current_dir(dir.path())
        .args(["doctor", "--job", "job.json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        assert!(output.status.success());
        assert_eq!(report["ready"], true);
        assert!(report["estimates"]["conventional"]["peak_resident_bytes"].is_u64());
        assert!(report["estimates"]["bounded"]["scratch_high_water_bytes"].is_u64());
    } else {
        assert_eq!(output.status.code(), Some(10));
        assert_eq!(report["reasons"][0]["code"], "unsupported_platform");
    }
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        let event: tinyzkp_contracts::ProgressEventV1 = serde_json::from_str(line).unwrap();
        assert!(event.validate(&expected_engine_release_identity()));
    }
}

#[test]
fn doctor_exit_ten_and_twelve_flush_complete_reports() {
    let dir = tempdir().unwrap();
    let manifest = write_doctor_job(dir.path(), "auto", 4 * 1024 * 1024 * 1024);
    let mut payload: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    payload["compatibility_profile"] = json!("unsupported-profile");
    std::fs::write(&manifest, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    let output = cargo_bin_cmd!("hc-cli")
        .current_dir(dir.path())
        .args(["doctor", "--job", "job.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["reasons"][0]["code"], "unsupported_profile");

    payload["compatibility_profile"] = json!("tinyzkp-p3-goldilocks-v1");
    payload["mode"] = json!("conventional");
    payload["ram_budget_bytes"] = json!(16 * 1024 * 1024);
    std::fs::write(&manifest, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    let output = cargo_bin_cmd!("hc-cli")
        .current_dir(dir.path())
        .args(["doctor", "--job", "job.json"])
        .output()
        .unwrap();
    let expected = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        12
    } else {
        10
    };
    assert_eq!(output.status.code(), Some(expected));
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let codes: Vec<_> = report["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|reason| reason["code"].as_str())
        .collect();
    if expected == 12 {
        assert!(codes.contains(&"ram_budget_insufficient"));
    } else {
        assert!(codes.contains(&"unsupported_platform"));
    }
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
        .stdout(predicate::str::contains(
            "\"code\":\"verification_rejected\"",
        ))
        .stderr(predicate::str::is_empty());
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
        "air-package-v1.schema.json",
        "trace-manifest-v1.schema.json",
        "public-inputs-v1.schema.json",
        "air-proof-bundle-v1.schema.json",
    ] {
        assert!(dir.path().join(file).is_file());
    }
    assert_eq!(tinyzkp_contracts::PUBLIC_SCHEMA_NAMES.len(), 12);
    for file in tinyzkp_contracts::PUBLISHED_SCHEMA_NAMES {
        let mut expected =
            serde_json::to_vec_pretty(&tinyzkp_contracts::schema_by_name(file).unwrap()).unwrap();
        expected.push(b'\n');
        assert_eq!(
            std::fs::read(dir.path().join(file)).unwrap(),
            expected,
            "{file}"
        );
        let checked_in = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../site/schemas")
            .join(file);
        assert_eq!(
            std::fs::read(&checked_in).unwrap(),
            expected,
            "{} must be the exact exporter output",
            checked_in.display()
        );
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
    assert!(report["peak_rss_bytes"].as_u64().is_some());
    #[cfg(target_os = "linux")]
    assert!(report["peak_rss_bytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
}

#[test]
fn benchmark_estimate_is_read_only_and_manifest_bound() {
    let dir = tempdir().unwrap();
    let manifest = write_fibonacci_manifest(dir.path());
    let output = cargo_bin_cmd!("hc-cli")
        .args([
            "benchmark-estimate",
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
    assert_eq!(report["schema_version"], 1);
    assert!(report["manifest_digest_hex"]
        .as_str()
        .is_some_and(|digest| digest.len() == 64));
    assert!(report["estimate"]["peak_resident_bytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
    assert!(report["estimate"]["scratch_high_water_bytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
}
