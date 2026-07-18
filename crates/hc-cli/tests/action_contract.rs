#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::tempdir;
use tinyzkp_contracts::{
    ArtifactReferenceV1, EngineErrorEnvelopeV1, JobResultV1, JobStatusV1, ObservedResourcesV1,
    ReasonCodeV1, ReasonV1, ReleaseIdentityV1, RequestedModeV1, ResourceEstimateV1,
    ResourceEstimatesV1, SelectedModeV1, VerifierOutcomeV1,
};

const ACTION: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../.github/actions/tinyzkp-guard/run.sh"
);
const VALIDATOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../.github/actions/tinyzkp-guard/validate-result.py"
);

fn executable(path: &std::path::Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn base_command(operation: &str, root: &std::path::Path) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(ACTION)
        .current_dir(root)
        .env("TINYZKP_ACTION_OPERATION", operation)
        .env("TINYZKP_ACTION_ENGINE", root.join("engine"))
        .env("TINYZKP_ACTION_GUARD", root.join("guard"))
        .env("TINYZKP_ACTION_JOB", "job.json")
        .env("TINYZKP_ACTION_JOB_DIR", "jobs/example")
        .env("TINYZKP_ACTION_REPORT", "result.json")
        .env("TINYZKP_ACTION_BASELINE", "baseline.json")
        .env(
            "TINYZKP_ACTION_PATH",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../.github/actions/tinyzkp-guard"
            ),
        );
    command
}

fn release() -> ReleaseIdentityV1 {
    ReleaseIdentityV1 {
        guard_version: "1.0.0".into(),
        guard_source_identity: "guard-source".into(),
        engine_source_identity: "engine-source".into(),
        engine_artifact_sha256: "a".repeat(64),
        release_identity: "tinyzkp-guard/1.0.0+qualified".into(),
        compatibility_profile: tinyzkp_contracts::COMPATIBILITY_PROFILE.into(),
        qualification: "candidate_build_authorized".into(),
    }
}

fn estimates() -> ResourceEstimatesV1 {
    ResourceEstimatesV1 {
        conventional: ResourceEstimateV1 {
            peak_resident_bytes: 1_000,
            scratch_high_water_bytes: 0,
            total_read_bytes: 2_000,
            total_write_bytes: 1_000,
        },
        bounded: ResourceEstimateV1 {
            peak_resident_bytes: 500,
            scratch_high_water_bytes: 2_000,
            total_read_bytes: 4_000,
            total_write_bytes: 3_000,
        },
    }
}

fn succeeded_result() -> JobResultV1 {
    JobResultV1 {
        schema_version: 1,
        status: JobStatusV1::Succeeded,
        requested_mode: RequestedModeV1::Auto,
        selected_mode: SelectedModeV1::Bounded,
        estimates: estimates(),
        observed_resources: Some(ObservedResourcesV1 {
            peak_resident_bytes: 400,
            scratch_high_water_bytes: 1_500,
            wall_time_millis: 10,
        }),
        release: release(),
        proof: Some(ArtifactReferenceV1 {
            relative_path: "proofs/air-proof-bundle-v1.json".into(),
            sha256: "b".repeat(64),
        }),
        verifier_outcome: VerifierOutcomeV1::Accepted,
        reason: None,
        resumable: false,
        checkpoint_relative_path: None,
    }
}

fn interrupted_result() -> JobResultV1 {
    JobResultV1 {
        schema_version: 1,
        status: JobStatusV1::Interrupted,
        requested_mode: RequestedModeV1::Bounded,
        selected_mode: SelectedModeV1::Bounded,
        estimates: estimates(),
        observed_resources: None,
        release: release(),
        proof: None,
        verifier_outcome: VerifierOutcomeV1::NotRun,
        reason: Some(ReasonV1::new(ReasonCodeV1::InterruptedResumable)),
        resumable: true,
        checkpoint_relative_path: Some("checkpoint.json".into()),
    }
}

fn write_guard_output<T: serde::Serialize>(root: &std::path::Path, value: &T) {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    fs::write(root.join("guard-output.json"), bytes).unwrap();
}

fn guard_emits(root: &std::path::Path, exit_code: u8) {
    executable(
        &root.join("guard"),
        &format!("#!/usr/bin/env bash\ncat guard-output.json\nexit {exit_code}\n"),
    );
}

fn validator_accepts(
    root: &std::path::Path,
    kind: &str,
    expectation: &str,
    value: &serde_json::Value,
) -> bool {
    let path = root.join("validator-input.json");
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    Command::new("python3")
        .args([VALIDATOR, kind, expectation, path.to_str().unwrap()])
        .status()
        .unwrap()
        .success()
}

#[test]
fn free_doctor_dispatches_only_to_the_community_engine() {
    let dir = tempdir().unwrap();
    executable(
        &dir.path().join("engine"),
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" > engine.args\nprintf '{\"ready\":true}\\n'\n",
    );
    executable(&dir.path().join("guard"), "#!/usr/bin/env bash\nexit 99\n");
    let output = base_command("doctor", dir.path()).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(dir.path().join("engine.args")).unwrap(),
        "doctor --job job.json\n"
    );
    assert_eq!(output.stdout, b"{\"ready\":true}\n");
}

#[test]
fn paid_operations_require_self_hosted_linux_x64_and_dispatch_explicitly() {
    let dir = tempdir().unwrap();
    write_guard_output(dir.path(), &succeeded_result());
    executable(
        &dir.path().join("guard"),
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" > guard.args\ncat guard-output.json\n",
    );
    let hosted = base_command("run", dir.path())
        .env("RUNNER_OS", "Linux")
        .env("RUNNER_ARCH", "X64")
        .env("RUNNER_ENVIRONMENT", "github-hosted")
        .output()
        .unwrap();
    assert_eq!(hosted.status.code(), Some(11));
    assert!(String::from_utf8_lossy(&hosted.stderr).contains("self-hosted"));

    let output = base_command("run", dir.path())
        .env("RUNNER_OS", "Linux")
        .env("RUNNER_ARCH", "X64")
        .env("RUNNER_ENVIRONMENT", "self-hosted")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(dir.path().join("guard.args")).unwrap(),
        "run --job job.json\n"
    );
    assert!(dir.path().join("result.json").is_file());
}

#[test]
fn action_rejects_unknown_operations_and_has_no_secret_or_download_surface() {
    let dir = tempdir().unwrap();
    let output = base_command("activate", dir.path()).output().unwrap();
    assert_eq!(output.status.code(), Some(11));
    let action_yaml =
        include_str!("../../../.github/actions/tinyzkp-guard/action.yml").to_ascii_lowercase();
    let runner = include_str!("../../../.github/actions/tinyzkp-guard/run.sh").to_ascii_lowercase();
    let operation = action_yaml
        .split_once("  operation:")
        .unwrap()
        .1
        .split_once("  engine-binary:")
        .unwrap()
        .0;
    assert!(operation.contains("default: doctor"));
    for forbidden in [
        "license-key",
        "license_key",
        "api-key",
        "api_key",
        "curl ",
        "wget ",
        "http://",
        "https://",
    ] {
        assert!(!action_yaml.contains(forbidden), "{forbidden}");
        assert!(!runner.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn failed_run_preserves_existing_report_and_forwards_typed_error() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("result.json"), b"existing\n").unwrap();
    write_guard_output(
        dir.path(),
        &EngineErrorEnvelopeV1::new(
            "engine-source",
            ReasonV1::new(ReasonCodeV1::VerificationRejected),
            false,
            false,
        ),
    );
    guard_emits(dir.path(), 15);
    let output = base_command("run", dir.path())
        .env("RUNNER_OS", "Linux")
        .env("RUNNER_ARCH", "X64")
        .env("RUNNER_ENVIRONMENT", "self-hosted")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(15));
    assert_eq!(
        fs::read(dir.path().join("result.json")).unwrap(),
        b"existing\n"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"exit_code\":15"));
}

#[test]
fn interrupted_run_atomically_publishes_result_and_preserves_exit_thirteen() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("result.json"), b"old\n").unwrap();
    write_guard_output(dir.path(), &interrupted_result());
    guard_emits(dir.path(), 13);
    let output = base_command("run", dir.path())
        .env("RUNNER_OS", "Linux")
        .env("RUNNER_ARCH", "X64")
        .env("RUNNER_ENVIRONMENT", "self-hosted")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(13));
    let result: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("result.json")).unwrap()).unwrap();
    assert_eq!(result["status"], "interrupted");
    assert_eq!(result["reason"]["code"], "interrupted_resumable");
}

#[test]
fn action_validator_rejects_nested_contract_and_semantic_mutations() {
    let dir = tempdir().unwrap();
    let succeeded = serde_json::to_value(succeeded_result()).unwrap();
    let interrupted = serde_json::to_value(interrupted_result()).unwrap();
    let error = serde_json::to_value(EngineErrorEnvelopeV1::new(
        "engine-source",
        ReasonV1::new(ReasonCodeV1::VerificationRejected),
        false,
        false,
    ))
    .unwrap();
    assert!(validator_accepts(
        dir.path(),
        "job-result",
        "succeeded",
        &succeeded
    ));
    assert!(validator_accepts(
        dir.path(),
        "job-result",
        "interrupted",
        &interrupted
    ));
    assert!(validator_accepts(
        dir.path(),
        "error-envelope",
        "15",
        &error
    ));

    let mut mutations = Vec::new();
    let mut missing_estimate_field = succeeded.clone();
    missing_estimate_field["estimates"]["conventional"]
        .as_object_mut()
        .unwrap()
        .remove("total_write_bytes");
    mutations.push(missing_estimate_field);
    let mut boolean_bytes = succeeded.clone();
    boolean_bytes["estimates"]["bounded"]["peak_resident_bytes"] = serde_json::json!(true);
    mutations.push(boolean_bytes);
    let mut invalid_release = succeeded.clone();
    invalid_release["release"]["engine_artifact_sha256"] = serde_json::json!("ABC");
    mutations.push(invalid_release);
    let mut escaping_proof = succeeded.clone();
    escaping_proof["proof"]["relative_path"] = serde_json::json!("../proof.json");
    mutations.push(escaping_proof);
    let mut zero_observation = succeeded.clone();
    zero_observation["observed_resources"]["wall_time_millis"] = serde_json::json!(0);
    mutations.push(zero_observation);
    for mutation in mutations {
        assert!(!validator_accepts(
            dir.path(),
            "job-result",
            "succeeded",
            &mutation
        ));
    }

    let mut truncated_reason = interrupted;
    truncated_reason["reason"] = serde_json::json!({"code": "interrupted_resumable"});
    assert!(!validator_accepts(
        dir.path(),
        "job-result",
        "interrupted",
        &truncated_reason
    ));
    let mut wrong_exit = error.clone();
    wrong_exit["error"]["exit_code"] = serde_json::json!(70);
    assert!(!validator_accepts(
        dir.path(),
        "error-envelope",
        "15",
        &wrong_exit
    ));
    assert!(!validator_accepts(
        dir.path(),
        "error-envelope",
        "70",
        &error
    ));
    let mut noncanonical_reason = error;
    noncanonical_reason["error"]["reason"]["summary"] = serde_json::json!("tampered");
    assert!(!validator_accepts(
        dir.path(),
        "error-envelope",
        "15",
        &noncanonical_reason
    ));
}
