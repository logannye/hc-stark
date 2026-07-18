#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::tempdir;

const ACTION: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../.github/actions/tinyzkp-guard/run.sh"
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
    executable(
        &dir.path().join("guard"),
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" > guard.args\nprintf '%s\\n' '{\"schema_version\":1,\"status\":\"succeeded\",\"requested_mode\":\"auto\",\"selected_mode\":\"bounded\",\"estimates\":{},\"observed_resources\":null,\"release\":{},\"proof\":null,\"verifier_outcome\":\"accepted\",\"reason\":null,\"resumable\":false,\"checkpoint_relative_path\":null}'\n",
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
    for forbidden in [
        "license-key",
        "license_key",
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
    executable(
        &dir.path().join("guard"),
        "#!/usr/bin/env bash\nprintf '%s\\n' '{\"schema_version\":1,\"engine_release_identity\":\"release\",\"ok\":false,\"error\":{\"class\":\"verification_failure\",\"exit_code\":15,\"reason\":{\"code\":\"verification_rejected\"},\"resumable\":false,\"checkpoint_present\":false}}'\nexit 15\n",
    );
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
    executable(
        &dir.path().join("guard"),
        "#!/usr/bin/env bash\nprintf '%s\\n' '{\"schema_version\":1,\"status\":\"interrupted\",\"requested_mode\":\"bounded\",\"selected_mode\":\"bounded\",\"estimates\":{},\"observed_resources\":null,\"release\":{},\"proof\":null,\"verifier_outcome\":\"not_run\",\"reason\":{\"code\":\"interrupted_resumable\"},\"resumable\":true,\"checkpoint_relative_path\":\"engine/checkpoint.json\"}'\nexit 13\n",
    );
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
