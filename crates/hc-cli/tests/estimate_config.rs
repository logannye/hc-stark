use std::io::Write;

use assert_cmd::cargo::cargo_bin_cmd;
use hc_cli::protocol::ProtocolFailure;
use tinyzkp_contracts::{EngineErrorEnvelopeV1, ReasonCodeV1};

fn write_config(json: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(json.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

const BABYBEAR_MULTI_TABLE: &str = r#"{
  "schema_version": 1,
  "field": "babybear",
  "extension_degree": 4,
  "logical_rows": 4194304,
  "trace_width": 180,
  "max_constraint_degree": 3,
  "public_values": 8,
  "has_next_row_columns": true,
  "features": {
    "uses_lookups": true,
    "uses_buses": false,
    "uses_permutations": false,
    "uses_multi_table": true,
    "uses_preprocessed_columns": false,
    "uses_periodic_columns": false,
    "uses_recursion": false,
    "uses_gpu": false
  },
  "ram_budget_bytes": 2147483648
}"#;

/// The product in one test: a config we cannot prove still returns real
/// numbers, flagged as unprovable.
#[test]
fn estimates_a_config_that_cannot_be_proved() {
    let cfg = write_config(BABYBEAR_MULTI_TABLE);
    let response = hc_cli::commands::estimate_config::run(cfg.path()).unwrap();

    assert!(!response.provable_today);
    assert!(!response.blocking_reasons.is_empty());
    assert!(response.estimates.bounded.peak_resident_bytes > 0);
    assert!(response.estimates.conventional.peak_resident_bytes > 0);
    assert!(!response.request_digest.is_empty());
}

/// The headline claim must be visible in the output: bounded mode needs
/// materially less resident memory than conventional.
#[test]
fn bounded_estimate_is_below_conventional() {
    let cfg = write_config(BABYBEAR_MULTI_TABLE);
    let response = hc_cli::commands::estimate_config::run(cfg.path()).unwrap();
    assert!(
        response.estimates.bounded.peak_resident_bytes
            < response.estimates.conventional.peak_resident_bytes,
        "bounded {} must be below conventional {}",
        response.estimates.bounded.peak_resident_bytes,
        response.estimates.conventional.peak_resident_bytes
    );
}

/// In-process check that an unsupported field fails as a structured
/// `ProtocolFailure` carrying `UnsupportedProfile`, not a bare/opaque
/// `anyhow` error that would fall through `protocol::failure_from_anyhow`
/// to `internal_error`. `ReasonV1` forbids free-form diagnostic text on the
/// wire, so this deliberately does NOT assert anything about "bn254"
/// appearing in the error — see
/// `unknown_field_cli_end_to_end_is_not_internal_error` below for the actual
/// wire-level guarantee.
#[test]
fn unknown_field_is_rejected_as_unsupported_profile() {
    let cfg = write_config(&BABYBEAR_MULTI_TABLE.replace("babybear", "bn254"));
    let err = hc_cli::commands::estimate_config::run(cfg.path()).unwrap_err();
    let failure = err
        .downcast_ref::<ProtocolFailure>()
        .expect("unsupported field must fail as a ProtocolFailure, not a bare anyhow error");
    assert_eq!(failure.reason.code, ReasonCodeV1::UnsupportedProfile);
}

#[test]
fn malformed_config_is_rejected() {
    let cfg = write_config("{ not json");
    assert!(hc_cli::commands::estimate_config::run(cfg.path()).is_err());
}

/// Drives the real `tinyzkp-engine` binary end to end. This is the guard
/// against the defect this test replaces caught in review: `run()` returning
/// a plain `anyhow!(...)` for an unsupported field meant `main()`'s
/// `protocol::failure_from_anyhow` couldn't downcast it, so the CLI printed
/// `internal_error` for a config that was simply unsupported, not broken.
#[test]
fn unknown_field_cli_end_to_end_is_not_internal_error() {
    let cfg = write_config(&BABYBEAR_MULTI_TABLE.replace("babybear", "bn254"));
    let output = cargo_bin_cmd!("hc-cli")
        .args(["estimate", "--config"])
        .arg(cfg.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let envelope: EngineErrorEnvelopeV1 = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(envelope.error.reason.code, ReasonCodeV1::InternalError);
    assert_eq!(envelope.error.reason.code, ReasonCodeV1::UnsupportedProfile);
}

/// A declared RAM budget below `MIN_RAM_BUDGET_BYTES` must still produce a
/// full estimate (with `provable_today: false` and `RamBudgetInsufficient`
/// among `blocking_reasons`), not a hard CLI failure. Drives the real binary
/// so the whole path — including whatever `ResourcePolicyV1` construction
/// `run()` does internally — is exercised, not just `run()`'s Rust-level
/// contract.
#[test]
fn ram_budget_below_minimum_still_estimates_end_to_end() {
    let cfg = write_config(&BABYBEAR_MULTI_TABLE.replace("2147483648", "1048576"));
    let output = cargo_bin_cmd!("hc-cli")
        .args(["estimate", "--config"])
        .arg(cfg.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["provable_today"], false);
    let reasons = response["blocking_reasons"].as_array().unwrap();
    assert!(
        reasons
            .iter()
            .any(|reason| reason["code"] == "ram_budget_insufficient"),
        "expected ram_budget_insufficient among {reasons:?}"
    );
    assert!(
        response["estimates"]["bounded"]["peak_resident_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        response["estimates"]["conventional"]["peak_resident_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
}
