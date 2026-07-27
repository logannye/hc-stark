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

/// An entirely ordinary first-time-user config: 1,000,000 rows (not a power
/// of two, but nothing a real caller would expect to be treated as an
/// internal fault) on the field TinyZKP actually proves.
const GOLDILOCKS_ORDINARY_NON_POW2_ROWS: &str = r#"{
  "schema_version": 1,
  "field": "goldilocks",
  "extension_degree": 2,
  "logical_rows": 1000000,
  "trace_width": 8,
  "max_constraint_degree": 3,
  "public_values": 3,
  "has_next_row_columns": false,
  "features": {
    "uses_lookups": false,
    "uses_buses": false,
    "uses_permutations": false,
    "uses_multi_table": false,
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

/// `estimate_from_params`'s only documented failure mode
/// (`BoundedProverError::UnsupportedProfile`, for rows that are zero or not
/// a power of two) must reach the caller as `ReasonCodeV1::UnsupportedProfile`.
/// 1,000,000 is an entirely ordinary number a first-time user might type —
/// it happens not to be a power of two, but that is not an internal fault.
/// This regression guards the defect this fix replaces: every
/// `estimate_from_params` error used to be collapsed onto `InternalError`,
/// so this exact config produced exit 70 / `internal_error` /
/// "generate_support_report" for a config that was simply unsupported.
#[test]
fn ordinary_non_power_of_two_rows_is_unsupported_profile_not_internal_error() {
    let cfg = write_config(GOLDILOCKS_ORDINARY_NON_POW2_ROWS);
    let err = hc_cli::commands::estimate_config::run(cfg.path()).unwrap_err();
    let failure = err
        .downcast_ref::<ProtocolFailure>()
        .expect("non-power-of-two rows must fail as a ProtocolFailure, not a bare anyhow error");
    assert_ne!(failure.reason.code, ReasonCodeV1::InternalError);
    assert_eq!(failure.reason.code, ReasonCodeV1::UnsupportedProfile);
}

/// Same defect, driven through the real `tinyzkp-engine` binary end to end,
/// mirroring `unknown_field_cli_end_to_end_is_not_internal_error` above: the
/// wire-level JSON error envelope, not just `run()`'s Rust-level contract,
/// must name `unsupported_profile`.
#[test]
fn ordinary_non_power_of_two_rows_cli_end_to_end_is_not_internal_error() {
    let cfg = write_config(GOLDILOCKS_ORDINARY_NON_POW2_ROWS);
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

/// `logical_rows`/`trace_width` far beyond anything this estimator was
/// built to price must be refused outright (`UnsupportedProfile`) rather
/// than priced and silently saturated. 2^48 and 2^50 rows are the exact
/// values that, before the overflow fix, produced
/// `total_read_bytes = 10_700_552_714_632_300_784` and
/// `1_297_036_692_682_705_071` respectively — the second, larger row count
/// producing a *smaller* answer. The ceiling in `estimate_config::run` means
/// neither of these ever reaches the estimator at all now.
#[test]
fn rows_far_beyond_the_ceiling_are_refused_not_estimated() {
    for rows in [1u64 << 48, 1u64 << 50] {
        let cfg = write_config(&BABYBEAR_MULTI_TABLE.replace("4194304", &rows.to_string()));
        let err = hc_cli::commands::estimate_config::run(cfg.path()).unwrap_err();
        let failure = err.downcast_ref::<ProtocolFailure>().unwrap_or_else(|| {
            panic!("rows={rows} beyond the ceiling must fail as a ProtocolFailure")
        });
        assert_eq!(failure.reason.code, ReasonCodeV1::UnsupportedProfile);
    }
}

/// Same ceiling, for `trace_width`.
#[test]
fn trace_width_far_beyond_the_ceiling_is_refused_not_estimated() {
    let cfg = write_config(
        &BABYBEAR_MULTI_TABLE.replace("\"trace_width\": 180", "\"trace_width\": 4294967295"),
    );
    let err = hc_cli::commands::estimate_config::run(cfg.path()).unwrap_err();
    let failure = err
        .downcast_ref::<ProtocolFailure>()
        .expect("trace_width beyond the ceiling must fail as a ProtocolFailure");
    assert_eq!(failure.reason.code, ReasonCodeV1::UnsupportedProfile);
}
