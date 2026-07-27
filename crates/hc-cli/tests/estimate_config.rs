use std::io::Write;

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

#[test]
fn unknown_field_is_rejected_with_a_clear_error() {
    let cfg = write_config(&BABYBEAR_MULTI_TABLE.replace("babybear", "bn254"));
    let err = hc_cli::commands::estimate_config::run(cfg.path()).unwrap_err();
    assert!(
        err.to_string().contains("bn254"),
        "error must name the unsupported field, got: {err}"
    );
}

#[test]
fn malformed_config_is_rejected() {
    let cfg = write_config("{ not json");
    assert!(hc_cli::commands::estimate_config::run(cfg.path()).is_err());
}
