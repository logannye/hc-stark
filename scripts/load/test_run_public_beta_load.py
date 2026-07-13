import importlib.util
import os
from pathlib import Path
import sys

import pytest


MODULE_PATH = Path(__file__).with_name("run_public_beta_load.py")
SPEC = importlib.util.spec_from_file_location("run_public_beta_load", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def job(index):
    return {
        "idempotency_key": f"load-job-{index:02d}-unique",
        "request": {
            "air_package_id": f"air-{index}",
            "upload_id": f"upload-{index}",
            "public_inputs": {},
        },
    }


def scenario():
    return {
        "schema_version": 2,
        "api_base_url": "http://127.0.0.1:18090",
        "jobs": [job(index) for index in range(4)],
        "timeout_seconds": 3600,
        "poll_interval_seconds": 5,
        "minimum_predicted_rss_bytes": MODULE.MIN_RELEASE_PREDICTED_RSS,
    }


def test_scenario_requires_exact_advertised_concurrency():
    assert len(MODULE.validate_scenario(scenario())["jobs"]) == 4
    invalid = scenario()
    invalid["jobs"] = invalid["jobs"][:3]
    with pytest.raises(ValueError, match="exactly four"):
        MODULE.validate_scenario(invalid)


def test_scenario_rejects_duplicate_idempotency_keys_and_public_http():
    invalid = scenario()
    invalid["jobs"][1]["idempotency_key"] = invalid["jobs"][0]["idempotency_key"]
    with pytest.raises(ValueError, match="unique"):
        MODULE.validate_scenario(invalid)
    invalid = scenario()
    invalid["api_base_url"] = "http://api.tinyzkp.com"
    with pytest.raises(ValueError, match="HTTPS or a loopback"):
        MODULE.validate_scenario(invalid)


def test_percentile_is_deterministic_and_bounded():
    assert MODULE.percentile([4.0, 1.0, 3.0, 2.0], 0.50) == 2.0
    assert MODULE.percentile([4.0, 1.0, 3.0, 2.0], 0.99) == 3.0


def telemetry():
    return {
        "schema_version": 1,
        "status": "passed",
        "release_sha": "a" * 40,
        "sample_interval_seconds": 5,
        "worker": {
            "slots": 4,
            "threads_per_job": 2,
            "effective_cpus": 8,
            "memory_limit_bytes": 16 * 1024 * 1024 * 1024,
            "swap_bytes": 0,
            "oom_events": 0,
            "unexpected_restarts": 0,
            "leaked_scratch_directories": 0,
            "max_heartbeat_age_seconds": 30,
            "max_scratch_utilization_percent": 60,
        },
        "postgres": {
            "configured_max_connections": 40,
            "max_observed_connections": 20,
            "deadlocks": 0,
            "statement_timeouts": 0,
            "lock_timeouts": 0,
        },
    }


def test_telemetry_requires_the_fixed_envelope_and_clean_database():
    assert MODULE.validate_telemetry(telemetry(), "a" * 40)["status"] == "passed"
    invalid = telemetry()
    invalid["worker"]["oom_events"] = 1
    with pytest.raises(ValueError, match="fixed production envelope"):
        MODULE.validate_telemetry(invalid, "a" * 40)


def test_scenario_requires_independent_artifacts_and_near_limit_jobs():
    invalid = scenario()
    invalid["jobs"][1]["request"]["upload_id"] = invalid["jobs"][0]["request"]["upload_id"]
    with pytest.raises(ValueError, match="independent"):
        MODULE.validate_scenario(invalid)
    invalid = scenario()
    invalid["minimum_predicted_rss_bytes"] = MODULE.MIN_RELEASE_PREDICTED_RSS - 1
    with pytest.raises(ValueError, match="85% of the bounded working-set envelope"):
        MODULE.validate_scenario(invalid)


def test_load_target_uses_the_effective_bounded_working_set_and_hard_cap():
    assert MODULE.EFFECTIVE_PREDICTED_RSS_ENVELOPE < MODULE.MAX_PREDICTED_RSS
    assert MODULE.MIN_RELEASE_PREDICTED_RSS == (
        MODULE.EFFECTIVE_PREDICTED_RSS_ENVELOPE * 85 // 100
    )
    assert MODULE.MIN_RELEASE_PREDICTED_RSS < 1_082_130_432 < MODULE.MAX_PREDICTED_RSS


def test_prepare_candidates_are_descending_unique_powers_of_two():
    assert MODULE.parse_candidate_rows("1048576,4194304,2097152") == [
        4_194_304,
        2_097_152,
        1_048_576,
    ]
    for invalid in ("", "1024,1024", "1000", "33554432"):
        with pytest.raises(ValueError):
            MODULE.parse_candidate_rows(invalid)


def test_four_load_air_variants_have_distinct_digests_inputs_and_equal_work():
    canary = Path(__file__).resolve().parents[1] / "canary"
    sys.path.insert(0, str(canary))
    try:
        import declarative_fixtures
    finally:
        sys.path.pop(0)
    variants = [MODULE.customer_load_variant(declarative_fixtures, index) for index in range(4)]
    names = [tuple(item["name"] for item in variant.air["public_inputs"]) for variant in variants]
    assert len(set(names)) == 4
    assert all(variant.air["constraints"] == variants[0].air["constraints"] for variant in variants)
    assert len({variant.name for variant in variants}) == 4
    wall = MODULE.predicted_wall_time_ms(variants[0].air, 1 << 24)
    assert 1_000 <= wall < MODULE.MAX_PREDICTED_WALL_MS


def test_load_outputs_are_owner_only_and_never_replaced(tmp_path: Path):
    output = tmp_path / "private" / "load.json"
    MODULE.write_private_json(output, {"status": "passed"})
    assert os.stat(output).st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="refusing to replace"):
        MODULE.write_private_json(output, {"status": "passed"})


def test_signed_cli_identity_and_bundle_verification_are_mandatory(tmp_path: Path, monkeypatch):
    release_sha = "a" * 40
    cli = tmp_path / "hc-cli"
    cli.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = release ]; then\n"
        f"  printf '%s\\n' '{{\"release_sha\":\"{release_sha}\"}}'\n"
        "  exit 0\n"
        "fi\n"
        "test \"$1 $2 $3\" = 'plonky3 verify-hosted --bundle'\n",
        encoding="utf-8",
    )
    cli.chmod(0o700)
    monkeypatch.setenv("TINYZKP_CLI", str(cli))
    selected = MODULE.signed_cli(release_sha)
    MODULE.verify_bundle_with_signed_cli(selected, {"schema_version": 1})
    with pytest.raises(RuntimeError, match="release identity"):
        MODULE.signed_cli("b" * 40)
