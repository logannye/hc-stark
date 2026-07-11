import importlib.util
from pathlib import Path

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
            "air_package_id": "a",
            "upload_id": "u",
            "public_inputs": {},
        },
    }


def scenario():
    return {
        "schema_version": 1,
        "api_base_url": "http://127.0.0.1:18090",
        "jobs": [job(index) for index in range(4)],
        "timeout_seconds": 3600,
        "poll_interval_seconds": 5,
        "minimum_predicted_rss_bytes": 0,
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
