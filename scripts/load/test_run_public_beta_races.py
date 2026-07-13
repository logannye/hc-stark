import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).with_name("run_public_beta_races.py")
SPEC = importlib.util.spec_from_file_location("run_public_beta_races", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


SHA = "a" * 40


def evidence():
    cases = [
        {"id": case, "status": "passed", "outcomes": {"ok": True}}
        for case in MODULE.CASE_IDS
    ]
    cases[-1]["outcomes"] = {
        "ledger_mismatches": 0,
        "pending_events": 0,
        "database_state_sha256": "b" * 64,
    }
    return {
        "schema_version": MODULE.SCHEMA,
        "status": "passed",
        "release_sha": SHA,
        "database": "tinyzkp_beta_race_" + SHA[:12],
        "started_at": "2026-07-12T00:00:00+00:00",
        "completed_at": "2026-07-12T00:01:00+00:00",
        "cases": cases,
    }


def test_complete_evidence_passes():
    assert MODULE.validate_evidence(evidence(), SHA)["status"] == "passed"


def test_missing_case_or_pending_event_fails():
    value = evidence()
    value["cases"].pop()
    with pytest.raises(ValueError, match="case set"):
        MODULE.validate_evidence(value, SHA)
    value = evidence()
    value["cases"][-1]["outcomes"]["pending_events"] = 1
    with pytest.raises(ValueError, match="not clean"):
        MODULE.validate_evidence(value, SHA)


def test_parallel_releases_all_waiters():
    observed = MODULE.parallel(16, lambda index: index)
    assert sorted(observed) == list(range(16))


@pytest.mark.parametrize("name", ["postgres", "tinyzkp_beta_race_bad", "tinyzkp_beta_race_aaaaaaaaaaaa_extra"])
def test_database_name_is_fail_closed(name):
    assert MODULE.DATABASE.fullmatch(name) is None
