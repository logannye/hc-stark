import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def test_founding_program_is_capped_and_contains_no_customer_payloads() -> None:
    status = load("release/founding-validation-status-v1.json")
    assert status["schema_version"] == 1
    assert status["permanent_organization_cap"] == 3
    assert 0 <= status["accepted_organizations"] <= 3
    assert status["assistance_limit_minutes_per_organization"] == 240
    assert status["witness_data_accepted"] is False
    assert status["customer_specific_branches"] == 0
    assert status["private_ledger_schema"] == (
        "release/founding-validation-ledger-v1.schema.json"
    )
    assert all(
        isinstance(item, str) and item.startswith("release/evidence/")
        for item in status["public_evidence"]
    )


def test_private_ledger_schema_allows_only_the_locked_eight_fields() -> None:
    schema = load("release/founding-validation-ledger-v1.schema.json")
    assert schema["required"] == ["schema_version", "program", "organizations"]
    assert schema["properties"]["program"]["const"] == (
        "tinyzkp-guard-founding-validation-v1"
    )
    assert schema["properties"]["organizations"]["maxItems"] == 3
    record = schema["properties"]["organizations"]["items"]
    assert record["additionalProperties"] is False
    assert set(record["properties"]) == {
        "organization_id",
        "source_profile_evidence",
        "doctor_report_sha256",
        "compatibility_result",
        "pain_category",
        "assistance_minutes",
        "written_4990_acceptance",
        "purchase_outcome",
    }
    assert record["properties"]["organization_id"]["pattern"] == (
        "^org-[0-9a-f]{32}$"
    )
    serialized = json.dumps(schema).lower()
    for forbidden in (
        "proof_digest",
        "verifier_digest",
        "checkpoint_digest",
        "resource_summary",
        "resume_outcome",
        "unaided_time",
    ):
        assert forbidden not in serialized


def test_founding_metrics_remain_transparent_nonblocking_advisories() -> None:
    status = load("release/founding-validation-status-v1.json")
    launch = load("release/guard-launch-state-v2.json")
    advisory = launch["advisory_status"]
    assert advisory["three_external_workloads"] == "not_completed"
    assert advisory["two_standard_annual_customers"] == "not_completed"
    assert advisory["five_unaided_installs"] == "not_completed"
    assert status["market_gate_passed"] is False
    assert status["external_workloads"] == 0
    assert status["ordinary_paid_annual_subscriptions"] == 0
