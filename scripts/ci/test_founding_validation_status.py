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
    assert all(
        isinstance(item, str) and item.startswith("release/evidence/")
        for item in status["public_evidence"]
    )


def test_commercial_gate_cannot_outrun_founding_evidence() -> None:
    status = load("release/founding-validation-status-v1.json")
    launch = load("release/guard-launch-gates-v1.json")
    gate_status = launch["gate_status"]

    if gate_status["three_external_workloads"]["status"] == "passed":
        assert status["market_gate_passed"] is True
        assert status["external_workloads"] >= 3
        assert status["organizations_with_external_workloads"] >= 2
        assert status["standard_annual_price_acceptances"] >= 2

    if gate_status["two_standard_annual_customers"]["status"] == "passed":
        assert status["ordinary_paid_annual_subscriptions"] >= 2
