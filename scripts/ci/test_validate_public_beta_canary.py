from datetime import datetime, timedelta, timezone

import validate_public_beta_canary as canary


def valid():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    workloads = ["fibonacci", "poseidon2", "customer_cubic8"]
    return {
        "schema_version": 1,
        "release_channel": "public_beta",
        "release_sha": "a" * 40,
        "started_at": start.isoformat(),
        "completed_at": (start + timedelta(hours=24)).isoformat(),
        "hourly_verified_proofs": [
            {"workload": workloads[index % 3], "official_verification": True} for index in range(24)
        ],
        "cancellation_refund_exercises": [{"full_reservation_released": True} for _ in range(4)],
        "live_billing_canaries": [
            {"kind": "topup", "synthetic": True, "refunded": True, "excluded_from_revenue": True},
            {"kind": "subscription", "synthetic": True, "cancelled": True, "refunded": True, "excluded_from_revenue": True},
        ],
        "verifier_failures": 0,
        "unexplained_credit_differences": 0,
        "stuck_leases": 0,
        "unauthorized_artifact_accesses": 0,
        "leaked_scratch_directories": 0,
        "status": "passed",
    }


def test_accepts_exact_24_hour_contract():
    assert canary.validate(valid(), "a" * 40) == []


def test_rejects_missing_proof_and_credit_difference():
    value = valid()
    value["hourly_verified_proofs"].pop()
    value["unexplained_credit_differences"] = 1
    failures = canary.validate(value, "a" * 40)
    assert any("24 hourly" in failure for failure in failures)
    assert any("credit" in failure for failure in failures)
