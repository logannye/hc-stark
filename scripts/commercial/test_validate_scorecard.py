import copy

import validate_scorecard as scorecard


def example():
    return {
        "schema_version": 1,
        "period": "2026-07",
        "contracted_arr_usd": 60_000,
        "cash_collected_usd": 60_000,
        "evaluation_revenue_usd": 0,
        "recurring_software_revenue_usd": 5_000,
        "recurring_software_cogs_usd": 500,
        "hosted_revenue_usd": 0,
        "hosted_cogs_usd": 0,
        "buyer_calls_completed": 3,
        "reproducible_bottlenecks": 1,
        "benchmark_reports_received": 1,
        "evaluations_sold": 1,
        "annual_conversions": 1,
        "customers": [
            {"customer_id": "customer-a", "arr_usd": 60_000, "support_hours_quarter_to_date": 4}
        ],
        "pipeline": [
            {"stage": "annual_signed", "evidence": "agreement-1", "contracted_value_usd": 60_000}
        ],
        "runway_months": 12,
    }


def test_valid_evidence_scorecard_passes():
    assert scorecard.validate(example()) == []


def test_vanity_pipeline_and_unbounded_support_fail():
    payload = copy.deepcopy(example())
    payload["directory_listings"] = 10
    payload["customers"][0]["support_hours_quarter_to_date"] = 11
    payload["pipeline"][0] = {
        "stage": "interview_completed",
        "evidence": "calendar-call",
        "contracted_value_usd": 50_000,
    }
    failures = scorecard.validate(payload)
    assert any("vanity metrics" in failure for failure in failures)
    assert any("support hours" in failure for failure in failures)
    assert any("zero contracted value" in failure for failure in failures)


def test_margin_floors_fail_closed():
    payload = example()
    payload["recurring_software_cogs_usd"] = 501
    payload["hosted_revenue_usd"] = 100
    payload["hosted_cogs_usd"] = 21
    failures = scorecard.validate(payload)
    assert "recurring software gross margin is below 90%" in failures
    assert "hosted gross margin is below 80%" in failures
