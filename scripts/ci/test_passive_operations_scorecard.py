import copy
import hashlib
from pathlib import Path

import pytest

import passive_operations_scorecard as scorecard


def source() -> dict:
    return scorecard.load(scorecard.SOURCE)


def month(period: str, **overrides) -> dict:
    value = {
        "period": period,
        "paid_customers": 10,
        "annual_customers": 8,
        "monthly_customers": 2,
        "qualified_organizations_cumulative": 10,
        "annualized_recurring_revenue_usd": 49900,
        "churned_customers": 0,
        "refunds": 0,
        "support_minutes": 60,
        "owner_minutes": 60,
        "monthly_activations": 2,
        "early_monthly_cancellations": 0,
        "renewal_opportunities": 4,
        "renewals": 3,
    }
    value.update(overrides)
    return value


def prepare(tmp_path: Path, value: dict, *, running: bool = False) -> dict:
    clock = scorecard.load(scorecard.ROOT / "release/guard-market-clock-v1.json")
    if running:
        clock["status"] = "running"
        clock["started_at"] = "2026-01-01T00:00:00Z"
        clock["six_month_stop_deadline"] = "2026-07-01T00:00:00Z"
    path = tmp_path / "release" / "guard-market-clock-v1.json"
    path.parent.mkdir(parents=True)
    raw = scorecard.canonical(clock)
    path.write_bytes(raw)
    value["market_clock"]["sha256"] = hashlib.sha256(raw).hexdigest()
    return scorecard.derive(value, root=tmp_path)


def test_checked_in_scorecard_is_local_closed_and_generated() -> None:
    result = scorecard.derive(source())
    assert result["recommendation"] == "continue"
    assert result["checkout_mutation_authorized"] is False
    assert scorecard.OUTPUT.read_bytes() == scorecard.canonical(result)


def test_critical_incident_and_operating_limits_freeze_sales(tmp_path: Path) -> None:
    value = source()
    value["critical_incidents"]["official_verifier_rejection"] = True
    result = prepare(tmp_path, value)
    assert result["recommendation"] == "freeze_sales"
    assert "critical:official_verifier_rejection" in result["freeze_reasons"]

    value = source()
    value["evaluated_at"] = "2026-08-31T12:00:00Z"
    value["months"] = [
        month(
            "2026-07",
            annual_customers=6,
            monthly_customers=4,
            support_minutes=130,
        ),
        month(
            "2026-08",
            annual_customers=6,
            monthly_customers=4,
            support_minutes=130,
        ),
    ]
    result = prepare(tmp_path / "limits", value)
    assert result["recommendation"] == "freeze_sales"
    assert any("support_over_12" in item for item in result["freeze_reasons"])
    assert any("annual_share_below_70" in item for item in result["warnings"])


def test_early_monthly_churn_freezes_expansion_not_sales(tmp_path: Path) -> None:
    value = source()
    value["evaluated_at"] = "2026-12-31T12:00:00Z"
    value["months"] = [
        month(
            "2026-07",
            monthly_activations=3,
            early_monthly_cancellations=1,
        )
    ]
    result = prepare(tmp_path, value)
    assert result["recommendation"] == "continue"
    assert result["expansion_frozen"] is True
    assert any("early_monthly_churn" in item for item in result["expansion_reasons"])


def test_annual_share_is_warning_and_renewal_waits_for_five_outcomes(
    tmp_path: Path,
) -> None:
    value = source()
    value["evaluated_at"] = "2026-08-31T12:00:00Z"
    value["months"] = [
        month(
            "2026-07",
            annual_customers=6,
            monthly_customers=4,
            renewal_opportunities=4,
            renewals=0,
        )
    ]
    result = prepare(tmp_path, value)
    assert result["recommendation"] == "continue"
    assert any("annual_share_below_70" in item for item in result["warnings"])
    assert not any("renewal_below_75" in item for item in result["warnings"])

    value["months"][0]["renewal_opportunities"] = 5
    result = prepare(tmp_path / "renewal", value)
    assert any("renewal_below_75" in item for item in result["warnings"])


def test_six_month_and_month_twelve_stop_rules(tmp_path: Path) -> None:
    value = source()
    value["evaluated_at"] = "2026-07-18T12:00:00Z"
    value["months"] = [
        month(
            "2026-07",
            paid_customers=2,
            annual_customers=2,
            monthly_customers=0,
            qualified_organizations_cumulative=20,
        )
    ]
    result = prepare(tmp_path / "six", value, running=True)
    assert result["recommendation"] == "stop_commercial"
    assert any("six_month" in item for item in result["stop_reasons"])

    value["months"][0]["qualified_organizations_cumulative"] = 19
    value["months"][0]["paid_customers"] = 10
    value["months"][0]["annual_customers"] = 8
    value["months"][0]["monthly_customers"] = 2
    result = prepare(tmp_path / "under20", value, running=True)
    assert result["recommendation"] == "stop_commercial"
    assert any("fewer_than_20" in item for item in result["stop_reasons"])

    value = source()
    value["evaluated_at"] = "2026-07-18T12:00:00Z"
    value["months"] = []
    result = prepare(tmp_path / "no-records", value, running=True)
    assert result["recommendation"] == "stop_commercial"
    assert "six_month_scorecard_coverage_missing" in result["stop_reasons"]
    assert any("fewer_than_20" in item for item in result["stop_reasons"])

    value["months"] = [
        month(
            "2026-05",
            paid_customers=3,
            annual_customers=3,
            monthly_customers=0,
            qualified_organizations_cumulative=20,
        )
    ]
    result = prepare(tmp_path / "stale", value, running=True)
    assert result["recommendation"] == "stop_commercial"
    assert "six_month_scorecard_coverage_missing" in result["stop_reasons"]

    value = source()
    value["evaluated_at"] = "2026-12-31T12:00:00Z"
    value["months"] = [
        month(f"2026-{index:02d}")
        for index in range(1, 13)
    ]
    value["months"][-1]["annualized_recurring_revenue_usd"] = 24949
    result = prepare(tmp_path / "twelve", value)
    assert result["recommendation"] == "stop_commercial"
    assert any("month_12" in item for item in result["stop_reasons"])


def test_qualified_organization_count_is_distinct_and_cumulative(
    tmp_path: Path,
) -> None:
    value = source()
    value["evaluated_at"] = "2026-08-31T12:00:00Z"
    value["months"] = [
        month("2026-07", qualified_organizations_cumulative=20),
        month("2026-08", qualified_organizations_cumulative=19),
    ]
    with pytest.raises(
        scorecard.ScorecardError,
        match="qualified organization count must be cumulative",
    ):
        prepare(tmp_path, value)


def test_monthly_coverage_cannot_skip_periods(tmp_path: Path) -> None:
    value = source()
    value["evaluated_at"] = "2026-09-18T12:00:00Z"
    value["months"] = [
        month("2026-07"),
        month("2026-09"),
    ]
    with pytest.raises(scorecard.ScorecardError, match="consecutive coverage"):
        prepare(tmp_path, value)


def test_running_market_requires_completed_month_coverage_but_not_current_month(
    tmp_path: Path,
) -> None:
    value = source()
    value["evaluated_at"] = "2026-04-18T12:00:00Z"
    value["months"] = [
        month("2026-01"),
        month("2026-02"),
    ]
    result = prepare(tmp_path / "missing", value, running=True)
    assert result["recommendation"] == "freeze_sales"
    assert "operations_monthly_coverage_missing" in result["freeze_reasons"]

    value["months"].append(month("2026-03"))
    result = prepare(tmp_path / "complete", value, running=True)
    assert "operations_monthly_coverage_missing" not in result["freeze_reasons"]
    assert result["recommendation"] == "continue"

    value["months"].append(month("2026-04"))
    result = prepare(tmp_path / "current-optional", value, running=True)
    assert result["recommendation"] == "continue"


def test_passive_input_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    path.write_text(
        '{"schema_version":1,"schema_version":1}', encoding="utf-8"
    )
    with pytest.raises(scorecard.ScorecardError, match="duplicate JSON object key"):
        scorecard.load(path)


def test_referenced_market_clock_rejects_duplicate_json_keys(
    tmp_path: Path,
) -> None:
    value = source()
    clock = scorecard.load(scorecard.ROOT / "release/guard-market-clock-v1.json")
    raw = scorecard.canonical(clock).replace(
        b'  "status": "not_started"\n',
        b'  "status": "not_started",\n  "status": "not_started"\n',
        1,
    )
    assert raw.count(b'"status": "not_started"') == 2
    path = tmp_path / "release" / "guard-market-clock-v1.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    value["market_clock"]["sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(scorecard.ScorecardError, match="duplicate JSON object key"):
        scorecard.derive(value, root=tmp_path)
