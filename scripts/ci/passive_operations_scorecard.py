#!/usr/bin/env python3
"""Evaluate a small local passive-operations ledger without telemetry or CRM."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

import strict_json


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "release" / "passive-operations-input-v1.json"
OUTPUT = ROOT / "release" / "passive-operations-scorecard-v1.json"
PERIOD_RE = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])$")
MONTH_FIELDS = {
    "period",
    "paid_customers",
    "annual_customers",
    "monthly_customers",
    "qualified_organizations_cumulative",
    "annualized_recurring_revenue_usd",
    "churned_customers",
    "refunds",
    "support_minutes",
    "owner_minutes",
    "monthly_activations",
    "early_monthly_cancellations",
    "renewal_opportunities",
    "renewals",
}
CRITICAL_FIELDS = {
    "official_verifier_rejection",
    "proof_equality_failure",
    "release_identity_mismatch",
    "critical_or_high_security_finding",
    "customer_proof_data_received",
    "activated_release_disabled",
    "artifact_signature_failure",
    "provenance_failure",
    "offline_runtime_failure",
    "checkpoint_recovery_failure",
    "legal_semantic_failure",
    "merchant_semantic_failure",
}


class ScorecardError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ScorecardError(f"{label} fields differ from the locked contract")
    return value


def nonnegative(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ScorecardError(f"{label} must be a non-negative integer")
    return value


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ScorecardError("evaluated_at must be UTC")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def period_index(value: datetime) -> int:
    return value.year * 12 + value.month - 1


def period_name(index: int) -> str:
    year, month = divmod(index, 12)
    return f"{year:04d}-{month + 1:02d}"


def load(path: Path) -> dict[str, Any]:
    try:
        value = strict_json.load(path)
    except (OSError, ValueError) as error:
        raise ScorecardError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise ScorecardError(f"{path} must contain an object")
    return value


def derive(source: dict[str, Any], *, root: Path = ROOT) -> dict[str, Any]:
    exact(
        source,
        {
            "schema_version",
            "document_type",
            "evaluated_at",
            "market_clock",
            "months",
            "critical_incidents",
        },
        "PassiveOperationsInputV1",
    )
    if (
        source["schema_version"] != 1
        or source["document_type"] != "PassiveOperationsInputV1"
    ):
        raise ScorecardError("operations input schema/type is invalid")
    evaluated_at = timestamp(source["evaluated_at"])
    reference = exact(source["market_clock"], {"path", "sha256"}, "market_clock")
    if reference["path"] != "release/guard-market-clock-v1.json":
        raise ScorecardError("market clock path differs")
    clock_path = root / reference["path"]
    raw_clock = clock_path.read_bytes()
    if hashlib.sha256(raw_clock).hexdigest() != reference["sha256"]:
        raise ScorecardError("market clock digest differs")
    try:
        market = strict_json.loads(raw_clock)
    except ValueError as error:
        raise ScorecardError(f"market clock is not strict JSON: {error}") from error
    if not isinstance(market, dict):
        raise ScorecardError("market clock must contain an object")
    if market.get("document_type") != "GuardMarketClockV1":
        raise ScorecardError("market clock type differs")

    critical = exact(
        source["critical_incidents"], CRITICAL_FIELDS, "critical_incidents"
    )
    if any(not isinstance(value, bool) for value in critical.values()):
        raise ScorecardError("critical incident values must be booleans")
    critical_reasons = sorted(name for name, value in critical.items() if value)

    if not isinstance(source["months"], list) or len(source["months"]) > 24:
        raise ScorecardError("months must contain at most 24 records")
    records = []
    prior_period = ""
    prior_period_index: int | None = None
    freeze_reasons = [f"critical:{name}" for name in critical_reasons]
    high_support_run = 0
    warnings: list[str] = []
    expansion_reasons: list[str] = []
    renewal_opportunities_total = 0
    renewals_total = 0
    qualified_organizations_prior = 0
    for value in source["months"]:
        month = exact(value, MONTH_FIELDS, "monthly record")
        period = month["period"]
        if not isinstance(period, str) or not PERIOD_RE.fullmatch(period) or period <= prior_period:
            raise ScorecardError("monthly periods must be unique and increasing")
        year, month_number = (int(part) for part in period.split("-"))
        current_period_index = year * 12 + month_number - 1
        if (
            prior_period_index is not None
            and current_period_index != prior_period_index + 1
        ):
            raise ScorecardError("monthly periods must provide consecutive coverage")
        if period > evaluated_at.strftime("%Y-%m"):
            raise ScorecardError("monthly records cannot be future-dated")
        prior_period = period
        prior_period_index = current_period_index
        for field in MONTH_FIELDS - {"period"}:
            nonnegative(month[field], f"{period}.{field}")
        if month["annual_customers"] + month["monthly_customers"] != month["paid_customers"]:
            raise ScorecardError("paid cadence counts must equal paid customers")
        if month["renewals"] > month["renewal_opportunities"]:
            raise ScorecardError("renewals cannot exceed opportunities")
        if month["early_monthly_cancellations"] > month["monthly_activations"]:
            raise ScorecardError("early cancellations cannot exceed monthly activations")
        if (
            month["qualified_organizations_cumulative"]
            < qualified_organizations_prior
        ):
            raise ScorecardError(
                "qualified organization count must be cumulative and nondecreasing"
            )
        qualified_organizations_prior = month[
            "qualified_organizations_cumulative"
        ]

        paid = month["paid_customers"]
        annual_share = month["annual_customers"] / paid if paid else None
        support_per_customer = month["support_minutes"] / paid if paid else 0.0
        support_band = (
            "healthy"
            if support_per_customer <= 6
            else "warning"
            if support_per_customer <= 12
            else "over_limit"
        )
        renewal_rate = (
            month["renewals"] / month["renewal_opportunities"]
            if month["renewal_opportunities"]
            else None
        )
        early_churn = (
            month["early_monthly_cancellations"] / month["monthly_activations"]
            if month["monthly_activations"]
            else 0.0
        )
        high_support_run = high_support_run + 1 if support_per_customer > 12 else 0
        renewal_opportunities_total += month["renewal_opportunities"]
        renewals_total += month["renewals"]
        if month["owner_minutes"] > 120:
            freeze_reasons.append(f"{period}:owner_minutes_over_120")
        if high_support_run >= 2:
            freeze_reasons.append(f"{period}:support_over_12_two_consecutive_months")
        if annual_share is not None and annual_share < 0.70:
            warnings.append(f"{period}:annual_share_below_70_percent_target")
        if (
            renewal_opportunities_total >= 5
            and renewals_total / renewal_opportunities_total < 0.75
        ):
            warnings.append(f"{period}:renewal_below_75_percent_target")
        if early_churn > 0.30:
            expansion_reasons.append(
                f"{period}:early_monthly_churn_over_30_percent"
            )
        records.append(
            {
                **month,
                "annual_share": annual_share,
                "support_minutes_per_customer": support_per_customer,
                "support_band": support_band,
                "renewal_rate": renewal_rate,
                "early_monthly_churn_rate": early_churn,
            }
        )

    stop_reasons = []
    latest = records[-1] if records else None
    if market.get("status") == "running":
        started_at = timestamp(market["started_at"])
        first_required = period_index(started_at)
        last_completed = period_index(evaluated_at) - 1
        if first_required <= last_completed:
            observed = {record["period"] for record in records}
            required = {
                period_name(index)
                for index in range(first_required, last_completed + 1)
            }
            if not required.issubset(observed):
                freeze_reasons.append("operations_monthly_coverage_missing")
    if len(records) >= 12 and latest is not None:
        annual_equivalent = latest["annualized_recurring_revenue_usd"] / 4990
        if annual_equivalent < 6:
            stop_reasons.append("month_12_below_six_annual_equivalent_customers")
    if market.get("status") == "running":
        deadline_value = market.get("six_month_stop_deadline")
        if deadline_value and evaluated_at >= timestamp(deadline_value):
            last_completed_period = period_name(period_index(evaluated_at) - 1)
            qualified = (
                latest["qualified_organizations_cumulative"] if latest else 0
            )
            paid = latest["paid_customers"] if latest else 0
            if (
                latest is None
                or latest["period"] < last_completed_period
            ):
                stop_reasons.append("six_month_scorecard_coverage_missing")
            if qualified < 20:
                stop_reasons.append(
                    "six_month_fewer_than_20_qualified_organizations"
                )
            elif paid < 3:
                stop_reasons.append(
                    "six_month_20_qualified_organizations_fewer_than_three_payers"
                )

    recommendation = (
        "stop_commercial"
        if stop_reasons
        else "freeze_sales"
        if freeze_reasons
        else "continue"
    )
    return {
        "schema_version": 1,
        "document_type": "PassiveOperationsScorecardV1",
        "generated_from": "release/passive-operations-input-v1.json",
        "source_sha256": hashlib.sha256(canonical(source)).hexdigest(),
        "evaluated_at": source["evaluated_at"],
        "market_clock_status": market["status"],
        "recommendation": recommendation,
        "freeze_reasons": sorted(set(freeze_reasons)),
        "stop_reasons": sorted(set(stop_reasons)),
        "warnings": sorted(set(warnings)),
        "expansion_frozen": bool(expansion_reasons),
        "expansion_reasons": sorted(set(expansion_reasons)),
        "months": records,
        "thresholds": {
            "owner_minutes_per_month_max": 120,
            "support_target_minutes_per_customer": 6,
            "support_warning_max_minutes_per_customer": 12,
            "annual_customer_share_min": 0.70,
            "early_monthly_churn_max": 0.30,
            "renewal_rate_min": 0.75,
            "month_12_annual_equivalent_min": 6,
            "six_month_qualified_organizations": 20,
            "six_month_paying_organizations_min": 3,
        },
        "checkout_mutation_authorized": False,
        "note": (
            "This local scorecard recommends action only. Checkout state changes "
            "require separately signed, reviewed Guard launch evidence."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    if args.check and args.write:
        parser.error("--check and --write are mutually exclusive")
    try:
        output = derive(load(args.source), root=args.root.resolve())
        if args.check or not args.write:
            if OUTPUT.read_bytes() != canonical(output):
                raise ScorecardError("passive operations scorecard is not generated")
        if args.write:
            temporary = OUTPUT.with_suffix(".json.tmp")
            temporary.write_bytes(canonical(output))
            os.replace(temporary, OUTPUT)
    except (OSError, ScorecardError) as error:
        print(f"passive operations scorecard: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"recommendation": output["recommendation"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
