#!/usr/bin/env python3
"""Validate TinyZKP's evidence-based monthly operating scorecard."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


MAX_BYTES = 1024 * 1024
ALLOWED_STAGES = {
    "benchmark_committed",
    "benchmark_reproduced",
    "evaluation_qualified",
    "evaluation_signed",
    "evaluation_invoiced",
    "evaluation_deposit_paid",
    "annual_signed",
}
ZERO_VALUE_KEYS = {"traffic", "directory_listings", "free_accounts", "unsent_leads"}


def margin(revenue: float, cogs: float) -> float | None:
    return None if revenue <= 0 else (revenue - cogs) / revenue


def validate(payload: dict[str, object]) -> list[str]:
    failures: list[str] = []
    if payload.get("schema_version") != 2:
        failures.append("schema_version must be 2")
    if not isinstance(payload.get("period"), str) or not re.fullmatch(r"\d{4}-\d{2}", payload["period"]):
        failures.append("period must use YYYY-MM")
    forbidden = sorted(ZERO_VALUE_KEYS & payload.keys())
    if forbidden:
        failures.append("zero-value vanity metrics must not appear: " + ", ".join(forbidden))

    numeric_fields = (
        "contracted_arr_usd",
        "cash_collected_usd",
        "evaluation_revenue_usd",
        "evaluation_invoiced_usd",
        "evaluation_paid_usd",
        "recurring_software_revenue_usd",
        "recurring_software_cogs_usd",
        "hosted_revenue_usd",
        "hosted_cogs_usd",
        "buyer_calls_completed",
        "inbound_applications",
        "qualified_opportunities",
        "signed_evaluations",
        "reproducible_bottlenecks",
        "benchmark_reports_received",
        "evaluations_sold",
        "annual_conversions",
        "runway_months",
    )
    for field in numeric_fields:
        value = payload.get(field)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            failures.append(f"{field} must be a non-negative number")
    ordered_counts = (
        payload.get("inbound_applications"),
        payload.get("qualified_opportunities"),
        payload.get("signed_evaluations"),
        payload.get("evaluations_sold"),
    )
    if all(
        isinstance(value, (int, float)) and not isinstance(value, bool)
        for value in ordered_counts
    ) and not (
        ordered_counts[0] >= ordered_counts[1] >= ordered_counts[2]
        == ordered_counts[3]
    ):
        failures.append(
            "applications, qualified opportunities, and signed evaluations are inconsistent"
        )
    invoiced = payload.get("evaluation_invoiced_usd")
    paid = payload.get("evaluation_paid_usd")
    revenue = payload.get("evaluation_revenue_usd")
    cash = payload.get("cash_collected_usd")
    if all(
        isinstance(value, (int, float)) and not isinstance(value, bool)
        for value in (invoiced, paid, revenue, cash)
    ):
        if paid > invoiced:
            failures.append("evaluation paid amount cannot exceed invoiced amount")
        if revenue != paid:
            failures.append("evaluation revenue must equal paid evaluation invoices")
        if paid > cash:
            failures.append("evaluation paid amount cannot exceed total cash collected")

    customers = payload.get("customers")
    if not isinstance(customers, list):
        failures.append("customers must be an array")
        customers = []
    customer_arr = 0.0
    seen_customers: set[str] = set()
    for customer in customers:
        if not isinstance(customer, dict):
            failures.append("customer records must be objects")
            continue
        customer_id = customer.get("customer_id")
        arr = customer.get("arr_usd")
        support = customer.get("support_hours_quarter_to_date")
        if not isinstance(customer_id, str) or not customer_id or customer_id in seen_customers:
            failures.append("customer_id must be present and unique")
        else:
            seen_customers.add(customer_id)
        if not isinstance(arr, (int, float)) or isinstance(arr, bool) or arr < 0:
            failures.append(f"customer {customer_id!r} arr_usd is invalid")
        else:
            customer_arr += float(arr)
        if not isinstance(support, (int, float)) or isinstance(support, bool) or support < 0:
            failures.append(f"customer {customer_id!r} support hours are invalid")
        elif support > 10:
            failures.append(f"customer {customer_id!r} exceeded ten included support hours")
    contracted = payload.get("contracted_arr_usd")
    if isinstance(contracted, (int, float)) and not isinstance(contracted, bool):
        if abs(customer_arr - float(contracted)) > 0.01:
            failures.append("contracted_arr_usd must equal the customer ARR ledger")

    pipeline = payload.get("pipeline")
    if not isinstance(pipeline, list):
        failures.append("pipeline must be an array")
        pipeline = []
    for item in pipeline:
        if not isinstance(item, dict):
            failures.append("pipeline records must be objects")
            continue
        stage = item.get("stage")
        evidence = item.get("evidence")
        if stage not in ALLOWED_STAGES:
            failures.append(f"unsupported pipeline stage: {stage!r}")
        if not isinstance(evidence, str) or not evidence.strip():
            failures.append("every pipeline record requires evidence")
        amount = item.get("contracted_value_usd", 0)
        if not isinstance(amount, (int, float)) or isinstance(amount, bool) or amount < 0:
            failures.append("pipeline contracted_value_usd is invalid")
        elif stage not in {
            "evaluation_signed",
            "evaluation_invoiced",
            "evaluation_deposit_paid",
            "annual_signed",
        } and amount != 0:
            failures.append("unsigned pipeline stages must have zero contracted value")

    software_margin = margin(
        float(payload.get("recurring_software_revenue_usd", 0) or 0),
        float(payload.get("recurring_software_cogs_usd", 0) or 0),
    )
    if software_margin is not None and software_margin < 0.90:
        failures.append("recurring software gross margin is below 90%")
    hosted_margin = margin(
        float(payload.get("hosted_revenue_usd", 0) or 0),
        float(payload.get("hosted_cogs_usd", 0) or 0),
    )
    if hosted_margin is not None and hosted_margin < 0.80:
        failures.append("hosted gross margin is below 80%")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scorecard", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.scorecard.stat().st_size > MAX_BYTES:
            raise ValueError("scorecard exceeds 1 MiB")
        payload = json.loads(args.scorecard.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("scorecard must contain a JSON object")
        failures = validate(payload)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        failures = [str(exc)]
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1
    print("PASS  monthly scorecard contains evidence-backed, margin-safe metrics")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
