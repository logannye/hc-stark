#!/usr/bin/env python3
"""Summarize TinyZKP GTM attribution, activation, and paid-plan signals."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Iterable

import tenant_store


ROOT = Path(__file__).resolve().parents[1]
TENANT_DB_PATH = os.environ.get("HC_TENANT_STORE_PATH", tenant_store.DB_PATH)
USAGE_DB_PATH = os.environ.get("HC_USAGE_DB_PATH", "/opt/hc-stark/data/usage.sqlite")
PRICING_PATH = ROOT / "site" / "pricing.json"
FREE_PLANS = {"free"}


@dataclass
class TenantUsage:
    total_proofs: int = 0
    monthly_proofs: int = 0
    trace_length_sum: int = 0
    first_completed_at_ms: int = 0
    last_completed_at_ms: int = 0
    trace_lengths: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class PricingModel:
    base_monthly_by_plan: dict[str, int]
    proof_rate_bands: list[dict]
    compute_price_per_million: Decimal
    compute_minimum_cents: int


@dataclass
class SourceSummary:
    source: str
    medium: str
    platform: str
    accounts: int = 0
    active_accounts: int = 0
    monthly_active_accounts: int = 0
    activated_accounts: int = 0
    paid_accounts: int = 0
    free_accounts: int = 0
    total_proofs: int = 0
    monthly_proofs: int = 0
    trace_length_sum: int = 0
    paid_proofs: int = 0
    compute_trace_steps: int = 0
    estimated_base_mrr: int = 0
    estimated_usage_revenue_cents: int = 0
    first_proof_accounts: int = 0
    time_to_first_proof_sum_ms: int = 0
    first_signup_ms: int = 0
    last_signup_ms: int = 0

    @property
    def paid_rate(self) -> float:
        return self.paid_accounts / self.accounts if self.accounts else 0.0

    @property
    def activation_rate(self) -> float:
        return self.activated_accounts / self.accounts if self.accounts else 0.0

    @property
    def estimated_usage_revenue(self) -> float:
        return self.estimated_usage_revenue_cents / 100

    @property
    def avg_time_to_first_proof_hours(self) -> float:
        if not self.first_proof_accounts:
            return 0.0
        return self.time_to_first_proof_sum_ms / self.first_proof_accounts / (60 * 60 * 1000)


def now_ms() -> int:
    return int(time.time() * 1000)


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def load_pricing_model(path: Path = PRICING_PATH) -> PricingModel:
    with path.open(encoding="utf-8") as handle:
        pricing = json.load(handle)
    if isinstance(pricing, dict) and pricing.get("service_status") == "backend_recovery":
        return PricingModel({}, [], Decimal("0"), 0)
    plans = (pricing.get("plans") or []) if isinstance(pricing, dict) else []
    base_monthly_by_plan = {
        str(plan.get("id", "")).lower(): int(plan.get("base_monthly") or 0)
        for plan in plans
        if isinstance(plan, dict)
    }
    compute = pricing.get("compute") if isinstance(pricing.get("compute"), dict) else {}
    return PricingModel(
        base_monthly_by_plan=base_monthly_by_plan,
        proof_rate_bands=[
            band for band in pricing.get("proof_rate_bands", [])
            if isinstance(band, dict)
        ],
        compute_price_per_million=Decimal(str(compute.get("price_per_million_trace_steps", "0.50"))),
        compute_minimum_cents=int((Decimal(str(compute.get("minimum_per_proof", "0.05"))) * 100).to_integral_value(ROUND_HALF_UP)),
    )


def _dollars_to_cents(value: object) -> int:
    return int((Decimal(str(value)) * 100).to_integral_value(ROUND_HALF_UP))


def _rate_for_trace(plan: str, trace_length: int, pricing: PricingModel) -> int:
    if plan == "compute":
        cents = (Decimal(trace_length) * pricing.compute_price_per_million * Decimal(100) / Decimal(1_000_000))
        return max(pricing.compute_minimum_cents, int(cents.to_integral_value(ROUND_HALF_UP)))

    for band in pricing.proof_rate_bands:
        steps = band.get("trace_steps") if isinstance(band.get("trace_steps"), dict) else {}
        min_steps = int(steps.get("min") or 0)
        max_exclusive = steps.get("max_exclusive")
        if trace_length < min_steps:
            continue
        if max_exclusive is not None and trace_length >= int(max_exclusive):
            continue
        if plan in band:
            return _dollars_to_cents(band[plan])
    return 0


def estimate_usage_revenue_cents(plan: str, usage: TenantUsage, pricing: PricingModel) -> int:
    if plan in FREE_PLANS:
        return 0
    return sum(_rate_for_trace(plan, trace_length, pricing) for trace_length in usage.trace_lengths)


def load_usage_by_tenant(path: str, *, current_ms: int | None = None) -> dict[str, TenantUsage]:
    current_ms = current_ms if current_ms is not None else now_ms()
    month_start_ms = current_ms - 30 * 24 * 60 * 60 * 1000
    if not path or not Path(path).exists():
        return {}

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        if not _table_exists(conn, "usage_log"):
            return {}
        rows = conn.execute(
            """SELECT tenant_id, trace_length, completed_at_ms
               FROM usage_log
               ORDER BY tenant_id, completed_at_ms""",
        ).fetchall()
    finally:
        conn.close()

    usage_by_tenant: dict[str, TenantUsage] = {}
    for row in rows:
        tenant_id = row["tenant_id"]
        trace_length = int(row["trace_length"] or 0)
        completed_at_ms = int(row["completed_at_ms"] or 0)
        usage = usage_by_tenant.setdefault(tenant_id, TenantUsage())
        usage.total_proofs += 1
        if completed_at_ms >= month_start_ms:
            usage.monthly_proofs += 1
        usage.trace_length_sum += trace_length
        usage.trace_lengths.append(trace_length)
        if completed_at_ms and (not usage.first_completed_at_ms or completed_at_ms < usage.first_completed_at_ms):
            usage.first_completed_at_ms = completed_at_ms
        if completed_at_ms > usage.last_completed_at_ms:
            usage.last_completed_at_ms = completed_at_ms
    return usage_by_tenant


def load_tenants(path: str) -> list[sqlite3.Row]:
    if not path or not Path(path).exists():
        return []
    conn = tenant_store.open_db(path)
    try:
        return tenant_store.list_tenants(conn)
    finally:
        conn.close()


def _source(row: sqlite3.Row) -> tuple[str, str, str]:
    source = row["attribution_source"] or ""
    medium = row["attribution_medium"] or ""
    platform = row["attribution_platform"] or ""
    if not source:
        if row["attribution_referrer_host"]:
            source = f"referrer:{row['attribution_referrer_host']}"
        elif row["attribution_landing_path"]:
            source = f"landing:{row['attribution_landing_path']}"
        else:
            source = "unknown"
    return source, medium or "-", platform or "-"


def summarize(
    tenants: Iterable[sqlite3.Row],
    usage_by_tenant: dict[str, TenantUsage],
    pricing: PricingModel | None = None,
) -> list[SourceSummary]:
    pricing = pricing if pricing is not None else load_pricing_model()
    groups: dict[tuple[str, str, str], SourceSummary] = {}
    for tenant in tenants:
        source, medium, platform = _source(tenant)
        key = (source, medium, platform)
        group = groups.setdefault(key, SourceSummary(source=source, medium=medium, platform=platform))
        usage = usage_by_tenant.get(tenant["tenant_id"], TenantUsage())
        plan = str(tenant["plan"] or "").lower()
        created_at_ms = int(tenant["created_at_ms"] or 0)
        active = tenant["status"] == "active"

        group.accounts += 1
        if active:
            group.active_accounts += 1
        if usage.monthly_proofs > 0:
            group.monthly_active_accounts += 1
        if usage.total_proofs > 0:
            group.activated_accounts += 1
        if plan in FREE_PLANS:
            group.free_accounts += 1
        else:
            group.paid_accounts += 1
            group.paid_proofs += usage.total_proofs
            group.estimated_usage_revenue_cents += estimate_usage_revenue_cents(plan, usage, pricing)
            if active:
                group.estimated_base_mrr += pricing.base_monthly_by_plan.get(plan, 0)
        if plan == "compute":
            group.compute_trace_steps += usage.trace_length_sum
        group.total_proofs += usage.total_proofs
        group.monthly_proofs += usage.monthly_proofs
        group.trace_length_sum += usage.trace_length_sum
        if usage.first_completed_at_ms and created_at_ms and usage.first_completed_at_ms >= created_at_ms:
            group.first_proof_accounts += 1
            group.time_to_first_proof_sum_ms += usage.first_completed_at_ms - created_at_ms
        if created_at_ms and (not group.first_signup_ms or created_at_ms < group.first_signup_ms):
            group.first_signup_ms = created_at_ms
        if created_at_ms > group.last_signup_ms:
            group.last_signup_ms = created_at_ms

    return sorted(
        groups.values(),
        key=lambda group: (group.paid_accounts, group.activated_accounts, group.accounts, group.total_proofs),
        reverse=True,
    )


def _fmt_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _fmt_date(ms: int) -> str:
    if not ms:
        return "-"
    return time.strftime("%Y-%m-%d", time.gmtime(ms / 1000))


def _fmt_money_cents(cents: int) -> str:
    return f"${cents / 100:.2f}"


def _fmt_hours(value: float) -> str:
    return "-" if value <= 0 else f"{value:.2f}h"


def report_json(groups: list[SourceSummary]) -> str:
    return json.dumps(
        [
            {
                **asdict(group),
                "activation_rate": round(group.activation_rate, 4),
                "paid_rate": round(group.paid_rate, 4),
                "estimated_usage_revenue": round(group.estimated_usage_revenue, 2),
                "avg_time_to_first_proof_hours": round(group.avg_time_to_first_proof_hours, 4),
            }
            for group in groups
        ],
        indent=2,
    )


def report_markdown(groups: list[SourceSummary], *, generated_ms: int | None = None) -> str:
    generated_ms = generated_ms if generated_ms is not None else now_ms()
    total_accounts = sum(group.accounts for group in groups)
    total_paid = sum(group.paid_accounts for group in groups)
    total_activated = sum(group.activated_accounts for group in groups)
    total_monthly_active = sum(group.monthly_active_accounts for group in groups)
    total_proofs = sum(group.total_proofs for group in groups)
    total_paid_proofs = sum(group.paid_proofs for group in groups)
    total_base_mrr = sum(group.estimated_base_mrr for group in groups)
    total_usage_revenue_cents = sum(group.estimated_usage_revenue_cents for group in groups)
    total_compute_trace_steps = sum(group.compute_trace_steps for group in groups)
    rows = [
        "# TinyZKP Legacy Account Activity Report",
        "",
        "> Historical account/proof activity only. This is not contracted ARR, cash, or pipeline value during backend recovery.",
        "",
        f"Generated: {_fmt_date(generated_ms)} UTC",
        "",
        f"- Accounts: {total_accounts}",
        f"- Activated accounts: {total_activated}",
        f"- 30d active accounts: {total_monthly_active}",
        f"- Paid accounts: {total_paid}",
        f"- Total proofs: {total_proofs}",
        f"- Paid proofs: {total_paid_proofs}",
        f"- Estimated active base MRR: ${total_base_mrr}",
        f"- Estimated usage revenue: {_fmt_money_cents(total_usage_revenue_cents)}",
        f"- Compute trace steps: {total_compute_trace_steps}",
        "",
        "| Source | Medium | Platform | Accounts | Activated | 30d active | Paid | Activation | Paid rate | Base MRR | Usage rev | Paid proofs | Proofs | 30d proofs | Trace steps | Compute steps | Avg first proof | First signup | Last signup |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for group in groups:
        rows.append(
            "| "
            + " | ".join(
                [
                    group.source,
                    group.medium,
                    group.platform,
                    str(group.accounts),
                    str(group.activated_accounts),
                    str(group.monthly_active_accounts),
                    str(group.paid_accounts),
                    _fmt_pct(group.activation_rate),
                    _fmt_pct(group.paid_rate),
                    f"${group.estimated_base_mrr}",
                    _fmt_money_cents(group.estimated_usage_revenue_cents),
                    str(group.paid_proofs),
                    str(group.total_proofs),
                    str(group.monthly_proofs),
                    str(group.trace_length_sum),
                    str(group.compute_trace_steps),
                    _fmt_hours(group.avg_time_to_first_proof_hours),
                    _fmt_date(group.first_signup_ms),
                    _fmt_date(group.last_signup_ms),
                ]
            )
            + " |"
        )
    return "\n".join(rows) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-db", default=TENANT_DB_PATH, help="Path to tenant_store.sqlite")
    parser.add_argument("--usage-db", default=USAGE_DB_PATH, help="Path to usage.sqlite")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    args = parser.parse_args(argv)

    tenants = load_tenants(args.tenant_db)
    usage = load_usage_by_tenant(args.usage_db)
    groups = summarize(tenants, usage)
    if args.json:
        print(report_json(groups))
    else:
        print(report_markdown(groups), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
