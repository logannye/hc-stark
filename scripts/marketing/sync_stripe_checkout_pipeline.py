#!/usr/bin/env python3
"""Historical checkout-pipeline synchronizer; executable entry point retired.

The implementation remains in source control as recovery-era audit evidence.
It must not read payment-provider state or mutate the current Community/Guard
revenue-readiness pipeline.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BILLING_DIR = ROOT / "billing"
if str(BILLING_DIR) not in sys.path:
    sys.path.insert(0, str(BILLING_DIR))

import stripe_checkout_monitor  # noqa: E402


DEFAULT_EXECUTION_LEDGER = ROOT / "marketing" / "generated" / "gtm_execution_ledger.json"
DEFAULT_STATE = ROOT / "marketing" / "gtm_pipeline_state.json"
DEFAULT_JSON = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.json"
DEFAULT_CSV = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.csv"
DEFAULT_MD = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.md"
PILOT_TASK_ID = "revenue.pilot_checkout_launch"
STRIPE_DASHBOARD_URL = "https://dashboard.stripe.com/payments"
RETIREMENT_NOTICE = (
    "retired: the legacy checkout pipeline sync cannot update the current Guard "
    "revenue-readiness ledger; use the canonical launch-state and Lemon Squeezy "
    "commerce gates"
)


def _load_renderer():
    path = ROOT / "scripts" / "marketing" / "render_gtm_pipeline_ledger.py"
    spec = importlib.util.spec_from_file_location("render_gtm_pipeline_ledger_for_stripe_sync", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def today_iso() -> str:
    return date.today().isoformat()


def tomorrow_iso(today: str) -> str:
    return (date.fromisoformat(today) + timedelta(days=1)).isoformat()


def _currency_cents(cents_by_currency: dict[str, Any], currency: str = "usd") -> int:
    return int(cents_by_currency.get(currency, 0) or 0)


def _pilot_paid_revenue_cents(summary: dict[str, Any], currency: str = "usd") -> int:
    total = 0
    for group in summary.get("groups", []):
        if not isinstance(group, dict):
            continue
        if str(group.get("plan") or "") != stripe_checkout_monitor.PRODUCTION_PILOT_PLAN:
            continue
        total += _currency_cents(group.get("paid_amount_by_currency", {}) or {}, currency)
    return total


def _pilot_started_revenue_cents(summary: dict[str, Any], currency: str = "usd") -> int:
    total = 0
    for group in summary.get("groups", []):
        if not isinstance(group, dict):
            continue
        if str(group.get("plan") or "") != stripe_checkout_monitor.PRODUCTION_PILOT_PLAN:
            continue
        total += _currency_cents(group.get("amount_total_by_currency", {}) or {}, currency)
    return total


def _money(cents: int) -> str:
    return f"${cents / 100:,.2f}"


def _summary_note(summary: dict[str, Any], *, synced_at: str, pilot_paid_cents: int, pilot_started_cents: int) -> str:
    return (
        f"Stripe checkout sync {synced_at}: "
        f"lookback={summary.get('lookback_hours', 0):g}h, "
        f"sessions={summary.get('sessions', 0)}, "
        f"paid_sessions={summary.get('paid', 0)}, "
        f"paid_revenue={_money(_currency_cents(summary.get('paid_amount_by_currency', {}) or {}))}, "
        f"production_pilot_starts={summary.get('production_pilot_starts', 0)}, "
        f"production_pilot_paid={summary.get('production_pilot_paid', 0)}, "
        f"production_pilot_started_value={_money(pilot_started_cents)}, "
        f"production_pilot_paid_revenue={_money(pilot_paid_cents)}. "
        "No buyer PII, Stripe object IDs, or checkout URLs are stored in this ledger; inspect Stripe Dashboard for row-level payment evidence."
    )


def sync_state(
    state: dict[str, Any],
    summary: dict[str, Any],
    *,
    synced_at: str | None = None,
    dashboard_url: str = STRIPE_DASHBOARD_URL,
) -> tuple[dict[str, Any], dict[str, Any]]:
    synced_at = synced_at or today_iso()
    tasks = state.get("tasks")
    if not isinstance(tasks, dict) or PILOT_TASK_ID not in tasks:
        raise RuntimeError(f"{PILOT_TASK_ID} is missing from pipeline state")
    entry = dict(tasks[PILOT_TASK_ID])

    previous_revenue = int(entry.get("actual_revenue_cents") or 0)
    pilot_paid_cents = _pilot_paid_revenue_cents(summary)
    pilot_started_cents = _pilot_started_revenue_cents(summary)
    observed_pilot_paid = int(summary.get("production_pilot_paid", 0) or 0)
    new_revenue = max(previous_revenue, pilot_paid_cents)

    entry["last_action_at"] = synced_at
    entry["actual_revenue_cents"] = new_revenue
    entry["notes"] = _summary_note(
        summary,
        synced_at=synced_at,
        pilot_paid_cents=pilot_paid_cents,
        pilot_started_cents=pilot_started_cents,
    )
    if observed_pilot_paid > 0 or pilot_paid_cents > 0 or previous_revenue > 0:
        entry["stage"] = "won"
        entry["completed_at"] = entry.get("completed_at") or synced_at
        entry["evidence_url"] = dashboard_url
        entry["next_action_at"] = ""
        entry["outcome"] = entry.get("outcome") or "stripe_checkout_paid"
    else:
        if entry.get("stage") not in {"won", "lost", "disqualified"}:
            entry["stage"] = "live_monitoring"
        entry["completed_at"] = ""
        entry["evidence_url"] = entry.get("evidence_url") or "https://tinyzkp.com/api/create-pilot-checkout"
        entry["next_action_at"] = tomorrow_iso(synced_at)

    updated_state = dict(state)
    updated_tasks = dict(tasks)
    updated_tasks[PILOT_TASK_ID] = entry
    updated_state["tasks"] = updated_tasks
    updated_state["updated_at"] = synced_at
    return updated_state, entry


def summary_from_payload(payload: dict[str, Any], *, lookback_hours: float) -> dict[str, Any]:
    if "data" in payload and isinstance(payload.get("data"), list):
        summary = stripe_checkout_monitor.summarize_sessions(
            payload["data"],
            mode="file",
            lookback_hours=lookback_hours,
        )
        return stripe_checkout_monitor.summary_to_dict(summary)
    if "sessions" in payload and "groups" in payload:
        return payload
    raise RuntimeError("Stripe payload must be a checkout.sessions.list response or stripe_checkout_monitor summary JSON")


def render_outputs(
    *,
    execution_path: Path,
    state: dict[str, Any],
    json_output: Path,
    csv_output: Path,
    md_output: Path,
) -> None:
    renderer = _load_renderer()
    execution = renderer.load_json(execution_path)
    normalized_state = renderer.normalize_state(execution, state)
    payload = renderer.render_pipeline(execution, normalized_state)
    outputs = renderer.expected_outputs(payload)
    paths = {
        Path("json"): json_output,
        Path("csv"): csv_output,
        Path("md"): md_output,
    }
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    for key, content in outputs.items():
        paths[key].write_text(content, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stripe-bin", default="stripe", help="Stripe CLI executable path")
    parser.add_argument("--stripe-project-name", default="", help="Optional Stripe CLI project profile name")
    parser.add_argument(
        "--account-source",
        choices=("cli", "api"),
        default=os.environ.get(
            "TINYZKP_GROWTH_STRIPE_ACCOUNT_SOURCE",
            os.environ.get("TINYZKP_STRIPE_ACCOUNT_SOURCE", "cli"),
        ),
        help="Stripe checkout source: CLI profile or Stripe API key",
    )
    parser.add_argument(
        "--stripe-api-key-env",
        default=os.environ.get(
            "TINYZKP_GROWTH_STRIPE_API_KEY_ENV",
            os.environ.get("TINYZKP_STRIPE_API_KEY_ENV", "STRIPE_SECRET_KEY"),
        ),
        help="Environment variable containing the Stripe secret key for --account-source api",
    )
    parser.add_argument("--test", action="store_true", help="Use Stripe test mode instead of live mode")
    parser.add_argument("--limit", type=int, default=100, help="Checkout sessions per Stripe page")
    parser.add_argument("--max-pages", type=int, default=3, help="Maximum Stripe pages to read")
    parser.add_argument("--lookback-hours", type=float, default=168, help="Trailing checkout window for Stripe summary")
    parser.add_argument("--from-json", type=Path, help="Read Stripe checkout.sessions.list or monitor summary JSON from disk")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--execution-ledger", type=Path, default=DEFAULT_EXECUTION_LEDGER)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--csv-output", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--md-output", type=Path, default=DEFAULT_MD)
    parser.add_argument("--dashboard-url", default=STRIPE_DASHBOARD_URL, help="No-PII dashboard URL used as paid revenue evidence")
    parser.add_argument("--synced-at", help="Override sync date; mainly for deterministic tests")
    parser.add_argument(
        "--expected-stripe-display-name",
        default=os.environ.get("TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME", "LN Holdings"),
        help="Required substring in the active Stripe account display_name",
    )
    parser.add_argument("--skip-account-check", action="store_true", help="Skip Stripe account display_name validation")
    parser.add_argument("--account-check-timeout", type=int, default=30, help="Stripe account-context timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Print the updated pilot state entry without writing files")
    parser.add_argument("--json", action="store_true", help="Print machine-readable sync result")
    return parser


def main(argv: list[str]) -> int:
    # Fail before argument parsing, file reads, account checks, network access,
    # or writes. Historical helpers below remain importable only so the prior
    # aggregation behavior can be audited against preserved fixtures.
    _ = argv
    print(f"FAIL {RETIREMENT_NOTICE}", file=sys.stderr)
    return 2

    # Historical implementation retained below; unreachable by design.
    args = build_parser().parse_args(argv)
    if args.from_json:
        summary = summary_from_payload(load_json(args.from_json), lookback_hours=args.lookback_hours)
    else:
        try:
            checkout_summary = stripe_checkout_monitor.collect_checkout_summary(
                stripe_bin=args.stripe_bin,
                stripe_project_name=args.stripe_project_name,
                live=not args.test,
                limit=args.limit,
                max_pages=args.max_pages,
                lookback_hours=args.lookback_hours,
                include_monitoring=False,
                expected_display_name=args.expected_stripe_display_name,
                account_source=args.account_source,
                stripe_api_key_env=args.stripe_api_key_env,
                skip_account_check=args.skip_account_check,
                timeout=args.account_check_timeout,
            )
        except RuntimeError as exc:
            print(f"FAIL {stripe_checkout_monitor.redact(exc)}", file=sys.stderr)
            return 1
        summary = stripe_checkout_monitor.summary_to_dict(checkout_summary)

    state = load_json(args.state)
    updated_state, pilot_entry = sync_state(
        state,
        summary,
        synced_at=args.synced_at,
        dashboard_url=args.dashboard_url,
    )
    result = {
        "task_id": PILOT_TASK_ID,
        "stage": pilot_entry.get("stage"),
        "actual_revenue_cents": pilot_entry.get("actual_revenue_cents"),
        "production_pilot_starts": summary.get("production_pilot_starts", 0),
        "production_pilot_paid": summary.get("production_pilot_paid", 0),
        "dry_run": args.dry_run,
    }

    if args.dry_run:
        print(json.dumps({**result, "entry": pilot_entry}, indent=2))
        return 0

    write_json(args.state, updated_state)
    render_outputs(
        execution_path=args.execution_ledger,
        state=updated_state,
        json_output=args.json_output,
        csv_output=args.csv_output,
        md_output=args.md_output,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        revenue = int(pilot_entry.get("actual_revenue_cents") or 0)
        print(
            "Synced Stripe checkout evidence into GTM pipeline: "
            f"stage={pilot_entry.get('stage')}, "
            f"production_pilot_starts={summary.get('production_pilot_starts', 0)}, "
            f"production_pilot_paid={summary.get('production_pilot_paid', 0)}, "
            f"actual_revenue={_money(revenue)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
