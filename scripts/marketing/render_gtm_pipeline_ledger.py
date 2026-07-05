#!/usr/bin/env python3
"""Render a no-PII GTM pipeline ledger from the execution queue.

The execution ledger answers "what should be done next?" This pipeline ledger
answers "what happened, what is the current stage, and what revenue is at
risk?" Manual fields live in marketing/gtm_pipeline_state.json so operator
updates are preserved across regenerations.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXECUTION_LEDGER = ROOT / "marketing" / "generated" / "gtm_execution_ledger.json"
DEFAULT_STATE = ROOT / "marketing" / "gtm_pipeline_state.json"
DEFAULT_JSON = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.json"
DEFAULT_CSV = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.csv"
DEFAULT_MD = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.md"
SCHEMA_VERSION = 1
PILOT_VALUE_CENTS = 500_000
DEVELOPER_YEAR_VALUE_CENTS = 22_800

CSV_COLUMNS = [
    "task_id",
    "channel",
    "target",
    "stage",
    "owner",
    "next_action_at",
    "pipeline_value_cents",
    "probability_percent",
    "weighted_pipeline_cents",
    "actual_revenue_cents",
    "evidence_url",
    "completed_at",
    "next_action",
]


def sanitize_text(value: str) -> str:
    return (
        value.replace("sk_live_...", "<live Stripe API key>")
        .replace("sk_test_...", "<test Stripe API key>")
        .replace("rk_live_...", "<live Stripe restricted key>")
        .replace("rk_test_...", "<test Stripe restricted key>")
        .replace("whsec_...", "<Stripe webhook secret>")
        .replace("tzk_...", "<TinyZKP API key>")
    )


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def today_iso() -> str:
    return date.today().isoformat()


def initial_stage(task: dict[str, Any]) -> str:
    status = task.get("status")
    channel = task.get("channel")
    if status == "external_secret_required":
        return "blocked_external_secret"
    if status == "ready_for_live_verification":
        return "ready_to_verify"
    if status == "completed" and channel == "revenue":
        return "live_monitoring"
    if status == "active_listing_monitor":
        return "live_monitoring"
    if channel == "founder_outbound":
        return "needs_contact_research"
    if status in {"ready_for_manual_submission", "manual_submission_required"}:
        return "ready_to_submit"
    return "not_started"


def pipeline_value(task: dict[str, Any]) -> int:
    task_id = str(task.get("task_id") or "")
    channel = str(task.get("channel") or "")
    primary_cta = str(task.get("primary_cta") or "")
    parsed = urlparse(primary_cta)
    query = parse_qs(parsed.query)
    intent = (query.get("intent") or [""])[0]
    if task_id == "revenue.stripe_catalog_hygiene":
        return 0
    if task_id in {"revenue.pilot_price_binding", "revenue.pilot_checkout_launch"}:
        return PILOT_VALUE_CENTS
    if channel == "founder_outbound":
        return PILOT_VALUE_CENTS
    if intent in {"paid_pilot_checkout", "paid_pilot_contact"}:
        return PILOT_VALUE_CENTS
    return DEVELOPER_YEAR_VALUE_CENTS


def probability_percent(task: dict[str, Any], stage: str) -> int:
    channel = str(task.get("channel") or "")
    if channel == "revenue" and stage == "live_monitoring":
        return 30
    if stage in {"won", "live_monitoring"}:
        return 100 if stage == "won" else 5
    if stage == "blocked_external_secret":
        return 0
    if stage == "ready_to_verify":
        return 20
    if channel == "founder_outbound" and stage == "company_research_ready":
        return 12
    if channel == "founder_outbound":
        return 10
    if channel in {"mcp_distribution", "agent_app_distribution"}:
        return 8
    return 5


def default_state_entry(task: dict[str, Any]) -> dict[str, Any]:
    stage = initial_stage(task)
    return {
        "stage": stage,
        "last_action_at": "",
        "next_action_at": str(task.get("due_date") or ""),
        "evidence_url": str(task.get("evidence_url") or ""),
        "completed_at": "",
        "reply_type": "",
        "outcome": "",
        "actual_revenue_cents": 0,
        "loss_reason": "",
        "notes": "",
    }


def normalize_state(execution: dict[str, Any], state: dict[str, Any] | None) -> dict[str, Any]:
    existing = state or {}
    existing_tasks = existing.get("tasks") if isinstance(existing.get("tasks"), dict) else {}
    synced_tasks: dict[str, dict[str, Any]] = {}
    for task in execution.get("tasks", []):
        task_id = str(task["task_id"])
        entry = default_state_entry(task)
        previous = existing_tasks.get(task_id)
        if isinstance(previous, dict):
            for key in entry:
                if key in previous:
                    entry[key] = previous[key]
        synced_tasks[task_id] = entry
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": str(existing.get("updated_at") or today_iso()),
        "privacy_rules": [
            "Do not commit personal email addresses, phone numbers, private CRM notes, API keys, or customer secrets.",
            "Use evidence URLs, public listing URLs, task IDs, and aggregate outcomes instead of personal contact details.",
            "Record actual revenue only after Stripe, invoice, or signed-contract evidence exists.",
        ],
        "tasks": synced_tasks,
    }


def next_action_for_stage(task: dict[str, Any], stage: str) -> str:
    channel = str(task.get("channel") or "")
    target = str(task.get("target") or "task")
    if stage == "live_monitoring":
        if channel == "revenue":
            return "Monitor pilot checkout starts, completed payments, and paid-pilot contact fallbacks; record revenue only after Stripe or invoice evidence exists."
        return "Monitor accepted listing for current copy, endpoint health, and source-tagged CTA attribution."
    if stage == "submitted":
        return f"Follow up on {target} review, then update the evidence URL when the public listing is accepted."
    if stage == "accepted":
        return "Confirm the public listing renders current copy and move the stage to live_monitoring."
    if stage == "ready_to_verify":
        return sanitize_text(str(task["next_action"]))
    if stage == "sent":
        return "Wait for the scheduled follow-up date, then reply or follow up from the original thread."
    if channel == "founder_outbound" and stage == "company_research_ready":
        return "Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft."
    if stage == "followed_up":
        return "Monitor for replies and move qualified interest to meeting_scheduled."
    if stage in {"won", "lost", "disqualified"}:
        return "No next action; keep evidence and outcome fields immutable unless correcting the record."
    if channel == "founder_outbound" and stage == "needs_contact_research":
        return str(task["next_action"])
    return sanitize_text(str(task["next_action"]))


def pipeline_record(task: dict[str, Any], state_entry: dict[str, Any]) -> dict[str, Any]:
    stage = str(state_entry.get("stage") or initial_stage(task))
    value = int(state_entry.get("pipeline_value_cents") or pipeline_value(task))
    probability = int(state_entry.get("probability_percent") or probability_percent(task, stage))
    actual_revenue = int(state_entry.get("actual_revenue_cents") or 0)
    return {
        "task_id": str(task["task_id"]),
        "channel": str(task["channel"]),
        "task_type": str(task["task_type"]),
        "target": str(task["target"]),
        "owner": str(task["owner"]),
        "stage": stage,
        "source_status": str(task["status"]),
        "next_action_at": str(state_entry.get("next_action_at") or task.get("due_date") or ""),
        "last_action_at": str(state_entry.get("last_action_at") or ""),
        "evidence_url": str(state_entry.get("evidence_url") or task.get("evidence_url") or ""),
        "completed_at": str(state_entry.get("completed_at") or ""),
        "reply_type": str(state_entry.get("reply_type") or ""),
        "outcome": str(state_entry.get("outcome") or ""),
        "loss_reason": str(state_entry.get("loss_reason") or ""),
        "notes": str(state_entry.get("notes") or ""),
        "primary_cta": str(task["primary_cta"]),
        "secondary_cta": str(task["secondary_cta"]),
        "source_artifact": str(task["source_artifact"]),
        "pipeline_value_cents": value,
        "probability_percent": probability,
        "weighted_pipeline_cents": round(value * probability / 100),
        "actual_revenue_cents": actual_revenue,
        "next_action": next_action_for_stage(task, stage),
        "blocker": sanitize_text(str(task.get("blocker") or "")),
    }


def render_pipeline(execution: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    records = [
        pipeline_record(task, state["tasks"][str(task["task_id"])])
        for task in execution.get("tasks", [])
    ]
    by_stage: dict[str, int] = {}
    by_channel: dict[str, int] = {}
    for record in records:
        by_stage[record["stage"]] = by_stage.get(record["stage"], 0) + 1
        by_channel[record["channel"]] = by_channel.get(record["channel"], 0) + 1
    return {
        # Date-tolerant: stamp the committed state version this ledger reflects
        # (state.updated_at), not wall-clock time. This keeps `--check` from
        # going falsely stale when it runs on a different UTC day than the day
        # the ledger was regenerated (CI runs UTC; the operator/cron may be in
        # another timezone). Real content drift is still caught. Write mode is
        # unchanged in practice: the daily cron syncs state first, which sets
        # updated_at to that day, so the freshly written ledger is dated today.
        "generated_at": str(state.get("updated_at") or today_iso()),
        "generated_from": [
            "marketing/generated/gtm_execution_ledger.json",
            "marketing/gtm_pipeline_state.json",
        ],
        "privacy_rules": state["privacy_rules"],
        "summary": {
            "total_records": len(records),
            "open_records": sum(1 for record in records if record["stage"] not in {"won", "lost", "disqualified"}),
            "gross_pipeline_cents": sum(record["pipeline_value_cents"] for record in records),
            "weighted_pipeline_cents": sum(record["weighted_pipeline_cents"] for record in records),
            "actual_revenue_cents": sum(record["actual_revenue_cents"] for record in records),
            "by_stage": dict(sorted(by_stage.items())),
            "by_channel": dict(sorted(by_channel.items())),
        },
        "records": records,
    }


def render_csv(payload: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for record in payload["records"]:
        writer.writerow(record)
    return buffer.getvalue()


def dollars(cents: int) -> str:
    return f"${cents / 100:,.0f}"


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# TinyZKP GTM Pipeline Ledger",
        "",
        "This no-PII ledger tracks GTM execution outcomes, pipeline value, and revenue evidence after manual submissions, outbound sends, and pilot checkout setup.",
        "",
        "## Privacy Rules",
        "",
    ]
    lines.extend(f"- {rule}" for rule in payload["privacy_rules"])
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Total records: {summary['total_records']}",
            f"- Open records: {summary['open_records']}",
            f"- Gross pipeline: {dollars(summary['gross_pipeline_cents'])}",
            f"- Weighted pipeline: {dollars(summary['weighted_pipeline_cents'])}",
            f"- Actual revenue recorded: {dollars(summary['actual_revenue_cents'])}",
            "",
            "## Stage Counts",
            "",
            "| Stage | Count |",
            "|---|---:|",
        ]
    )
    for stage, count in summary["by_stage"].items():
        lines.append(f"| `{stage}` | {count} |")
    lines.extend(
        [
            "",
            "## Pipeline Records",
            "",
            "| Task | Stage | Target | Weighted | Next action |",
            "|---|---|---|---:|---|",
        ]
    )
    for record in payload["records"]:
        lines.append(
            f"| `{record['task_id']}` | `{record['stage']}` | {record['target']} | "
            f"{dollars(record['weighted_pipeline_cents'])} | {record['next_action']} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def expected_outputs(payload: dict[str, Any]) -> dict[Path, str]:
    return {
        Path("json"): json.dumps(payload, indent=2) + "\n",
        Path("csv"): render_csv(payload),
        Path("md"): render_markdown(payload),
    }


def check_outputs(expected: dict[Path, str], paths: dict[Path, Path]) -> list[str]:
    failures: list[str] = []
    for key, path in paths.items():
        if not path.is_file():
            failures.append(f"missing generated GTM pipeline ledger file: {path}")
            continue
        if path.read_text(encoding="utf-8") != expected[key]:
            failures.append(f"stale generated GTM pipeline ledger file: {path}")
    return failures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-ledger", type=Path, default=DEFAULT_EXECUTION_LEDGER)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--csv-output", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--md-output", type=Path, default=DEFAULT_MD)
    parser.add_argument("--sync-state", action="store_true", help="Write missing state entries before rendering")
    parser.add_argument("--check", action="store_true", help="Fail if generated pipeline files are stale")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    execution = load_json(args.execution_ledger)
    existing_state = load_json(args.state) if args.state.is_file() else None
    state = normalize_state(execution, existing_state)
    if args.sync_state:
        args.state.parent.mkdir(parents=True, exist_ok=True)
        args.state.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    elif not args.state.is_file():
        print(f"FAIL missing GTM pipeline state file: {args.state}", file=sys.stderr)
        return 1
    payload = render_pipeline(execution, state)
    expected = expected_outputs(payload)
    paths = {
        Path("json"): args.json_output,
        Path("csv"): args.csv_output,
        Path("md"): args.md_output,
    }
    if args.check:
        failures = check_outputs(expected, paths)
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        if failures:
            print(f"\n{len(failures)} GTM pipeline ledger file(s) are stale.", file=sys.stderr)
            return 1
        print("PASS GTM pipeline ledger is current")
        return 0
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    for key, content in expected.items():
        paths[key].write_text(content, encoding="utf-8")
    print(f"Wrote GTM pipeline ledger with {len(payload['records'])} record(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
