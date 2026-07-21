#!/usr/bin/env python3
"""Render the no-PII Guard launch-readiness pipeline.

Canonical status comes from the generated Guard revenue-readiness ledger.
The state file contains only an optional next-action date per gate; it cannot
override gate status, store free-form data, create pipeline value, or record
revenue.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXECUTION_LEDGER = ROOT / "marketing" / "generated" / "gtm_execution_ledger.json"
DEFAULT_STATE = ROOT / "marketing" / "gtm_pipeline_state.json"
DEFAULT_JSON = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.json"
DEFAULT_CSV = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.csv"
DEFAULT_MD = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.md"
SCHEMA_VERSION = 2
STATE_MODE = "guard_revenue_readiness_schedule"
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
OPERATOR_RULES = [
    "Do not override gate status in this file; update canonical Guard launch evidence instead.",
    "Do not add fields or free-form text; each gate may contain only an optional next-action date.",
    "Do not record customer data, payment data, credentials, pipeline value, or revenue in this schedule.",
]

CSV_COLUMNS = [
    "task_id",
    "category",
    "gate",
    "status",
    "owner",
    "reason_code",
    "evidence_count",
    "public_status_url",
    "next_action_at",
    "next_action",
]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject_nonfinite,
    )
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _valid_date(value: str) -> bool:
    if not value:
        return True
    if not DATE_RE.fullmatch(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def default_state_entry() -> dict[str, str]:
    return {"next_action_at": ""}


def normalize_state(execution: dict[str, Any], state: dict[str, Any] | None) -> dict[str, Any]:
    existing = state if isinstance(state, dict) else {}
    existing_tasks = existing.get("tasks") if existing.get("schema_version") == SCHEMA_VERSION else {}
    if not isinstance(existing_tasks, dict):
        existing_tasks = {}
    tasks: dict[str, dict[str, str]] = {}
    for task in execution.get("tasks", []):
        task_id = str(task["task_id"])
        entry = default_state_entry()
        previous = existing_tasks.get(task_id)
        if isinstance(previous, dict):
            entry["next_action_at"] = str(previous.get("next_action_at") or "")
        if not _valid_date(entry["next_action_at"]):
            raise ValueError(f"{task_id} next_action_at must be an ISO date")
        tasks[task_id] = entry
    generated_at = str(execution.get("generated_at") or "")
    updated_at = str(existing.get("updated_at") or generated_at) if existing.get("schema_version") == SCHEMA_VERSION else generated_at
    if not _valid_date(updated_at):
        raise ValueError("pipeline state updated_at must be an ISO date")
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": STATE_MODE,
        "updated_at": updated_at,
        "operator_rules": OPERATOR_RULES,
        "tasks": tasks,
    }


def pipeline_record(task: dict[str, Any], state_entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": str(task["task_id"]),
        "category": str(task["category"]),
        "gate": str(task["gate"]),
        "status": str(task["status"]),
        "owner": str(task["owner"]),
        "reason_code": str(task["reason_code"]),
        "evidence_count": int(task["evidence_count"]),
        "public_status_url": str(task["public_status_url"]),
        "source_artifact": str(task["source_artifact"]),
        "next_action_at": str(state_entry.get("next_action_at") or ""),
        "next_action": str(task["next_action"]),
    }


def render_pipeline(execution: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    if execution.get("schema_version") != 2 or execution.get("ledger_type") != "guard_revenue_readiness":
        raise ValueError("execution ledger must be the current Guard revenue-readiness schema")
    business_state = execution.get("business_state")
    if not isinstance(business_state, dict):
        raise ValueError("execution business_state must be an object")
    if business_state.get("revenue_evidence_claimed") is not False or business_state.get("recorded_revenue_cents") != 0:
        raise ValueError("execution ledger must not claim revenue evidence")
    execution_summary = execution.get("summary")
    if not isinstance(execution_summary, dict):
        raise ValueError("execution summary must be an object")
    if execution_summary.get("revenue_evidence_claimed") is not False or execution_summary.get("recorded_revenue_cents") != 0:
        raise ValueError("execution summary must not claim revenue evidence")
    execution_tasks = execution.get("tasks")
    if not isinstance(execution_tasks, list):
        raise ValueError("execution ledger tasks must be a list")
    state_tasks = state.get("tasks")
    if not isinstance(state_tasks, dict):
        raise ValueError("pipeline state tasks must be an object")
    records = [pipeline_record(task, state_tasks[str(task["task_id"])]) for task in execution_tasks]
    by_category: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for record in records:
        by_category[record["category"]] = by_category.get(record["category"], 0) + 1
        by_status[record["status"]] = by_status.get(record["status"], 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "ledger_type": "guard_revenue_readiness_pipeline",
        "generated_at": str(execution["generated_at"]),
        "generated_from": [
            "marketing/generated/gtm_execution_ledger.json",
            "marketing/gtm_pipeline_state.json",
        ],
        "operator_rules": state["operator_rules"],
        "business_state": business_state,
        "offers": execution["offers"],
        "summary": {
            "total_records": len(records),
            "blocking_records": sum(record["status"] == "blocked" for record in records),
            "passed_records": sum(record["status"] == "passed" for record in records),
            "sales_open": bool(execution_summary["sales_open"]),
            "checkout_enabled": bool(execution_summary["checkout_enabled"]),
            "revenue_evidence_claimed": False,
            "recorded_revenue_cents": 0,
            "by_category": dict(sorted(by_category.items())),
            "by_status": dict(sorted(by_status.items())),
        },
        "records": records,
    }


def render_csv(payload: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(payload["records"])
    return buffer.getvalue()


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# TinyZKP Guard Revenue Readiness Pipeline",
        "",
        "This pipeline is a canonical gate view with a date-only schedule overlay. It is not a sales forecast, customer ledger, payment ledger, or booked-revenue report.",
        "",
        "## Summary",
        "",
        f"- Total records: {summary['total_records']}",
        f"- Blocking records: {summary['blocking_records']}",
        f"- Passed records: {summary['passed_records']}",
        f"- Sales open: `{str(summary['sales_open']).lower()}`",
        f"- Checkout enabled: `{str(summary['checkout_enabled']).lower()}`",
        "- Revenue evidence claimed: `false`",
        "- Recorded revenue: `$0`",
        "",
        "## Gate Records",
        "",
        "| Gate | Category | Status | Evidence | Next action date | Next action |",
        "|---|---|---|---:|---|---|",
    ]
    for record in payload["records"]:
        lines.append(
            f"| [{record['gate']}]({record['public_status_url']}) | `{record['category']}` | "
            f"`{record['status']}` | {record['evidence_count']} | {record['next_action_at']} | {record['next_action']} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def expected_outputs(payload: dict[str, Any]) -> dict[str, str]:
    return {
        "json": json.dumps(payload, indent=2) + "\n",
        "csv": render_csv(payload),
        "md": render_markdown(payload),
    }


def check_outputs(expected: dict[str, str], paths: dict[str, Path]) -> list[str]:
    failures: list[str] = []
    for key, path in paths.items():
        if not path.is_file():
            failures.append(f"missing generated Guard pipeline file: {path}")
        elif path.read_text(encoding="utf-8") != expected[key]:
            failures.append(f"stale generated Guard pipeline file: {path}")
    return failures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-ledger", type=Path, default=DEFAULT_EXECUTION_LEDGER)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--csv-output", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--md-output", type=Path, default=DEFAULT_MD)
    parser.add_argument("--sync-state", action="store_true", help="Synchronize the bounded operator-note state")
    parser.add_argument("--check", action="store_true", help="Fail if generated pipeline files are stale")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        execution = load_json(args.execution_ledger)
        existing_state = load_json(args.state) if args.state.is_file() else None
        state = normalize_state(execution, existing_state)
        if args.sync_state:
            args.state.parent.mkdir(parents=True, exist_ok=True)
            args.state.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        elif not args.state.is_file():
            print(f"FAIL missing Guard pipeline state file: {args.state}", file=sys.stderr)
            return 1
        payload = render_pipeline(execution, state)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"FAIL cannot render Guard pipeline: {exc}", file=sys.stderr)
        return 1
    expected = expected_outputs(payload)
    paths = {"json": args.json_output, "csv": args.csv_output, "md": args.md_output}
    if args.check:
        failures = check_outputs(expected, paths)
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        if failures:
            return 1
        print("PASS Guard revenue-readiness pipeline is current")
        return 0
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    for key, content in expected.items():
        paths[key].write_text(content, encoding="utf-8")
    print(f"Wrote Guard revenue-readiness pipeline with {len(payload['records'])} record(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
