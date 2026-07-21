#!/usr/bin/env python3
"""Validate the bounded Guard revenue-readiness pipeline and note overlay."""

from __future__ import annotations

import csv
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
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
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
SECRET_RE = re.compile(r"\b(?:sk|rk)_(?:live|test)_|\bwhsec_|\btzk_", re.IGNORECASE)
BANNED_ACTIVE_MARKERS = {
    "retired payment provider": re.compile(r"\bstripe\b", re.IGNORECASE),
    "retired one-off offer": re.compile(r"\bpilot\b", re.IGNORECASE),
    "retired account funnel": re.compile(r"\bsignup\b", re.IGNORECASE),
    "retired agent distribution": re.compile(r"\bmcp\b", re.IGNORECASE),
    "retired hosted API route": re.compile(r"(?:https://api\.tinyzkp\.com|https://mcp\.tinyzkp\.com|tinyzkp\.com/api/)", re.IGNORECASE),
    "retired site route": re.compile(r"tinyzkp\.com/(?:try|verify|contact|pilot|signup)(?:[?#/]|$)", re.IGNORECASE),
    "legacy sales stage": re.compile(r"\b(?:completed|won|live_monitoring|meeting_scheduled|ready_to_send)\b", re.IGNORECASE),
}
EXPECTED_OPERATOR_RULES = [
    "Do not override gate status in this file; update canonical Guard launch evidence instead.",
    "Do not add fields or free-form text; each gate may contain only an optional next-action date.",
    "Do not record customer data, payment data, credentials, pipeline value, or revenue in this schedule.",
]
EXPECTED_PIPELINE_ROOT_KEYS = {
    "schema_version", "ledger_type", "generated_at", "generated_from", "operator_rules",
    "business_state", "offers", "summary", "records",
}
EXPECTED_BUSINESS_KEYS = {
    "launch_state", "sales_state", "checkout_enabled", "commerce_state", "portal_state",
    "merchant_provider", "merchant_of_record_status", "legal_status", "hosted_proving",
    "usage_metering", "revenue_evidence_claimed", "recorded_revenue_cents",
}
EXPECTED_PIPELINE_SUMMARY_KEYS = {
    "total_records", "blocking_records", "passed_records", "sales_open", "checkout_enabled",
    "revenue_evidence_claimed", "recorded_revenue_cents", "by_category", "by_status",
}
EXPECTED_RECORD_KEYS = {
    "task_id", "category", "gate", "status", "owner", "reason_code", "evidence_count",
    "public_status_url", "source_artifact", "next_action_at", "next_action",
}


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


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


def load_renderer():
    path = ROOT / "scripts" / "marketing" / "render_gtm_pipeline_ledger.py"
    spec = importlib.util.spec_from_file_location("render_gtm_pipeline_ledger_for_check", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Guard pipeline renderer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def iso_date_error(value: str, label: str) -> str | None:
    if not value:
        return None
    try:
        date.fromisoformat(value)
    except ValueError:
        return f"{label} must be an ISO date"
    return None


def content_failures(label: str, value: object) -> list[str]:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    failures = [f"{label} contains {name}" for name, pattern in BANNED_ACTIVE_MARKERS.items() if pattern.search(text)]
    if EMAIL_RE.search(text):
        failures.append(f"{label} contains an email address")
    if SECRET_RE.search(text):
        failures.append(f"{label} contains secret-like data")
    return failures


def validate_state(root: Path, execution_ids: set[str]) -> list[Check]:
    path = root / "marketing" / "gtm_pipeline_state.json"
    try:
        state = load_json(path)
    except FileNotFoundError:
        return [Check("FAIL", str(path.relative_to(root)), "missing Guard pipeline state")]
    except (json.JSONDecodeError, ValueError) as exc:
        return [Check("FAIL", str(path.relative_to(root)), f"invalid JSON: {exc}")]
    failures = content_failures("active pipeline state", state)
    expected_root_keys = {"schema_version", "mode", "updated_at", "operator_rules", "tasks"}
    if set(state) != expected_root_keys:
        failures.append("pipeline state may contain only schema_version, mode, updated_at, operator_rules, and tasks")
    if state.get("schema_version") != 2:
        failures.append("schema_version must be 2")
    if state.get("mode") != "guard_revenue_readiness_schedule":
        failures.append("mode must be guard_revenue_readiness_schedule")
    error = iso_date_error(str(state.get("updated_at") or ""), "updated_at")
    if error:
        failures.append(error)
    rules = state.get("operator_rules")
    if rules != EXPECTED_OPERATOR_RULES:
        failures.append("operator_rules must exactly match the bounded schedule contract")
    tasks = state.get("tasks")
    if not isinstance(tasks, dict):
        failures.append("tasks must be an object")
        tasks = {}
    if set(tasks) != execution_ids:
        failures.append("state task IDs must exactly match current Guard execution gate IDs")
    for task_id, entry in tasks.items():
        if not isinstance(entry, dict):
            failures.append(f"{task_id} state entry must be an object")
            continue
        if set(entry) != {"next_action_at"}:
            failures.append(f"{task_id} state entry may contain only next_action_at")
        error = iso_date_error(str(entry.get("next_action_at") or ""), f"{task_id} next_action_at")
        if error:
            failures.append(error)
    if failures:
        return [Check("FAIL", str(path.relative_to(root)), "; ".join(failures[:30]))]
    return [Check("PASS", str(path.relative_to(root)), f"{len(tasks)} bounded schedule entries are safe")]


def validate_pipeline_json(root: Path, execution: dict[str, Any], state: dict[str, Any]) -> list[Check]:
    path = root / "marketing" / "generated" / "gtm_pipeline_ledger.json"
    try:
        payload = load_json(path)
    except FileNotFoundError:
        return [Check("FAIL", str(path.relative_to(root)), "missing Guard pipeline JSON")]
    except (json.JSONDecodeError, ValueError) as exc:
        return [Check("FAIL", str(path.relative_to(root)), f"invalid JSON: {exc}")]
    failures = content_failures("pipeline ledger", payload)
    if set(payload) != EXPECTED_PIPELINE_ROOT_KEYS:
        failures.append("pipeline ledger root fields must exactly match the bounded Guard schema")
    if payload.get("schema_version") != 2:
        failures.append("schema_version must be 2")
    if payload.get("ledger_type") != "guard_revenue_readiness_pipeline":
        failures.append("ledger_type must be guard_revenue_readiness_pipeline")
    if payload.get("generated_from") != [
        "marketing/generated/gtm_execution_ledger.json",
        "marketing/gtm_pipeline_state.json",
    ]:
        failures.append("generated_from must contain only the active execution ledger and note overlay")
    if payload.get("business_state") != execution.get("business_state"):
        failures.append("business_state must exactly mirror the current execution ledger")
    if isinstance(payload.get("business_state"), dict) and set(payload["business_state"]) != EXPECTED_BUSINESS_KEYS:
        failures.append("pipeline business_state fields must exactly match the bounded Guard schema")
    if payload.get("offers") != execution.get("offers"):
        failures.append("offers must exactly mirror the current execution ledger")

    execution_tasks = execution.get("tasks") if isinstance(execution.get("tasks"), list) else []
    execution_by_id = {str(task.get("task_id")): task for task in execution_tasks if isinstance(task, dict)}
    state_tasks = state.get("tasks") if isinstance(state.get("tasks"), dict) else {}
    records = payload.get("records")
    if not isinstance(records, list):
        failures.append("records must be a list")
        records = []
    record_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            failures.append("record must be an object")
            continue
        if set(record) != EXPECTED_RECORD_KEYS:
            failures.append("pipeline record fields must exactly match the bounded Guard schema")
        task_id = str(record.get("task_id") or "")
        record_ids.add(task_id)
        task = execution_by_id.get(task_id)
        note = state_tasks.get(task_id)
        if not isinstance(task, dict) or not isinstance(note, dict):
            failures.append(f"{task_id} must map to execution and state entries")
            continue
        for field in (
            "task_id",
            "category",
            "gate",
            "status",
            "owner",
            "reason_code",
            "evidence_count",
            "public_status_url",
            "source_artifact",
            "next_action",
        ):
            if record.get(field) != task.get(field):
                failures.append(f"{task_id} {field} must mirror execution ledger")
        if record.get("next_action_at") != note.get("next_action_at"):
            failures.append(f"{task_id} next-action date must mirror pipeline state")
        if any(field in record for field in ("primary_cta", "secondary_cta", "pipeline_value_cents", "probability_percent", "actual_revenue_cents", "completed_at")):
            failures.append(f"{task_id} must not contain CTA, forecast, completion, or revenue fields")
    if record_ids != set(execution_by_id):
        failures.append("pipeline records must exactly match current Guard gate tasks")

    summary = payload.get("summary")
    if not isinstance(summary, dict):
        failures.append("summary must be an object")
    else:
        if set(summary) != EXPECTED_PIPELINE_SUMMARY_KEYS:
            failures.append("pipeline summary fields must exactly match the bounded Guard schema")
        blocked = sum(record.get("status") == "blocked" for record in records if isinstance(record, dict))
        passed = sum(record.get("status") == "passed" for record in records if isinstance(record, dict))
        if summary.get("total_records") != len(records) or summary.get("blocking_records") != blocked or summary.get("passed_records") != passed:
            failures.append("summary record counts must match records")
        if summary.get("revenue_evidence_claimed") is not False or summary.get("recorded_revenue_cents") != 0:
            failures.append("pipeline summary must not claim revenue evidence")
        if summary.get("sales_open") != execution.get("summary", {}).get("sales_open"):
            failures.append("pipeline sales state must mirror execution ledger")
        if summary.get("checkout_enabled") != execution.get("summary", {}).get("checkout_enabled"):
            failures.append("pipeline checkout state must mirror execution ledger")
    if failures:
        return [Check("FAIL", str(path.relative_to(root)), "; ".join(failures[:30]))]
    return [Check("PASS", str(path.relative_to(root)), f"{len(records)} Guard readiness records are canonical and value-free")]


def validate_csv(root: Path, expected_count: int, expected_text: str | None = None) -> Check:
    path = root / "marketing" / "generated" / "gtm_pipeline_ledger.csv"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing Guard pipeline CSV")
    text = path.read_text(encoding="utf-8")
    failures = content_failures("pipeline CSV", text)
    if expected_text is not None and text != expected_text:
        failures.append("CSV must exactly match the canonical pipeline JSON rendering")
    rows = list(csv.DictReader(text.splitlines()))
    columns = list(rows[0].keys()) if rows else []
    if columns != CSV_COLUMNS:
        failures.append("CSV columns must match the bounded Guard pipeline schema")
    if len(rows) != expected_count:
        failures.append(f"expected {expected_count} rows, found {len(rows)}")
    if failures:
        return Check("FAIL", str(path.relative_to(root)), "; ".join(failures))
    return Check("PASS", str(path.relative_to(root)), f"CSV contains {len(rows)} Guard readiness records")


def validate_markdown(root: Path, expected_text: str | None = None) -> Check:
    path = root / "marketing" / "generated" / "gtm_pipeline_ledger.md"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing Guard pipeline markdown")
    text = path.read_text(encoding="utf-8")
    failures = content_failures("pipeline markdown", text)
    if expected_text is not None and text != expected_text:
        failures.append("markdown must exactly match the canonical pipeline JSON rendering")
    for marker in (
        "# TinyZKP Guard Revenue Readiness Pipeline",
        "It is not a sales forecast",
        "Revenue evidence claimed: `false`",
        "Recorded revenue: `$0`",
        "## Gate Records",
    ):
        if marker not in text:
            failures.append(f"markdown missing {marker!r}")
    if failures:
        return Check("FAIL", str(path.relative_to(root)), "; ".join(failures))
    return Check("PASS", str(path.relative_to(root)), "markdown reports only bounded Guard readiness")


def validate(root: Path = ROOT) -> list[Check]:
    execution_path = root / "marketing" / "generated" / "gtm_execution_ledger.json"
    state_path = root / "marketing" / "gtm_pipeline_state.json"
    try:
        execution = load_json(execution_path)
        state = load_json(state_path)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        return [Check("FAIL", "Guard pipeline inputs", str(exc))]
    input_failures = content_failures("execution ledger input", execution)
    if execution.get("schema_version") != 2 or execution.get("ledger_type") != "guard_revenue_readiness":
        input_failures.append("execution ledger input must use the current Guard revenue-readiness schema")
    business_state = execution.get("business_state")
    if not isinstance(business_state, dict):
        input_failures.append("execution ledger business_state must be an object")
    elif business_state.get("revenue_evidence_claimed") is not False or business_state.get("recorded_revenue_cents") != 0:
        input_failures.append("execution ledger business_state must not claim revenue evidence")
    execution_summary = execution.get("summary")
    if not isinstance(execution_summary, dict):
        input_failures.append("execution ledger summary must be an object")
    elif execution_summary.get("revenue_evidence_claimed") is not False or execution_summary.get("recorded_revenue_cents") != 0:
        input_failures.append("execution ledger summary must not claim revenue evidence")
    if input_failures:
        return [Check("FAIL", "Guard pipeline inputs", "; ".join(input_failures[:30]))]
    execution_ids = {
        str(task.get("task_id"))
        for task in execution.get("tasks", [])
        if isinstance(task, dict)
    }
    checks = validate_state(root, execution_ids)
    checks.extend(validate_pipeline_json(root, execution, state))
    expected_outputs: dict[str, str] = {}
    if all(check.status == "PASS" for check in checks):
        payload = load_json(root / "marketing" / "generated" / "gtm_pipeline_ledger.json")
        expected_outputs = load_renderer().expected_outputs(payload)
    checks.append(validate_csv(root, len(execution_ids), expected_outputs.get("csv")))
    checks.append(validate_markdown(root, expected_outputs.get("md")))
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} Guard pipeline check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll Guard revenue-readiness pipeline checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
