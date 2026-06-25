#!/usr/bin/env python3
"""Validate the GTM pipeline/outcome ledger."""

from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]
EXECUTION_LEDGER = ROOT / "marketing" / "generated" / "gtm_execution_ledger.json"
STATE = ROOT / "marketing" / "gtm_pipeline_state.json"
PIPELINE_JSON = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.json"
PIPELINE_CSV = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.csv"
PIPELINE_MD = ROOT / "marketing" / "generated" / "gtm_pipeline_ledger.md"
MIN_RECORDS = 20
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
GENERIC_INBOX_RE = re.compile(r"\b(?:info|hello|support|sales)@", re.IGNORECASE)
ALLOWED_STAGES = {
    "not_started",
    "blocked_external_secret",
    "ready_to_verify",
    "ready_to_submit",
    "submitted",
    "accepted",
    "live_monitoring",
    "needs_contact_research",
    "company_research_ready",
    "ready_to_send",
    "sent",
    "followed_up",
    "replied",
    "meeting_scheduled",
    "pilot_scoped",
    "won",
    "lost",
    "disqualified",
}
TERMINAL_STAGES = {"won", "lost", "disqualified"}


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def iso_date_error(value: str, label: str) -> str | None:
    if not value:
        return None
    try:
        date.fromisoformat(value)
    except ValueError:
        return f"{label} must be ISO date"
    return None


def tinyzkp_cta_error(value: str) -> str | None:
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.netloc != "tinyzkp.com":
        return "must be an https://tinyzkp.com URL"
    query = parse_qs(parsed.query)
    for field in ("source", "medium", "intent"):
        if not query.get(field):
            return f"must include {field}"
    return None


def privacy_failures(label: str, value: object) -> list[str]:
    text = json.dumps(value, sort_keys=True)
    failures: list[str] = []
    if EMAIL_RE.search(text):
        failures.append(f"{label} must not include personal email addresses")
    if GENERIC_INBOX_RE.search(text):
        failures.append(f"{label} must not include generic inboxes")
    for marker in ("sk_live_", "sk_test_", "rk_live_", "rk_test_", "tzk_", "whsec_"):
        if marker in text:
            failures.append(f"{label} must not include secret-like token {marker}")
    return failures


def validate_state(root: Path, execution_task_ids: set[str]) -> list[Check]:
    path = root / "marketing" / "gtm_pipeline_state.json"
    if not path.is_file():
        return [Check("FAIL", str(path.relative_to(root)), "missing GTM pipeline state")]
    try:
        state = load_json(path)
    except json.JSONDecodeError as exc:
        return [Check("FAIL", str(path.relative_to(root)), f"invalid JSON: {exc}")]

    failures: list[str] = []
    failures.extend(privacy_failures("pipeline state", state))
    if state.get("schema_version") != 1:
        failures.append("schema_version must be 1")
    rules = state.get("privacy_rules")
    if not isinstance(rules, list) or "personal email addresses" not in "\n".join(str(rule) for rule in rules):
        failures.append("privacy_rules must forbid personal email addresses")
    tasks = state.get("tasks")
    if not isinstance(tasks, dict):
        failures.append("tasks must be an object")
        tasks = {}
    missing = execution_task_ids - set(tasks)
    extra = set(tasks) - execution_task_ids
    if missing:
        failures.append("state missing task ids: " + ", ".join(sorted(missing)[:10]))
    if extra:
        failures.append("state has stale task ids: " + ", ".join(sorted(extra)[:10]))
    for task_id, entry in tasks.items():
        if not isinstance(entry, dict):
            failures.append(f"{task_id} state entry must be an object")
            continue
        stage = str(entry.get("stage") or "")
        if stage not in ALLOWED_STAGES:
            failures.append(f"{task_id} has unsupported stage {stage!r}")
        for field in ("last_action_at", "next_action_at", "completed_at"):
            error = iso_date_error(str(entry.get(field) or ""), f"{task_id} {field}")
            if error:
                failures.append(error)
        evidence_url = str(entry.get("evidence_url") or "")
        completed_at = str(entry.get("completed_at") or "")
        actual_revenue = int(entry.get("actual_revenue_cents") or 0)
        if stage in {"won", "accepted", "submitted", "sent", "followed_up", "meeting_scheduled", "pilot_scoped"}:
            if not evidence_url:
                failures.append(f"{task_id} stage {stage} requires evidence_url")
        if stage in TERMINAL_STAGES and not completed_at:
            failures.append(f"{task_id} terminal stage requires completed_at")
        if stage == "won" and actual_revenue <= 0:
            failures.append(f"{task_id} won stage requires actual_revenue_cents")
    if failures:
        return [Check("FAIL", str(path.relative_to(root)), "; ".join(failures[:25]))]
    return [Check("PASS", str(path.relative_to(root)), f"{len(tasks)} pipeline state entries are no-PII and stage-safe")]


def validate_pipeline_json(root: Path, execution_task_ids: set[str]) -> list[Check]:
    path = root / "marketing" / "generated" / "gtm_pipeline_ledger.json"
    if not path.is_file():
        return [Check("FAIL", str(path.relative_to(root)), "missing GTM pipeline ledger JSON")]
    try:
        payload = load_json(path)
    except json.JSONDecodeError as exc:
        return [Check("FAIL", str(path.relative_to(root)), f"invalid JSON: {exc}")]

    failures: list[str] = []
    failures.extend(privacy_failures("pipeline ledger", payload))
    generated_from = payload.get("generated_from")
    required_sources = {"marketing/generated/gtm_execution_ledger.json", "marketing/gtm_pipeline_state.json"}
    if not isinstance(generated_from, list) or not required_sources.issubset(set(generated_from)):
        failures.append("generated_from must include execution ledger and pipeline state")
    records = payload.get("records")
    if not isinstance(records, list):
        failures.append("records must be a list")
        records = []
    elif len(records) < MIN_RECORDS:
        failures.append(f"records must include at least {MIN_RECORDS} rows")
    record_ids = {str(record.get("task_id") or "") for record in records if isinstance(record, dict)}
    if record_ids != execution_task_ids:
        failures.append("pipeline records must match execution ledger task ids")
    for record in records:
        if not isinstance(record, dict):
            failures.append("record entries must be objects")
            continue
        task_id = str(record.get("task_id") or "")
        stage = str(record.get("stage") or "")
        if stage not in ALLOWED_STAGES:
            failures.append(f"{task_id} has unsupported stage {stage!r}")
        for field in ("primary_cta", "secondary_cta"):
            error = tinyzkp_cta_error(str(record.get(field) or ""))
            if error:
                failures.append(f"{task_id} {field} {error}")
        value = int(record.get("pipeline_value_cents") or 0)
        probability = int(record.get("probability_percent") or 0)
        weighted = int(record.get("weighted_pipeline_cents") or 0)
        if value < 0 or probability < 0 or probability > 100:
            failures.append(f"{task_id} has invalid pipeline value/probability")
        if weighted != round(value * probability / 100):
            failures.append(f"{task_id} weighted pipeline must equal value * probability")
    summary = payload.get("summary")
    if isinstance(summary, dict):
        if summary.get("total_records") != len(records):
            failures.append("summary.total_records must match records")
        if summary.get("weighted_pipeline_cents") != sum(int(record.get("weighted_pipeline_cents") or 0) for record in records if isinstance(record, dict)):
            failures.append("summary.weighted_pipeline_cents must match records")
    else:
        failures.append("summary must be an object")
    if failures:
        return [Check("FAIL", str(path.relative_to(root)), "; ".join(failures[:25]))]
    return [Check("PASS", str(path.relative_to(root)), f"{len(records)} pipeline records are attribution-safe")]


def validate_csv(root: Path, expected_count: int | None) -> Check:
    path = root / "marketing" / "generated" / "gtm_pipeline_ledger.csv"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing GTM pipeline ledger CSV")
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    if expected_count is not None and len(rows) != expected_count:
        return Check("FAIL", str(path.relative_to(root)), f"expected {expected_count} rows, found {len(rows)}")
    required = {"task_id", "channel", "stage", "weighted_pipeline_cents", "actual_revenue_cents", "evidence_url"}
    missing = required - set(rows[0] if rows else [])
    if missing:
        return Check("FAIL", str(path.relative_to(root)), "missing columns: " + ", ".join(sorted(missing)))
    failures = []
    for row in rows:
        failures.extend(privacy_failures(f"CSV row {row.get('task_id', '<missing>')}", row))
    if failures:
        return Check("FAIL", str(path.relative_to(root)), "; ".join(failures[:10]))
    return Check("PASS", str(path.relative_to(root)), "CSV is ready for no-PII pipeline review")


def validate_markdown(root: Path) -> Check:
    path = root / "marketing" / "generated" / "gtm_pipeline_ledger.md"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing GTM pipeline ledger markdown")
    text = path.read_text(encoding="utf-8")
    markers = [
        "# TinyZKP GTM Pipeline Ledger",
        "## Privacy Rules",
        "## Summary",
        "Weighted pipeline",
        "## Stage Counts",
        "## Pipeline Records",
    ]
    missing = [marker for marker in markers if marker not in text]
    if "needs_contact_research" not in text and "company_research_ready" not in text:
        missing.append("needs_contact_research or company_research_ready")
    if missing:
        return Check("FAIL", str(path.relative_to(root)), "missing markers: " + ", ".join(missing))
    failures = privacy_failures("pipeline markdown", text)
    if failures:
        return Check("FAIL", str(path.relative_to(root)), "; ".join(failures[:10]))
    return Check("PASS", str(path.relative_to(root)), "markdown summarizes no-PII pipeline status")


def validate(root: Path = ROOT) -> list[Check]:
    execution_path = root / "marketing" / "generated" / "gtm_execution_ledger.json"
    if not execution_path.is_file():
        return [Check("FAIL", str(execution_path.relative_to(root)), "missing execution ledger")]
    execution = load_json(execution_path)
    execution_task_ids = {str(task["task_id"]) for task in execution.get("tasks", []) if isinstance(task, dict)}
    checks = validate_state(root, execution_task_ids)
    checks.extend(validate_pipeline_json(root, execution_task_ids))
    expected_count = None
    if checks and all(check.status == "PASS" for check in checks[:2]):
        expected_count = len(execution_task_ids)
    checks.append(validate_csv(root, expected_count))
    checks.append(validate_markdown(root))
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} GTM pipeline ledger check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll GTM pipeline ledger checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
