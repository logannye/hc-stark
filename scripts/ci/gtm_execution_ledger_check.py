#!/usr/bin/env python3
"""Validate the generated GTM execution ledger."""

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
LEDGER_JSON = ROOT / "marketing" / "generated" / "gtm_execution_ledger.json"
LEDGER_CSV = ROOT / "marketing" / "generated" / "gtm_execution_ledger.csv"
LEDGER_MD = ROOT / "marketing" / "generated" / "gtm_execution_ledger.md"
MIN_MCP_TASKS = 8
MIN_OUTBOUND_TASKS = 10
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
GENERIC_INBOX_RE = re.compile(r"\b(?:info|hello|support|sales)@", re.IGNORECASE)
ALLOWED_STATUSES = {
    "external_secret_required",
    "ready_for_live_verification",
    "manual_submission_required",
    "ready_for_manual_submission",
    "ready_after_manual_contact_research",
    "active_listing_monitor",
    "completed",
    "submitted",
    "sent",
    "accepted",
}
COMPLETED_STATUSES = {"completed", "submitted", "sent", "accepted"}


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def tinyzkp_cta_error(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "tinyzkp.com":
        return "must be an https://tinyzkp.com URL"
    query = parse_qs(parsed.query)
    if not query.get("source"):
        return "must include source"
    if not query.get("medium"):
        return "must include medium"
    if not query.get("intent"):
        return "must include intent"
    return None


def parse_date(value: str, label: str, failures: list[str]) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        failures.append(f"{label} must be ISO date")
        return None


def validate_json(root: Path) -> list[Check]:
    path = root / "marketing" / "generated" / "gtm_execution_ledger.json"
    if not path.is_file():
        return [Check("FAIL", str(path.relative_to(root)), "missing GTM execution ledger JSON")]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [Check("FAIL", str(path.relative_to(root)), f"invalid JSON: {exc}")]

    failures: list[str] = []
    generated_from = payload.get("generated_from")
    required_sources = {
        "marketing/mcp_distribution_targets.json",
        "marketing/generated/outbound_send_queue.json",
        "marketing/openai_chatgpt_app_submission.json",
    }
    if not isinstance(generated_from, list) or not required_sources.issubset(set(generated_from)):
        failures.append("generated_from must include all source GTM artifacts")

    rules = payload.get("manual_rules")
    if not isinstance(rules, list):
        failures.append("manual_rules must be a list")
        rules = []
    else:
        rule_text = "\n".join(str(rule) for rule in rules)
        for marker in ("Do not mark a task complete", "Do not automate cold outbound", "Preserve every source-tagged"):
            if marker not in rule_text:
                failures.append(f"manual_rules must include {marker!r}")

    tasks = payload.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        failures.append("tasks must be a non-empty list")
        tasks = []

    seen_ids: set[str] = set()
    mcp_count = 0
    outbound_count = 0
    has_pilot = False
    has_stripe_catalog_hygiene = False
    has_chatgpt = False
    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            failures.append(f"task {index} must be an object")
            continue
        task_id = str(task.get("task_id") or "")
        label = task_id or f"task {index}"
        if not task_id:
            failures.append(f"{label} missing task_id")
        elif task_id in seen_ids:
            failures.append(f"duplicate task_id {task_id}")
        seen_ids.add(task_id)

        channel = str(task.get("channel") or "")
        status = str(task.get("status") or "")
        if channel == "mcp_distribution":
            mcp_count += 1
        if channel == "founder_outbound":
            outbound_count += 1
        if task_id in {"revenue.pilot_price_binding", "revenue.pilot_checkout_launch"}:
            has_pilot = True
            if "inline price_data" not in str(task.get("blocker", "")):
                failures.append("pilot task must document inline price_data fallback")
        if task_id == "revenue.stripe_catalog_hygiene":
            has_stripe_catalog_hygiene = True
            if status != "external_secret_required":
                failures.append("Stripe catalog hygiene task must stay external_secret_required until write-capable Stripe access exists")
            if "--strict-catalog" not in str(task.get("evidence_command", "")):
                failures.append("Stripe catalog hygiene task must use strict revenue-ops audit evidence")
        if task_id == "agent_app.openai_chatgpt_app_submission":
            has_chatgpt = True

        if status not in ALLOWED_STATUSES:
            failures.append(f"{label} has unsupported status {status!r}")
        for field in ("owner", "target", "task_type", "source_artifact", "evidence_command", "next_action"):
            if not isinstance(task.get(field), str) or not str(task.get(field)).strip():
                failures.append(f"{label} missing {field}")

        for field in ("primary_cta", "secondary_cta"):
            cta = str(task.get(field) or "")
            error = tinyzkp_cta_error(cta)
            if error:
                failures.append(f"{label} {field} {error}")

        due_date = parse_date(str(task.get("due_date") or ""), f"{label} due_date", failures)
        follow_up_date = parse_date(str(task.get("follow_up_date") or ""), f"{label} follow_up_date", failures)
        if due_date and follow_up_date and follow_up_date <= due_date:
            failures.append(f"{label} follow_up_date must be after due_date")

        evidence_url = str(task.get("evidence_url") or "")
        completed_at = str(task.get("completed_at") or "")
        if status in COMPLETED_STATUSES:
            if not evidence_url or not completed_at:
                failures.append(f"{label} completed/submitted/sent status requires evidence_url and completed_at")
        else:
            if completed_at:
                failures.append(f"{label} completed_at must stay blank until task is complete")

        if channel == "founder_outbound":
            if task.get("contact_name") or task.get("contact_email"):
                failures.append(f"{label} outbound contact fields must stay blank in generated ledger")
            if status != "ready_after_manual_contact_research":
                failures.append(f"{label} outbound task must require manual contact research")
            if not task.get("follow_up_date"):
                failures.append(f"{label} outbound task must include one follow-up date")

        serialized = json.dumps(task, sort_keys=True)
        if EMAIL_RE.search(serialized):
            failures.append(f"{label} must not include personal email addresses")
        if GENERIC_INBOX_RE.search(serialized):
            failures.append(f"{label} must not include generic inboxes")

    if not has_pilot:
        failures.append("ledger must include pilot checkout launch task")
    if not has_stripe_catalog_hygiene:
        failures.append("ledger must include Stripe catalog hygiene task")
    if not has_chatgpt:
        failures.append("ledger must include ChatGPT app submission task")
    if mcp_count < MIN_MCP_TASKS:
        failures.append(f"ledger must include at least {MIN_MCP_TASKS} MCP distribution tasks")
    if outbound_count < MIN_OUTBOUND_TASKS:
        failures.append(f"ledger must include at least {MIN_OUTBOUND_TASKS} founder outbound tasks")

    summary = payload.get("summary")
    if isinstance(summary, dict):
        if summary.get("total_tasks") != len(tasks):
            failures.append("summary.total_tasks must match task count")
        if summary.get("outbound_manual_sends") != outbound_count:
            failures.append("summary.outbound_manual_sends must match outbound task count")
    else:
        failures.append("summary must be an object")

    if failures:
        return [Check("FAIL", str(path.relative_to(root)), "; ".join(failures[:25]))]
    return [Check("PASS", str(path.relative_to(root)), f"{len(tasks)} GTM execution tasks are attribution-safe")]


def validate_csv(root: Path, expected_count: int | None) -> Check:
    path = root / "marketing" / "generated" / "gtm_execution_ledger.csv"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing GTM execution ledger CSV")
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    if expected_count is not None and len(rows) != expected_count:
        return Check("FAIL", str(path.relative_to(root)), f"expected {expected_count} rows, found {len(rows)}")
    required = {"task_id", "channel", "status", "primary_cta", "evidence_url", "completed_at", "next_action"}
    missing = required - set(rows[0] if rows else [])
    if missing:
        return Check("FAIL", str(path.relative_to(root)), "missing columns: " + ", ".join(sorted(missing)))
    if any(EMAIL_RE.search(json.dumps(row)) for row in rows):
        return Check("FAIL", str(path.relative_to(root)), "CSV must not include personal email addresses")
    return Check("PASS", str(path.relative_to(root)), "CSV is ready for operator execution tracking")


def validate_markdown(root: Path) -> Check:
    path = root / "marketing" / "generated" / "gtm_execution_ledger.md"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing GTM execution ledger markdown")
    text = path.read_text(encoding="utf-8")
    markers = [
        "## Revenue Binding",
        "## MCP Directory Submissions",
        "## Agent App Submission",
        "## Founder Outbound Sends",
        "source=gtm_execution_ledger",
        "source=founder_outbound",
        "inline price_data",
        "Do not automate cold outbound email sends.",
    ]
    missing = [marker for marker in markers if marker not in text]
    if missing:
        return Check("FAIL", str(path.relative_to(root)), "missing markers: " + ", ".join(missing))
    if EMAIL_RE.search(text):
        return Check("FAIL", str(path.relative_to(root)), "markdown must not include personal email addresses")
    return Check("PASS", str(path.relative_to(root)), "markdown preserves manual execution rules and source-tagged CTAs")


def validate(root: Path = ROOT) -> list[Check]:
    checks = validate_json(root)
    expected_count: int | None = None
    if checks and checks[0].status == "PASS":
        payload = json.loads((root / "marketing" / "generated" / "gtm_execution_ledger.json").read_text(encoding="utf-8"))
        expected_count = len(payload.get("tasks") or [])
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
        print(f"\n{len(failures)} GTM execution ledger check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll GTM execution ledger checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
