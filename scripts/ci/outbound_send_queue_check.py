#!/usr/bin/env python3
"""Validate the manual founder-led outbound send queue."""

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
QUEUE_JSON = ROOT / "marketing" / "generated" / "outbound_send_queue.json"
QUEUE_CSV = ROOT / "marketing" / "generated" / "outbound_send_queue.csv"
QUEUE_MD = ROOT / "marketing" / "generated" / "outbound_send_queue.md"
MIN_QUEUE_TARGETS = 10
SEND_WEEKDAYS = {0, 1, 2}
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
GENERIC_INBOX_RE = re.compile(r"\b(?:info|hello|support|sales)@", re.IGNORECASE)


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
    required = {
        "source": "founder_outbound",
        "medium": "email",
        "platform": "direct",
        "campaign": "yc_agent_outbound",
    }
    for field, expected in required.items():
        if query.get(field) != [expected]:
            return f"must include {field}={expected}"
    if not query.get("intent"):
        return "must include intent"
    if not query.get("workflow"):
        return "must include workflow"
    return None


def https_url_error(url: str, label: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        return f"{label} must be an HTTPS URL"
    return None


def parse_iso_date(value: object, label: str, failures: list[str]) -> date | None:
    if not isinstance(value, str):
        failures.append(f"{label} must be a date string")
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        failures.append(f"{label} must be ISO date")
        return None


def validate_json(root: Path) -> list[Check]:
    path = root / "marketing" / "generated" / "outbound_send_queue.json"
    if not path.is_file():
        return [Check("FAIL", str(path.relative_to(root)), "missing send queue JSON")]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [Check("FAIL", str(path.relative_to(root)), f"invalid JSON: {exc}")]

    failures: list[str] = []
    if payload.get("generated_from") != "marketing/generated/outbound_targets.json":
        failures.append("generated_from must point to outbound target catalog")
    rules = payload.get("manual_rules")
    if not isinstance(rules, list) or not any("Do not use automated" in str(rule) for rule in rules):
        failures.append("manual rules must forbid automated cold-email sending")
    if not any("one follow-up" in str(rule) for rule in rules or []):
        failures.append("manual rules must enforce one follow-up")

    queue = payload.get("queue")
    if not isinstance(queue, list):
        failures.append("queue must be a list")
        queue = []
    elif len(queue) < MIN_QUEUE_TARGETS:
        failures.append(f"queue must include at least {MIN_QUEUE_TARGETS} targets")

    seen_ids: set[str] = set()
    for index, row in enumerate(queue):
        if not isinstance(row, dict):
            failures.append(f"queue row {index} must be an object")
            continue
        target_id = str(row.get("target_id") or "")
        label = target_id or f"index {index}"
        if not target_id:
            failures.append(f"{label} missing target_id")
        if target_id in seen_ids:
            failures.append(f"duplicate target_id {target_id}")
        seen_ids.add(target_id)

        if row.get("contact_research_status") != "needs_manual_founder_or_engineering_contact":
            failures.append(f"{label} must require manual contact research")
        if row.get("send_status") != "ready_after_manual_contact_research":
            failures.append(f"{label} must not be marked sent before manual contact research")
        if row.get("contact_name") or row.get("contact_email"):
            failures.append(f"{label} contact fields must be blank before manual research")
        if not isinstance(row.get("contact_role"), str) or "Founder" not in row["contact_role"]:
            failures.append(f"{label} contact_role must name a founder/engineering research target")
        research_urls = row.get("research_urls")
        if not isinstance(research_urls, list) or len(research_urls) < 4:
            failures.append(f"{label} must include no-PII research_urls")
            research_urls = []
        seen_research_labels: set[str] = set()
        for item_index, item in enumerate(research_urls):
            if not isinstance(item, dict):
                failures.append(f"{label} research_urls[{item_index}] must be an object")
                continue
            research_label = str(item.get("label") or "")
            research_url = str(item.get("url") or "")
            purpose = str(item.get("purpose") or "")
            if not research_label or research_label in seen_research_labels:
                failures.append(f"{label} research_urls must have unique labels")
            seen_research_labels.add(research_label)
            error = https_url_error(research_url, f"{label} research_urls[{research_label}]")
            if error:
                failures.append(error)
            if not purpose:
                failures.append(f"{label} research_urls[{research_label}] must include purpose")
            serialized_research = json.dumps(item, sort_keys=True)
            if EMAIL_RE.search(serialized_research) or GENERIC_INBOX_RE.search(serialized_research):
                failures.append(f"{label} research_urls must not include email addresses")

        send_date = parse_iso_date(row.get("send_date"), f"{label} send_date", failures)
        follow_up_date = parse_iso_date(row.get("follow_up_date"), f"{label} follow_up_date", failures)
        if send_date and send_date.weekday() not in SEND_WEEKDAYS:
            failures.append(f"{label} send_date must be Monday, Tuesday, or Wednesday")
        if send_date and follow_up_date and follow_up_date <= send_date:
            failures.append(f"{label} follow_up_date must be after send_date")

        for field in ("company", "website", "yc_url", "subject", "body", "follow_up_body", "primary_cta", "secondary_cta"):
            if not isinstance(row.get(field), str) or not row[field].strip():
                failures.append(f"{label} missing {field}")
        if not str(row.get("yc_url", "")).startswith("https://www.ycombinator.com/companies/"):
            failures.append(f"{label} yc_url must point to YC")
        if len(str(row.get("subject", ""))) > 60:
            failures.append(f"{label} subject must be 60 chars or fewer")
        body = str(row.get("body", ""))
        if "[first name]" not in body:
            failures.append(f"{label} body must keep first-name placeholder")
        if "source=founder_outbound" not in body:
            failures.append(f"{label} body must include source-tagged CTA")
        if "will not follow up again" not in str(row.get("follow_up_body", "")):
            failures.append(f"{label} follow-up must state no further follow-up")

        serialized = json.dumps(row, sort_keys=True)
        if EMAIL_RE.search(serialized):
            failures.append(f"{label} must not include personal email addresses")
        if GENERIC_INBOX_RE.search(serialized):
            failures.append(f"{label} must not include generic inboxes")

        for field in ("primary_cta", "secondary_cta"):
            error = tinyzkp_cta_error(str(row.get(field) or ""))
            if error:
                failures.append(f"{label} {field} {error}")
        mailto = str(row.get("mailto_template") or "")
        if not mailto.startswith("mailto:?"):
            failures.append(f"{label} mailto_template must omit recipient")

    if failures:
        return [Check("FAIL", str(path.relative_to(root)), "; ".join(failures[:20]))]
    return [Check("PASS", str(path.relative_to(root)), f"{len(queue)} manual send-queue targets are contact-safe")]


def validate_csv(root: Path, expected_count: int | None) -> Check:
    path = root / "marketing" / "generated" / "outbound_send_queue.csv"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing send queue CSV")
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    if expected_count is not None and len(rows) != expected_count:
        return Check("FAIL", str(path.relative_to(root)), f"expected {expected_count} rows, found {len(rows)}")
    required = {"company", "contact_name", "contact_email", "primary_cta", "research_urls", "send_status"}
    missing = required - set(rows[0] if rows else [])
    if missing:
        return Check("FAIL", str(path.relative_to(root)), "missing columns: " + ", ".join(sorted(missing)))
    if any(row.get("contact_email") for row in rows):
        return Check("FAIL", str(path.relative_to(root)), "contact_email cells must stay blank")
    if any("Founder/engineering web search" not in row.get("research_urls", "") for row in rows):
        return Check("FAIL", str(path.relative_to(root)), "CSV research_urls must include founder/engineering search")
    return Check("PASS", str(path.relative_to(root)), "CSV is ready for manual contact research")


def validate_markdown(root: Path) -> Check:
    path = root / "marketing" / "generated" / "outbound_send_queue.md"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing send queue markdown")
    text = path.read_text(encoding="utf-8")
    markers = [
        "## Manual Send Rules",
        "Do not use automated cold-email sending tools.",
        "source=founder_outbound",
        "one follow-up",
        "Contact research: `needs_manual_founder_or_engineering_contact`",
        "Research links:",
        "Founder/engineering web search",
    ]
    missing = [marker for marker in markers if marker not in text]
    if missing:
        return Check("FAIL", str(path.relative_to(root)), "missing markers: " + ", ".join(missing))
    in_fence = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        marker = line.strip()
        if not marker.startswith("```"):
            continue
        if not in_fence:
            if marker != "```text":
                return Check("FAIL", str(path.relative_to(root)), f"markdown code fence at line {line_number} must use ```text")
            in_fence = True
        else:
            if marker != "```":
                return Check("FAIL", str(path.relative_to(root)), f"markdown code fence at line {line_number} must close with ```")
            in_fence = False
    if in_fence:
        return Check("FAIL", str(path.relative_to(root)), "markdown code fences must be balanced")
    if EMAIL_RE.search(text):
        return Check("FAIL", str(path.relative_to(root)), "markdown must not include personal email addresses")
    return Check("PASS", str(path.relative_to(root)), "markdown preserves manual send rules and source-tagged CTAs")


def validate(root: Path = ROOT) -> list[Check]:
    checks = validate_json(root)
    expected_count: int | None = None
    if checks and checks[0].status == "PASS":
        payload = json.loads((root / "marketing" / "generated" / "outbound_send_queue.json").read_text(encoding="utf-8"))
        expected_count = len(payload.get("queue") or [])
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
        print(f"\n{len(failures)} outbound send queue check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll outbound send queue checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
