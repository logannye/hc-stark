#!/usr/bin/env python3
"""Validate the founder-led outbound target catalog."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]
TARGETS_JSON = ROOT / "marketing" / "generated" / "outbound_targets.json"
TARGETS_MD = ROOT / "marketing" / "generated" / "outbound_targets.md"
MIN_TARGETS = 25
VALID_ROUTES = {"paid_pilot", "platform_rollout", "self_serve_developer", "fit_finder"}
REQUIRED_TRACKED_URLS = {"learn", "fit", "calculator", "pilot", "signup"}
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def tinyzkp_url_error(url: str, *, expected_intent: str | None = None) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "tinyzkp.com":
        return "must be an https://tinyzkp.com URL"
    query = parse_qs(parsed.query)
    required = {
        "source": "founder_outbound",
        "medium": "email",
        "platform": "direct",
    }
    for field, expected in required.items():
        if query.get(field) != [expected]:
            return f"must include {field}={expected}"
    if expected_intent and query.get("intent") != [expected_intent]:
        return f"must include intent={expected_intent}"
    if not query.get("campaign"):
        return "must include campaign"
    if not query.get("workflow"):
        return "must include workflow"
    return None


def validate(root: Path = ROOT) -> list[Check]:
    checks: list[Check] = []
    targets_path = root / "marketing" / "generated" / "outbound_targets.json"
    md_path = root / "marketing" / "generated" / "outbound_targets.md"

    if not targets_path.is_file():
        return [Check("FAIL", str(targets_path.relative_to(root)), "missing outbound target catalog")]
    if not md_path.is_file():
        checks.append(Check("FAIL", str(md_path.relative_to(root)), "missing rendered outbound target markdown"))

    try:
        payload = json.loads(targets_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [Check("FAIL", str(targets_path.relative_to(root)), f"invalid JSON: {exc}")]

    failures: list[str] = []
    if not isinstance(payload, dict):
        return [Check("FAIL", str(targets_path.relative_to(root)), "payload must be a JSON object")]
    if not payload.get("generated_at"):
        failures.append("generated_at is required")
    if not payload.get("campaign"):
        failures.append("campaign is required")
    source_urls = payload.get("source_urls")
    if not isinstance(source_urls, list) or not source_urls:
        failures.append("source_urls must be a non-empty list")
    elif not all(isinstance(url, str) and url.startswith("https://www.ycombinator.com/companies/") for url in source_urls):
        failures.append("source_urls must point to YC company directory pages")

    targets = payload.get("targets")
    if not isinstance(targets, list):
        failures.append("targets must be a list")
        targets = []
    elif len(targets) < MIN_TARGETS:
        failures.append(f"targets must contain at least {MIN_TARGETS} entries")

    seen_ids: set[str] = set()
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            failures.append(f"target {index} must be an object")
            continue
        target_id = str(target.get("id") or "")
        label = target_id or f"index {index}"
        if not target_id:
            failures.append(f"target {index} missing id")
        if target_id in seen_ids:
            failures.append(f"duplicate target id {target_id}")
        seen_ids.add(target_id)

        for field in ("company", "website", "yc_url", "source_url", "one_liner", "fit_reason"):
            if not isinstance(target.get(field), str) or not target[field].strip():
                failures.append(f"{label} missing {field}")
        if not str(target.get("yc_url", "")).startswith("https://www.ycombinator.com/companies/"):
            failures.append(f"{label} yc_url must point to YC company profile")
        if target.get("recommended_route") not in VALID_ROUTES:
            failures.append(f"{label} has invalid recommended_route")
        if not isinstance(target.get("score"), int) or target["score"] < 1:
            failures.append(f"{label} score must be positive integer")
        if not isinstance(target.get("signals"), list) or not target["signals"]:
            failures.append(f"{label} signals must be non-empty")
        if target.get("contact_research_status") != "needs_manual_founder_or_engineering_contact":
            failures.append(f"{label} must require manual contact research")
        serialized = json.dumps(target, sort_keys=True)
        if EMAIL_RE.search(serialized):
            failures.append(f"{label} must not include personal email addresses")

        tracked_urls = target.get("tracked_urls")
        if not isinstance(tracked_urls, dict):
            failures.append(f"{label} tracked_urls must be an object")
            continue
        missing_urls = REQUIRED_TRACKED_URLS - set(tracked_urls)
        if missing_urls:
            failures.append(f"{label} missing tracked URLs: {', '.join(sorted(missing_urls))}")
        expected_intents = {
            "learn": "learn",
            "fit": "find_route",
            "calculator": "calculator",
            "pilot": "paid_pilot_checkout",
            "signup": "api_key",
        }
        for key, expected_intent in expected_intents.items():
            value = tracked_urls.get(key)
            if not isinstance(value, str):
                failures.append(f"{label} tracked_urls.{key} must be a string")
                continue
            error = tinyzkp_url_error(value, expected_intent=expected_intent)
            if error:
                failures.append(f"{label} tracked_urls.{key} {error}")

        email_draft = target.get("email_draft")
        if not isinstance(email_draft, dict):
            failures.append(f"{label} email_draft must be an object")
        else:
            for field in ("subject", "first_line", "hook"):
                if not isinstance(email_draft.get(field), str) or not email_draft[field].strip():
                    failures.append(f"{label} email_draft.{field} is required")

    if failures:
        checks.append(Check("FAIL", str(targets_path.relative_to(root)), "; ".join(failures[:20])))
    else:
        checks.append(Check("PASS", str(targets_path.relative_to(root)), f"{len(targets)} founder-led outbound targets are source-tagged and contact-safe"))

    if md_path.is_file():
        text = md_path.read_text(encoding="utf-8")
        if "source=founder_outbound" in text and "## Operating Rules" in text:
            checks.append(Check("PASS", str(md_path.relative_to(root)), "rendered markdown preserves source-tagged CTAs and operating rules"))
        else:
            checks.append(Check("FAIL", str(md_path.relative_to(root)), "rendered markdown missing source-tagged CTAs or operating rules"))
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} outbound target check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll outbound target checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
