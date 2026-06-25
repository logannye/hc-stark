#!/usr/bin/env python3
"""Validate generated contact-safe outbound research packets."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]
PACKETS_JSON = ROOT / "marketing" / "generated" / "outbound_research_packets.json"
PACKETS_MD = ROOT / "marketing" / "generated" / "outbound_research_packets.md"
MIN_PACKETS = 10
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


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
    if parsed.scheme.lower() == "mailto":
        return f"{label} must not be mailto"
    return None


def validate_json(root: Path) -> list[Check]:
    path = root / "marketing" / "generated" / "outbound_research_packets.json"
    if not path.is_file():
        return [Check("FAIL", str(path.relative_to(root)), "missing outbound research packet JSON")]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [Check("FAIL", str(path.relative_to(root)), f"invalid JSON: {exc}")]

    failures: list[str] = []
    if payload.get("generated_from") != "marketing/generated/outbound_send_queue.json":
        failures.append("generated_from must point to outbound send queue")
    rules = payload.get("privacy_rules")
    if not isinstance(rules, list) or not any("Do not store personal email" in str(rule) for rule in rules):
        failures.append("privacy rules must forbid storing personal email addresses")

    packets = payload.get("packets")
    if not isinstance(packets, list):
        failures.append("packets must be a list")
        packets = []
    elif len(packets) < MIN_PACKETS:
        failures.append(f"packets must include at least {MIN_PACKETS} first-wave targets")

    seen_ids: set[str] = set()
    for index, packet in enumerate(packets):
        if not isinstance(packet, dict):
            failures.append(f"packet {index} must be an object")
            continue
        target_id = str(packet.get("target_id") or "")
        label = target_id or f"index {index}"
        if not target_id:
            failures.append(f"{label} missing target_id")
        if target_id in seen_ids:
            failures.append(f"duplicate target_id {target_id}")
        seen_ids.add(target_id)
        if packet.get("contact_research_status") != "needs_manual_founder_or_engineering_contact":
            failures.append(f"{label} must preserve manual contact research status")
        if "No personal emails" not in str(packet.get("privacy_rule") or ""):
            failures.append(f"{label} must include packet privacy rule")
        for field in ("company", "website", "yc_url", "recommended_route", "contact_role", "company_research_status", "route_guidance"):
            if not isinstance(packet.get(field), str) or not packet[field].strip():
                failures.append(f"{label} missing {field}")
        if not str(packet.get("yc_url", "")).startswith("https://www.ycombinator.com/companies/"):
            failures.append(f"{label} yc_url must point to YC")
        homepage = packet.get("homepage")
        if not isinstance(homepage, dict) or not homepage.get("status"):
            failures.append(f"{label} homepage must include status")
        public_links = packet.get("public_company_links")
        if not isinstance(public_links, dict):
            failures.append(f"{label} public_company_links must be an object")
            public_links = {}
        for group in ("contact", "about", "product"):
            values = public_links.get(group)
            if not isinstance(values, list):
                failures.append(f"{label} public_company_links.{group} must be a list")
                continue
            for url in values:
                error = https_url_error(str(url), f"{label} {group} URL")
                if error:
                    failures.append(error)
        for field in ("primary_cta", "secondary_cta"):
            error = tinyzkp_cta_error(str(packet.get(field) or ""))
            if error:
                failures.append(f"{label} {field} {error}")
        manual_urls = packet.get("manual_research_urls")
        if not isinstance(manual_urls, list) or len(manual_urls) < 4:
            failures.append(f"{label} must keep manual research URLs")

    serialized = json.dumps(payload, sort_keys=True)
    if EMAIL_RE.search(serialized):
        failures.append("packet JSON must not include email addresses")
    if "mailto:" in serialized.lower():
        failures.append("packet JSON must not include mailto links")

    if failures:
        return [Check("FAIL", str(path.relative_to(root)), "; ".join(failures[:20]))]
    return [Check("PASS", str(path.relative_to(root)), f"{len(packets)} contact-safe research packet(s)")]


def validate_markdown(root: Path) -> Check:
    path = root / "marketing" / "generated" / "outbound_research_packets.md"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing outbound research packet markdown")
    text = path.read_text(encoding="utf-8")
    markers = [
        "# TinyZKP Outbound Research Packets",
        "## Privacy Rules",
        "Company-level public pages only.",
        "Do not store personal email addresses",
        "source=founder_outbound",
        "Manual research URLs:",
    ]
    missing = [marker for marker in markers if marker not in text]
    if missing:
        return Check("FAIL", str(path.relative_to(root)), "missing markers: " + ", ".join(missing))
    if EMAIL_RE.search(text):
        return Check("FAIL", str(path.relative_to(root)), "markdown must not include email addresses")
    if "mailto:" in text.lower():
        return Check("FAIL", str(path.relative_to(root)), "markdown must not include mailto links")
    return Check("PASS", str(path.relative_to(root)), "markdown preserves privacy rules and source-tagged CTAs")


def validate(root: Path = ROOT) -> list[Check]:
    checks = validate_json(root)
    checks.append(validate_markdown(root))
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} outbound research packet check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll outbound research packet checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
