#!/usr/bin/env python3
"""Render the first founder-led outbound send queue from target records.

This does not discover contacts and does not send email. It converts the
company-level outbound target catalog into manual research slots, draft copy,
and source-tagged TinyZKP links so a founder can send one human email at a
time after selecting the right person.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import urllib.parse
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGETS = ROOT / "marketing" / "generated" / "outbound_targets.json"
DEFAULT_JSON = ROOT / "marketing" / "generated" / "outbound_send_queue.json"
DEFAULT_CSV = ROOT / "marketing" / "generated" / "outbound_send_queue.csv"
DEFAULT_MD = ROOT / "marketing" / "generated" / "outbound_send_queue.md"

SEND_WEEKDAYS = {0, 1, 2}  # Monday, Tuesday, Wednesday.


def load_targets(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_generated_date(payload: dict[str, Any]) -> date:
    generated_at = str(payload.get("generated_at") or "").replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(generated_at).date()
    except ValueError:
        return datetime.now(timezone.utc).date()


def next_send_day(start: date) -> date:
    candidate = start
    while candidate.weekday() not in SEND_WEEKDAYS:
        candidate += timedelta(days=1)
    return candidate


def add_business_days(start: date, days: int) -> date:
    candidate = start
    added = 0
    while added < days:
        candidate += timedelta(days=1)
        if candidate.weekday() < 5:
            added += 1
    return candidate


def contact_role(target: dict[str, Any]) -> str:
    route = target.get("recommended_route")
    signals = set(target.get("signals") or [])
    if route == "paid_pilot" or signals & {"audit", "compliance", "reconciliation", "erp", "manufacturing", "payments"}:
        return "Founder, head of engineering, or workflow owner"
    if route == "platform_rollout":
        return "Founder, platform lead, or agent product owner"
    if route == "self_serve_developer":
        return "Founder, developer-experience lead, or senior engineer"
    return "Founder or engineering lead"


def primary_cta(target: dict[str, Any]) -> str:
    urls = target["tracked_urls"]
    route = target.get("recommended_route")
    if route == "paid_pilot":
        return urls["pilot"]
    if route == "self_serve_developer":
        return urls["signup"]
    return urls["fit"]


def secondary_cta(target: dict[str, Any]) -> str:
    urls = target["tracked_urls"]
    route = target.get("recommended_route")
    if route == "paid_pilot":
        return urls["calculator"]
    if route == "self_serve_developer":
        return urls["learn"]
    return urls["pilot"]


def draft_body(target: dict[str, Any], cta: str) -> str:
    company = target["company"]
    one_liner = target["one_liner"].rstrip(".")
    hook = target["fit_reason"].rstrip(".")
    return (
        "Hi [first name] -\n\n"
        f"I looked at {company}. {one_liner}.\n\n"
        f"{hook}. TinyZKP's smallest useful test is one receipt for one state transition: "
        "initial state, declared steps, final state, and a verifier URL another service or "
        "human can inspect without replaying your system.\n\n"
        f"Start here: {cta}\n\n"
        "Free tier covers evaluation. If the statement or verifier placement needs design "
        "review, the paid pilot path is scoped to one workflow.\n\n"
        "- Logan"
    )


def follow_up_body(target: dict[str, Any]) -> str:
    company = target["company"]
    return (
        f"Bumping this once for {company}. If TinyZKP is not relevant, no need to reply "
        "and I will not follow up again. If the fit is unclear, the fastest test is one "
        "receipt on one consequential state transition."
    )


def mailto_template(subject: str, body: str) -> str:
    return "mailto:?" + urllib.parse.urlencode({"subject": subject, "body": body})


def company_domain(website: str) -> str:
    parsed = urllib.parse.urlparse(website)
    host = parsed.netloc or parsed.path
    return host.removeprefix("www.").strip("/")


def https_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if not parsed.scheme:
        return "https://" + value.lstrip("/")
    if parsed.scheme == "http":
        return urllib.parse.urlunparse(parsed._replace(scheme="https"))
    return value


def research_urls(target: dict[str, Any]) -> list[dict[str, str]]:
    company = str(target["company"])
    website = https_url(str(target["website"]))
    domain = company_domain(website)
    founder_query = f"{company} founder CTO engineering lead"
    if domain:
        founder_query = f"{founder_query} {domain}"
    return [
        {
            "label": "YC profile",
            "url": str(target["yc_url"]),
            "purpose": "Confirm company fit, batch, description, and public founder context.",
        },
        {
            "label": "Company website",
            "url": website,
            "purpose": "Confirm current positioning and avoid stale outreach hooks.",
        },
        {
            "label": "Founder/engineering web search",
            "url": "https://www.google.com/search?" + urllib.parse.urlencode({"q": founder_query}),
            "purpose": "Manually identify exactly one founder, engineering lead, platform lead, or workflow owner.",
        },
        {
            "label": "LinkedIn people search",
            "url": "https://www.linkedin.com/search/results/people/?" + urllib.parse.urlencode({"keywords": founder_query}),
            "purpose": "Cross-check role/title before sending; do not export or store personal emails.",
        },
    ]


def queue_record(target: dict[str, Any], rank: int, send_date: date, follow_up_date: date) -> dict[str, Any]:
    subject = target.get("email_draft", {}).get("subject") or f"verifiable receipts for {target['company']}?"
    cta = primary_cta(target)
    body = draft_body(target, cta)
    follow_up = follow_up_body(target)
    return {
        "rank": rank,
        "target_id": target["id"],
        "company": target["company"],
        "website": https_url(str(target["website"])),
        "yc_url": target["yc_url"],
        "score": target["score"],
        "recommended_route": target["recommended_route"],
        "send_date": send_date.isoformat(),
        "follow_up_date": follow_up_date.isoformat(),
        "contact_research_status": "needs_manual_founder_or_engineering_contact",
        "contact_role": contact_role(target),
        "contact_name": "",
        "contact_email": "",
        "send_status": "ready_after_manual_contact_research",
        "reply_type": "",
        "outcome": "",
        "subject": subject[:60],
        "body": body,
        "follow_up_body": follow_up,
        "primary_cta": cta,
        "secondary_cta": secondary_cta(target),
        "research_urls": research_urls(target),
        "mailto_template": mailto_template(subject[:60], body),
    }


def render_queue(payload: dict[str, Any], *, limit: int, first_send_date: date | None = None) -> dict[str, Any]:
    targets = payload.get("targets") or []
    base_date = first_send_date or next_send_day(parse_generated_date(payload))
    follow_up_date = add_business_days(base_date, 5)
    queue = [
        queue_record(target, rank, base_date, follow_up_date)
        for rank, target in enumerate(targets[:limit], start=1)
    ]
    return {
        "generated_from": "marketing/generated/outbound_targets.json",
        "source_campaign": payload.get("campaign"),
        "source_generated_at": payload.get("generated_at"),
        "send_window": {
            "first_send_date": base_date.isoformat(),
            "send_days": "Monday/Tuesday/Wednesday only",
            "follow_up_after_business_days": 5,
            "first_follow_up_date": follow_up_date.isoformat(),
        },
        "manual_rules": [
            "Research exactly one founder, engineering lead, platform lead, or workflow owner before sending.",
            "Do not use generic info@, hello@, support@, or sales@ inboxes.",
            "Send one human email and at most one follow-up.",
            "Do not use automated cold-email sending tools.",
            "Preserve the source-tagged TinyZKP CTA URLs.",
        ],
        "queue": queue,
    }


def render_csv(payload: dict[str, Any]) -> str:
    columns = [
        "rank",
        "company",
        "website",
        "yc_url",
        "score",
        "recommended_route",
        "send_date",
        "follow_up_date",
        "contact_role",
        "contact_name",
        "contact_email",
        "contact_research_status",
        "send_status",
        "reply_type",
        "outcome",
        "subject",
        "primary_cta",
        "secondary_cta",
        "research_urls",
        "mailto_template",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in payload["queue"]:
        row = {
            **row,
            "research_urls": " | ".join(f"{item['label']}: {item['url']}" for item in row["research_urls"]),
        }
        writer.writerow(row)
    return buffer.getvalue()


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# TinyZKP First-Wave Outbound Send Queue",
        "",
        f"Source catalog: `{payload['generated_from']}`",
        f"First send date: `{payload['send_window']['first_send_date']}`",
        f"First follow-up date: `{payload['send_window']['first_follow_up_date']}`",
        "",
        "This is a manual founder-led send queue. It deliberately leaves contact names and email addresses blank.",
        "",
        "## Manual Send Rules",
        "",
    ]
    lines.extend(f"- {rule}" for rule in payload["manual_rules"])
    lines.extend(
        [
            "",
            "## Queue",
            "",
            "| Rank | Company | Route | Contact role | Send | Follow-up | CTA |",
            "|---:|---|---|---|---|---|---|",
        ]
    )
    for row in payload["queue"]:
        lines.append(
            f"| {row['rank']} | [{row['company']}]({row['yc_url']}) | `{row['recommended_route']}` | "
            f"{row['contact_role']} | {row['send_date']} | {row['follow_up_date']} | [Primary CTA]({row['primary_cta']}) |"
        )

    lines.extend(["", "## Drafts", ""])
    for row in payload["queue"]:
        lines.extend(
            [
                f"### {row['rank']}. {row['company']}",
                "",
                f"- Website: {row['website']}",
                f"- YC profile: {row['yc_url']}",
                f"- Contact research: `{row['contact_research_status']}`",
                f"- Contact role: {row['contact_role']}",
                "- Research links:",
                *[f"  - [{item['label']}]({item['url']}) - {item['purpose']}" for item in row["research_urls"]],
                f"- Subject: `{row['subject']}`",
                f"- Primary CTA: {row['primary_cta']}",
                f"- Secondary CTA: {row['secondary_cta']}",
                "",
                "```text",
                row["body"],
                "```",
                "",
                "Follow-up:",
                "",
                "```text",
                row["follow_up_body"],
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def check_outputs(expected: dict[Path, str], output_paths: dict[Path, Path]) -> list[str]:
    failures: list[str] = []
    for label, path in output_paths.items():
        if not path.is_file():
            failures.append(f"missing generated outbound send queue file: {path}")
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected[label]:
            failures.append(f"stale generated outbound send queue file: {path}")
    return failures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--csv-output", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--md-output", type=Path, default=DEFAULT_MD)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--first-send-date", type=date.fromisoformat)
    parser.add_argument("--check", action="store_true", help="Fail if generated queue files are stale")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    source = load_targets(args.targets)
    payload = render_queue(source, limit=args.limit, first_send_date=args.first_send_date)
    expected = {
        Path("json"): json.dumps(payload, indent=2) + "\n",
        Path("csv"): render_csv(payload),
        Path("md"): render_markdown(payload),
    }
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
            print(f"\n{len(failures)} outbound send queue file(s) are stale.", file=sys.stderr)
            return 1
        print("PASS outbound send queue is current")
        return 0

    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    for key, content in expected.items():
        paths[key].write_text(content, encoding="utf-8")
    print(f"Wrote outbound send queue with {len(payload['queue'])} target(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
