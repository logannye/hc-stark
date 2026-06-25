#!/usr/bin/env python3
"""Generate founder-led outbound targets from public company directories.

This intentionally does not scrape personal email addresses and does not send
email. It produces a company-level target list plus source-tagged TinyZKP URLs
so the founder can manually research the right person and send one human email.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JSON = ROOT / "marketing" / "generated" / "outbound_targets.json"
DEFAULT_MD = ROOT / "marketing" / "generated" / "outbound_targets.md"
DEFAULT_SOURCES = [
    "https://www.ycombinator.com/companies/industry/ai",
    "https://www.ycombinator.com/companies/industry/developer-tools",
    "https://www.ycombinator.com/companies/industry/workflow-automation",
    "https://www.ycombinator.com/companies/industry/ai-assistant",
]

MIN_SCORE = 8
DEFAULT_LIMIT = 50

SIGNAL_KEYWORDS = {
    "agent": 5,
    "agents": 5,
    "autonomous": 4,
    "workflow": 4,
    "workflows": 4,
    "automation": 4,
    "automate": 4,
    "tool": 2,
    "tools": 2,
    "api": 3,
    "apis": 3,
    "developer-tools": 3,
    "devtools": 3,
    "browser": 2,
    "desktop": 2,
    "erp": 4,
    "manufacturing": 3,
    "fintech": 3,
    "finance": 3,
    "payments": 3,
    "compliance": 4,
    "audit": 5,
    "auditor": 5,
    "reconciliation": 5,
    "operations": 2,
    "support": 2,
    "security": 3,
    "observability": 2,
    "state": 3,
    "critical": 3,
}

NEGATIVE_KEYWORDS = {
    "dating",
    "game",
    "gaming",
    "consumer social",
    "avatar",
    "photo",
    "video",
    "music",
}


@dataclass(frozen=True)
class Company:
    slug: str
    name: str
    batch_name: str
    one_liner: str
    website: str
    long_description: str
    tags: list[str]
    team_size: int | None
    year_founded: int | None
    location: str
    linkedin_url: str
    twitter_url: str
    github_url: str
    ycdc_company_url: str
    source_url: str

    @property
    def yc_url(self) -> str:
        if self.ycdc_company_url.startswith("http"):
            return self.ycdc_company_url
        return urllib.parse.urljoin("https://www.ycombinator.com", self.ycdc_company_url)


class DataPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.payloads: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "div":
            return
        attr_map = {name: value or "" for name, value in attrs}
        data_page = attr_map.get("data-page", "")
        if not data_page or "CompanyListPage" not in data_page:
            return
        try:
            payload = json.loads(html.unescape(data_page))
        except json.JSONDecodeError:
            return
        if isinstance(payload, dict) and isinstance(payload.get("props"), dict):
            self.payloads.append(payload)


def fetch_text(url: str, timeout: float) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "TinyZKP-Outbound-Target-Research/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def companies_from_html(source_url: str, text: str) -> list[Company]:
    parser = DataPageParser()
    parser.feed(text)
    companies: list[Company] = []
    for payload in parser.payloads:
        raw_companies = payload.get("props", {}).get("companies", [])
        if not isinstance(raw_companies, list):
            continue
        for raw in raw_companies:
            if not isinstance(raw, dict) or raw.get("_type") != "company":
                continue
            companies.append(
                Company(
                    slug=str(raw.get("slug") or "").strip(),
                    name=str(raw.get("name") or "").strip(),
                    batch_name=str(raw.get("batch_name") or "").strip(),
                    one_liner=str(raw.get("one_liner") or "").strip(),
                    website=str(raw.get("website") or "").strip(),
                    long_description=str(raw.get("long_description") or "").strip(),
                    tags=[str(tag).strip() for tag in raw.get("tags") or [] if str(tag).strip()],
                    team_size=raw.get("team_size") if isinstance(raw.get("team_size"), int) else None,
                    year_founded=raw.get("year_founded") if isinstance(raw.get("year_founded"), int) else None,
                    location=str(raw.get("location") or "").strip(),
                    linkedin_url=str(raw.get("linkedin_url") or "").strip(),
                    twitter_url=str(raw.get("twitter_url") or "").strip(),
                    github_url=str(raw.get("github_url") or "").strip(),
                    ycdc_company_url=str(raw.get("ycdc_company_url") or "").strip(),
                    source_url=source_url,
                )
            )
    return [company for company in companies if company.slug and company.name and company.website]


def normalized_text(company: Company) -> str:
    return " ".join(
        [
            company.name,
            company.one_liner,
            company.long_description,
            " ".join(company.tags),
            company.location,
            company.batch_name,
        ]
    ).lower()


def matched_signals(company: Company) -> list[str]:
    text = normalized_text(company)
    signals: list[str] = []
    for keyword in SIGNAL_KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", text):
            signals.append(keyword)
    return signals


def score_company(company: Company) -> tuple[int, list[str]]:
    text = normalized_text(company)
    if any(keyword in text for keyword in NEGATIVE_KEYWORDS):
        return 0, []

    signals = matched_signals(company)
    score = sum(SIGNAL_KEYWORDS[signal] for signal in signals)
    tags = {tag.lower() for tag in company.tags}

    if company.team_size is not None and company.team_size <= 25:
        score += 2
        signals.append("small_team")
    if company.year_founded is not None and company.year_founded >= 2023:
        score += 2
        signals.append("recent_company")
    if company.batch_name.lower().endswith(("2025", "2026")) or company.batch_name.lower().startswith(("w25", "s25", "f25", "w26", "s26", "p2026")):
        score += 2
        signals.append("recent_yc_batch")
    if {"b2b", "enterprise-software", "developer-tools"} & tags:
        score += 2
        signals.append("b2b_or_devtools")
    if company.team_size is not None and company.team_size > 100:
        score -= 5
        signals.append("large_team_penalty")
    return max(score, 0), sorted(set(signals))


def recommended_route(company: Company, signals: list[str]) -> str:
    tags = {tag.lower() for tag in company.tags}
    text = normalized_text(company)
    if "developer-tools" in tags or "ide" in text or "platform" in text:
        return "platform_rollout"
    if {"audit", "compliance", "reconciliation", "erp", "manufacturing", "fintech", "payments"} & set(signals):
        return "paid_pilot"
    if "api" in signals or "devtools" in signals:
        return "self_serve_developer"
    return "fit_finder"


def hook_for(company: Company, signals: list[str]) -> str:
    text = normalized_text(company)
    if "manufacturing" in signals or "erp" in signals:
        return "Receipt ERP and supplier workflow state changes so customers can verify what the agent did without replaying the producer system."
    if "audit" in signals or "compliance" in signals:
        return "Attach verifier-friendly receipts to compliance or audit checkpoints where signed logs alone do not prove the transition rule."
    if "fintech" in signals or "payments" in signals or "reconciliation" in signals:
        return "Receipt balance, payment, or reconciliation transitions that need independent verification by customers, auditors, or downstream services."
    if "browser" in signals or "desktop" in signals:
        return "Receipt consequential browser/desktop agent actions so operators can inspect state changes after autonomous execution."
    if "developer-tools" in company.tags or "developer" in text:
        return "Expose TinyZKP as a native proof-receipt tool for agent builders who already operate through developer workflows."
    return "Add proof receipts to consequential agent actions so recipients can verify the state transition without trusting the agent transcript."


def tinyzkp_url(path: str, *, intent: str, company: Company, campaign: str) -> str:
    query = {
        "source": "founder_outbound",
        "medium": "email",
        "platform": "direct",
        "campaign": campaign,
        "intent": intent,
        "workflow": company.slug,
    }
    return f"https://tinyzkp.com{path}?" + urllib.parse.urlencode(query)


def target_record(company: Company, score: int, signals: list[str], campaign: str) -> dict[str, Any]:
    route = recommended_route(company, signals)
    return {
        "id": f"yc_{company.slug}",
        "company": company.name,
        "website": company.website,
        "yc_url": company.yc_url,
        "source_url": company.source_url,
        "batch": company.batch_name,
        "team_size": company.team_size,
        "year_founded": company.year_founded,
        "location": company.location,
        "tags": company.tags,
        "one_liner": company.one_liner,
        "score": score,
        "signals": signals,
        "recommended_route": route,
        "contact_research_status": "needs_manual_founder_or_engineering_contact",
        "fit_reason": hook_for(company, signals),
        "tracked_urls": {
            "learn": tinyzkp_url("/", intent="learn", company=company, campaign=campaign),
            "fit": tinyzkp_url("/fit", intent="find_route", company=company, campaign=campaign),
            "calculator": tinyzkp_url("/calculator", intent="calculator", company=company, campaign=campaign),
            "pilot": tinyzkp_url("/pilot", intent="paid_pilot_checkout", company=company, campaign=campaign),
            "signup": tinyzkp_url("/signup", intent="api_key", company=company, campaign=campaign),
        },
        "email_draft": {
            "subject": f"verifiable receipts for {company.name}?",
            "first_line": f"I looked at {company.name}. {company.one_liner}",
            "hook": hook_for(company, signals),
        },
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# TinyZKP Founder Outbound Targets",
        "",
        f"Generated: `{payload['generated_at']}`",
        "",
        "This is a company-level target list for manual founder-led outbound. It deliberately excludes personal email addresses and automated-send instructions.",
        "",
        "| Rank | Company | Score | Route | Hook | Tracked CTA |",
        "|---:|---|---:|---|---|---|",
    ]
    for idx, target in enumerate(payload["targets"], start=1):
        company = str(target["company"]).replace("|", "\\|")
        route = str(target["recommended_route"])
        hook = str(target["fit_reason"]).replace("|", "\\|")
        cta = target["tracked_urls"]["pilot"] if route == "paid_pilot" else target["tracked_urls"]["fit"]
        lines.append(f"| {idx} | [{company}]({target['yc_url']}) | {target['score']} | `{route}` | {hook} | [CTA]({cta}) |")
    lines.extend(
        [
            "",
            "## Operating Rules",
            "",
            "- Manually verify the company still fits before sending.",
            "- Research exactly one founder or lead engineer; do not use generic `info@` or `hello@` inboxes.",
            "- Send one human email and one follow-up only.",
            "- Preserve the source-tagged CTA URLs from this file.",
        ]
    )
    return "\n".join(lines) + "\n"


def generate(sources: list[str], *, timeout: float, limit: int, min_score: int, campaign: str) -> dict[str, Any]:
    deduped: dict[str, Company] = {}
    source_counts: dict[str, int] = {}
    for source_url in sources:
        text = fetch_text(source_url, timeout)
        companies = companies_from_html(source_url, text)
        source_counts[source_url] = len(companies)
        for company in companies:
            deduped.setdefault(company.slug, company)

    scored: list[tuple[int, list[str], Company]] = []
    for company in deduped.values():
        score, signals = score_company(company)
        if score >= min_score:
            scored.append((score, signals, company))

    scored.sort(key=lambda item: (-item[0], item[2].team_size or 9999, item[2].name.lower()))
    targets = [target_record(company, score, signals, campaign) for score, signals, company in scored[:limit]]
    return {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "campaign": campaign,
        "source_urls": sources,
        "source_counts": source_counts,
        "criteria": {
            "min_score": min_score,
            "limit": limit,
            "signals": SIGNAL_KEYWORDS,
            "negative_keywords": sorted(NEGATIVE_KEYWORDS),
        },
        "targets": targets,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", action="append", dest="sources", help="Public directory URL to scrape; repeatable")
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--md-output", type=Path, default=DEFAULT_MD)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--min-score", type=int, default=MIN_SCORE)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--campaign", default="yc_agent_outbound")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    sources = args.sources or DEFAULT_SOURCES
    payload = generate(sources, timeout=args.timeout, limit=args.limit, min_score=args.min_score, campaign=args.campaign)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.md_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    args.md_output.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Generated {len(payload['targets'])} outbound target(s) -> {args.json_output}")
        print(f"Rendered markdown -> {args.md_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
