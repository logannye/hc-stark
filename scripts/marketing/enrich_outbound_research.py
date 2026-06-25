#!/usr/bin/env python3
"""Build contact-safe research packets for founder-led outbound.

This script fetches company-level public pages only. It does not discover,
store, or send to personal email addresses. Generated packets are meant to
shorten manual founder/engineering-contact research while preserving the
one-human-email operating rule in the outbound send queue.
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
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_QUEUE = ROOT / "marketing" / "generated" / "outbound_send_queue.json"
DEFAULT_JSON = ROOT / "marketing" / "generated" / "outbound_research_packets.json"
DEFAULT_MD = ROOT / "marketing" / "generated" / "outbound_research_packets.md"

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
WHITESPACE_RE = re.compile(r"\s+")
CONTACT_WORDS = ("contact", "demo", "pilot", "sales")
ABOUT_WORDS = ("about", "team", "company")
PRODUCT_WORDS = ("pricing", "docs", "developers", "platform", "security", "customers", "use-cases")
MAX_BODY_BYTES = 400_000


@dataclass(frozen=True)
class PageSummary:
    url: str
    status: str
    title: str = ""
    description: str = ""
    contact_urls: tuple[str, ...] = ()
    about_urls: tuple[str, ...] = ()
    product_urls: tuple[str, ...] = ()
    error: str = ""


class HeadParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.in_title = False
        self.title_parts: list[str] = []
        self.description = ""
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key.lower(): value or "" for key, value in attrs}
        if tag == "title":
            self.in_title = True
            return
        if tag == "meta" and attrs_map.get("name", "").lower() in {"description", "og:description"}:
            if not self.description:
                self.description = clean_text(attrs_map.get("content", ""))
            return
        if tag != "a":
            return
        href = attrs_map.get("href", "").strip()
        if not href or href.lower().startswith(("mailto:", "tel:", "javascript:")):
            return
        text = clean_text(attrs_map.get("aria-label") or attrs_map.get("title") or "")
        url = urllib.parse.urljoin(self.base_url, href)
        if is_safe_public_url(url):
            self.links.append((url, text))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return clean_text(" ".join(self.title_parts))


def clean_text(value: str, *, limit: int = 220) -> str:
    value = html.unescape(value or "")
    value = EMAIL_RE.sub("[redacted-email]", value)
    value = WHITESPACE_RE.sub(" ", value).strip()
    return value[:limit].rstrip()


def is_safe_public_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        return False
    if EMAIL_RE.search(value):
        return False
    return True


def same_site(base_url: str, candidate: str) -> bool:
    base_host = urllib.parse.urlparse(base_url).netloc.removeprefix("www.")
    candidate_host = urllib.parse.urlparse(candidate).netloc.removeprefix("www.")
    return bool(base_host and candidate_host and base_host == candidate_host)


def classify_links(base_url: str, links: list[tuple[str, str]], words: tuple[str, ...], limit: int = 3) -> tuple[str, ...]:
    matches: list[str] = []
    for url, text in links:
        if not same_site(base_url, url):
            continue
        haystack = f"{urllib.parse.urlparse(url).path} {text}".lower()
        if any(word in haystack for word in words) and url not in matches:
            matches.append(url)
        if len(matches) >= limit:
            break
    return tuple(matches)


def fetch_page(url: str, *, timeout: float) -> PageSummary:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "TinyZKP-Outbound-Research/1.0 (+https://tinyzkp.com/contact)",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
    except Exception as exc:
        return PageSummary(url=url, status="fetch_failed", error=clean_text(str(exc), limit=160))
    parser = HeadParser(final_url)
    try:
        parser.feed(body)
    except Exception as exc:
        return PageSummary(url=final_url, status="parse_failed", error=clean_text(str(exc), limit=160))
    return PageSummary(
        url=final_url,
        status="ok",
        title=parser.title,
        description=parser.description,
        contact_urls=classify_links(final_url, parser.links, CONTACT_WORDS),
        about_urls=classify_links(final_url, parser.links, ABOUT_WORDS),
        product_urls=classify_links(final_url, parser.links, PRODUCT_WORDS),
    )


def load_queue(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def route_guidance(route: str) -> str:
    if route == "paid_pilot":
        return "Lead with the paid pilot CTA after confirming the workflow is consequential and has a visible audit/customer-verification need."
    if route == "self_serve_developer":
        return "Lead with the free API-key CTA and ask for one developer-owned state transition to receipt."
    if route == "platform_rollout":
        return "Lead with the fit-finder CTA and frame TinyZKP as a native proof-receipt primitive for their agent platform."
    return "Lead with the fit-finder CTA and use the manual contact role to qualify fit before proposing a pilot."


def research_status(summary: PageSummary) -> str:
    if summary.status != "ok":
        return "needs_manual_website_review"
    if summary.contact_urls or summary.about_urls:
        return "company_level_research_ready"
    return "needs_manual_contact_path_review"


def packet_for(row: dict[str, Any], *, timeout: float, offline: bool) -> dict[str, Any]:
    website = str(row.get("website") or "")
    summary = PageSummary(url=website, status="offline") if offline else fetch_page(website, timeout=timeout)
    contact_urls = list(summary.contact_urls)
    about_urls = list(summary.about_urls)
    product_urls = list(summary.product_urls)
    return {
        "target_id": row.get("target_id"),
        "company": row.get("company"),
        "website": website,
        "yc_url": row.get("yc_url"),
        "recommended_route": row.get("recommended_route"),
        "contact_role": row.get("contact_role"),
        "contact_research_status": "needs_manual_founder_or_engineering_contact",
        "company_research_status": research_status(summary),
        "homepage": {
            "status": summary.status,
            "url": summary.url,
            "title": summary.title,
            "description": summary.description,
            "error": summary.error,
        },
        "public_company_links": {
            "contact": contact_urls,
            "about": about_urls,
            "product": product_urls,
        },
        "manual_research_urls": row.get("research_urls") or [],
        "route_guidance": route_guidance(str(row.get("recommended_route") or "")),
        "primary_cta": row.get("primary_cta"),
        "secondary_cta": row.get("secondary_cta"),
        "privacy_rule": "No personal emails, phone numbers, private CRM notes, or mailto links are stored in this packet.",
    }


def build_packets(queue_payload: dict[str, Any], *, limit: int, timeout: float, offline: bool) -> dict[str, Any]:
    queue = queue_payload.get("queue") or []
    packets = [packet_for(row, timeout=timeout, offline=offline) for row in queue[:limit]]
    return {
        "generated_from": "marketing/generated/outbound_send_queue.json",
        "source_campaign": queue_payload.get("source_campaign"),
        "source_generated_at": queue_payload.get("source_generated_at"),
        "privacy_rules": [
            "Company-level public pages only.",
            "Do not store personal email addresses, phone numbers, private CRM notes, or mailto links.",
            "Use packets to accelerate manual founder/engineering contact research; do not automate cold email sending.",
        ],
        "packets": packets,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# TinyZKP Outbound Research Packets",
        "",
        "Source queue: `marketing/generated/outbound_send_queue.json`",
        "",
        "## Privacy Rules",
        "",
    ]
    for rule in payload.get("privacy_rules", []):
        lines.append(f"- {rule}")
    lines.extend(["", "## Packets", ""])
    for index, packet in enumerate(payload.get("packets") or [], start=1):
        homepage = packet.get("homepage") or {}
        links = packet.get("public_company_links") or {}
        lines.extend(
            [
                f"### {index}. {packet.get('company')}",
                "",
                f"- Target ID: `{packet.get('target_id')}`",
                f"- Route: `{packet.get('recommended_route')}`",
                f"- Company research status: `{packet.get('company_research_status')}`",
                f"- Contact research status: `{packet.get('contact_research_status')}`",
                f"- Contact role: {packet.get('contact_role')}",
                f"- Website: {packet.get('website')}",
                f"- YC profile: {packet.get('yc_url')}",
                f"- Homepage status: `{homepage.get('status')}`",
            ]
        )
        if homepage.get("title"):
            lines.append(f"- Homepage title: {homepage.get('title')}")
        if homepage.get("description"):
            lines.append(f"- Homepage description: {homepage.get('description')}")
        if homepage.get("error"):
            lines.append(f"- Homepage error: {homepage.get('error')}")
        lines.extend(
            [
                f"- Route guidance: {packet.get('route_guidance')}",
                f"- Primary CTA: {packet.get('primary_cta')}",
                f"- Secondary CTA: {packet.get('secondary_cta')}",
                "- Public company links:",
            ]
        )
        for label in ("contact", "about", "product"):
            values = links.get(label) or []
            if values:
                lines.append(f"  - {label}: " + " | ".join(values))
            else:
                lines.append(f"  - {label}: none found")
        lines.extend(["- Manual research URLs:"])
        for item in packet.get("manual_research_urls") or []:
            lines.append(f"  - [{item.get('label')}]({item.get('url')}) - {item.get('purpose')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def validate_no_pii(payload: dict[str, Any], markdown: str) -> list[str]:
    failures: list[str] = []
    serialized = json.dumps(payload, sort_keys=True)
    for label, text in (("json", serialized), ("markdown", markdown)):
        if EMAIL_RE.search(text):
            failures.append(f"{label} contains an email address")
        if "mailto:" in text.lower():
            failures.append(f"{label} contains a mailto link")
    if len(payload.get("packets") or []) < 1:
        failures.append("packets must be non-empty")
    return failures


def write_outputs(payload: dict[str, Any], json_output: Path, md_output: Path) -> None:
    markdown = render_markdown(payload)
    failures = validate_no_pii(payload, markdown)
    if failures:
        raise ValueError("; ".join(failures))
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    md_output.write_text(markdown, encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--md-output", type=Path, default=DEFAULT_MD)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--offline", action="store_true", help="Skip website fetches and render packets from queue metadata only")
    parser.add_argument("--check", action="store_true", help="Validate existing packet artifacts instead of fetching websites")
    args = parser.parse_args(argv)

    if args.check:
        try:
            payload = json.loads(args.json_output.read_text(encoding="utf-8"))
            markdown = args.md_output.read_text(encoding="utf-8")
        except Exception as exc:
            print(f"FAIL outbound research packets check - {exc}", file=sys.stderr)
            return 1
        failures = validate_no_pii(payload, markdown)
        if failures:
            print("FAIL outbound research packets check - " + "; ".join(failures), file=sys.stderr)
            return 1
        print("PASS outbound research packets are contact-safe")
        return 0

    payload = build_packets(load_queue(args.queue), limit=args.limit, timeout=args.timeout, offline=args.offline)
    try:
        write_outputs(payload, args.json_output, args.md_output)
    except ValueError as exc:
        print(f"FAIL outbound research packet generation - {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {len(payload['packets'])} outbound research packet(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
