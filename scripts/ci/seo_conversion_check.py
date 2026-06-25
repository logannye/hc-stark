#!/usr/bin/env python3
"""Validate priority SEO pages have measurable conversion paths."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]
SITEMAP = Path("site/sitemap.xml")
LLMS = Path("site/llms.txt")

CONVERSION_PATHS = {
    "/try",
    "/verify",
    "/signup",
    "/fit",
    "/pricing",
    "/pilot",
    "/mcp",
    "/contact",
}


@dataclass(frozen=True)
class Surface:
    file: Path
    route: str
    expected_source: str
    primary_intents: tuple[str, ...]


PRIORITY_SURFACES = (
    Surface(Path("site/agents.html"), "/agents", "agents_hero", ("mcp_install", "try_receipt")),
    Surface(Path("site/agent-platforms.html"), "/agent-platforms", "agent_platforms_hero", ("platform_rollout", "mcp_install")),
    Surface(Path("site/verifiable-agent-output.html"), "/verifiable-agent-output", "verifiable_agent_output", ("try_receipt",)),
    Surface(Path("site/agent-audit-trails.html"), "/agent-audit-trails", "agent_audit_trails", ("paid_pilot",)),
    Surface(Path("site/receipts.html"), "/receipts", "receipts_page", ("try_receipt", "verify_receipt")),
    Surface(Path("site/use-cases/offline-proof-verification.html"), "/use-cases/offline-proof-verification", "offline_verification", ("verify_receipt",)),
    Surface(Path("site/use-cases/post-quantum-stark-proving.html"), "/use-cases/post-quantum-stark-proving", "post_quantum_stark", ("try_receipt",)),
    Surface(Path("site/compare/self-hosted-stark-prover.html"), "/compare/self-hosted-stark-prover", "self_hosted_compare", ("try_receipt", "engineering_review")),
    Surface(Path("site/integrations/openai-agents.html"), "/integrations/openai-agents", "integration_openai_agents", ("free_signup", "find_route", "paid_pilot")),
    Surface(Path("site/pricing.html"), "/pricing", "pricing_hero", ("free_signup", "find_route")),
    Surface(Path("site/calculator.html"), "/calculator", "calculator", ("recommended_plan", "paid_pilot")),
    Surface(Path("site/fit.html"), "/fit", "fit_result", ("free_signup", "contact_summary")),
    Surface(Path("site/pilot.html"), "/pilot", "pilot_hero", ("paid_pilot_contact", "paid_pilot_checkout")),
    Surface(Path("site/platform-rollout.html"), "/platform-rollout", "platform_rollout_hero", ("platform_rollout_contact", "paid_pilot")),
    Surface(Path("site/enterprise.html"), "/enterprise", "enterprise_hero", ("enterprise_review",)),
)


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        data = {key.lower(): value or "" for key, value in attrs}
        self.links.append(data)


def title_ok(text: str) -> bool:
    return bool(re.search(r"<title>[^<]{12,}</title>", text, re.IGNORECASE))


def description_ok(text: str) -> bool:
    return bool(re.search(r'<meta\s+name="description"\s+content="[^"]{50,}"', text, re.IGNORECASE))


def h1_ok(text: str) -> bool:
    return bool(re.search(r"<h1\b[^>]*>.*?</h1>", text, re.IGNORECASE | re.DOTALL))


def is_cta_link(link: dict[str, str]) -> bool:
    return "cta" in link.get("class", "").split()


def conversion_path(href: str) -> str:
    return urlparse(href).path.rstrip("/") or "/"


def validate_surface(root: Path, surface: Surface, sitemap: str, llms: str) -> Check:
    path = root / surface.file
    if not path.is_file():
        return Check("FAIL", str(surface.file), "missing priority SEO page")

    text = path.read_text(encoding="utf-8")
    failures: list[str] = []
    if not title_ok(text):
        failures.append("missing descriptive <title>")
    if not description_ok(text):
        failures.append("missing descriptive meta description")
    if not h1_ok(text):
        failures.append("missing primary h1")

    canonical = f"https://tinyzkp.com{surface.route}"
    if canonical not in sitemap:
        failures.append("route missing from sitemap.xml")
    if canonical not in llms:
        failures.append("route missing from llms.txt")

    parser = LinkParser()
    parser.feed(text)
    measurable = False
    untagged_conversion_ctas: list[str] = []
    for link in parser.links:
        if not is_cta_link(link):
            continue
        href = link.get("href", "")
        path_only = conversion_path(href)
        if path_only not in CONVERSION_PATHS:
            continue
        query = parse_qs(urlparse(href).query)
        source = query.get("source", [""])[0]
        medium = query.get("medium", [""])[0]
        intent = query.get("intent", [""])[0]
        if not source or not medium or not intent or not link.get("data-track") or not link.get("data-source"):
            untagged_conversion_ctas.append(href)
            continue
        if (
            source == surface.expected_source
            and link.get("data-source") == surface.expected_source
            and intent in surface.primary_intents
        ):
            measurable = True

    if untagged_conversion_ctas:
        failures.append("CTA conversion links must include source, medium, intent, data-track, and data-source: " + ", ".join(untagged_conversion_ctas))
    if not measurable:
        failures.append(f"missing measurable conversion CTA for source={surface.expected_source}")

    return Check(
        "FAIL" if failures else "PASS",
        str(surface.file),
        "; ".join(failures) if failures else "priority SEO page has measurable conversion CTA",
    )


def validate(root: Path = ROOT) -> list[Check]:
    root = root.resolve()
    sitemap_path = root / SITEMAP
    llms_path = root / LLMS
    checks: list[Check] = []
    if not sitemap_path.is_file():
        checks.append(Check("FAIL", str(SITEMAP), "missing sitemap"))
        sitemap = ""
    else:
        sitemap = sitemap_path.read_text(encoding="utf-8")
    if not llms_path.is_file():
        checks.append(Check("FAIL", str(LLMS), "missing llms.txt"))
        llms = ""
    else:
        llms = llms_path.read_text(encoding="utf-8")

    checks.extend(validate_surface(root, surface, sitemap, llms) for surface in PRIORITY_SURFACES)
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} SEO conversion check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll SEO conversion checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
