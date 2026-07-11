#!/usr/bin/env python3
"""Validate and render the no-email design-partner research dossier."""

from __future__ import annotations

import argparse
from datetime import date, datetime
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse


MAX_BYTES = 1024 * 1024
STATUS = "research_only_blocked_until_live_no_email_canary"
ALLOWED_SIGNALS = {
    "direct_plonky3_use",
    "direct_plonky3_use_via_openvm",
    "public_memory_pressure",
}
ALLOWED_ROUTES = {"github_discussions", "github_issues"}
TOP_LEVEL_KEYS = {"schema_version", "generated_on", "status", "policy", "prospects"}
POLICY_KEYS = {
    "contact_scope",
    "personal_names_collected",
    "personal_emails_collected",
    "messages_sent",
    "outreach_blocker",
    "permitted_routes",
    "prohibited_actions",
}
PROSPECT_KEYS = {
    "rank",
    "id",
    "company_project",
    "public_repo",
    "repository_observed",
    "evidence",
    "fit_hypothesis",
    "qualification_gaps",
    "public_non_email_route",
    "status",
}
REPOSITORY_KEYS = {"date_checked", "archived", "updated_at"}
EVIDENCE_KEYS = {"signal", "url", "title", "date_checked", "summary", "supporting_urls"}
ROUTE_KEYS = {"kind", "url", "use_policy"}
EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
REPO_PATTERN = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def _exact_keys(value: object, expected: set[str], label: str, failures: list[str]) -> bool:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return False
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        failures.append(f"{label} keys differ; missing={missing}, extra={extra}")
        return False
    return True


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_date(value: object, label: str, failures: list[str]) -> None:
    if not isinstance(value, str):
        failures.append(f"{label} must be an ISO date")
        return
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        failures.append(f"{label} must be an ISO date")
        return
    if parsed > date.today():
        failures.append(f"{label} cannot be in the future")


def _validate_timestamp(value: object, label: str, failures: list[str]) -> None:
    if not isinstance(value, str):
        failures.append(f"{label} must be an ISO timestamp")
        return
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        failures.append(f"{label} must be an ISO timestamp")


def _validate_github_url(value: object, label: str, failures: list[str]) -> None:
    if not isinstance(value, str):
        failures.append(f"{label} must be an HTTPS GitHub URL")
        return
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com" or not parsed.path:
        failures.append(f"{label} must be an HTTPS GitHub URL")


def _walk_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def validate(payload: dict[str, object]) -> list[str]:
    failures: list[str] = []
    if not _exact_keys(payload, TOP_LEVEL_KEYS, "dossier", failures):
        return failures
    if payload.get("schema_version") != 1:
        failures.append("schema_version must be 1")
    _validate_date(payload.get("generated_on"), "generated_on", failures)
    if payload.get("status") != STATUS:
        failures.append(f"top-level status must be {STATUS}")

    policy = payload.get("policy")
    if _exact_keys(policy, POLICY_KEYS, "policy", failures):
        assert isinstance(policy, dict)
        if policy.get("contact_scope") != "organization_level_public_routes_only":
            failures.append("contact_scope must remain organization-level and public-only")
        for field in ("personal_names_collected", "personal_emails_collected", "messages_sent"):
            if policy.get(field) is not False:
                failures.append(f"policy.{field} must be false")
        if policy.get("outreach_blocker") != "live_no_email_canary":
            failures.append("policy.outreach_blocker must be live_no_email_canary")
        if policy.get("permitted_routes") != ["github_discussions", "github_issues"]:
            failures.append("policy.permitted_routes must contain only the two reviewed GitHub routes")
        prohibited = policy.get("prohibited_actions")
        if not isinstance(prohibited, list) or "send_messages_before_live_no_email_canary" not in prohibited:
            failures.append("policy must explicitly prohibit messages before the live no-email canary")

    prospects = payload.get("prospects")
    if not isinstance(prospects, list):
        failures.append("prospects must be an array")
        prospects = []
    if len(prospects) != 10:
        failures.append("prospects must contain exactly 10 records")

    seen_ids: set[str] = set()
    seen_repos: set[str] = set()
    ranks: list[int] = []
    for index, prospect in enumerate(prospects, start=1):
        label = f"prospect[{index}]"
        if not _exact_keys(prospect, PROSPECT_KEYS, label, failures):
            continue
        assert isinstance(prospect, dict)
        rank = prospect.get("rank")
        if not isinstance(rank, int) or isinstance(rank, bool):
            failures.append(f"{label}.rank must be an integer")
        else:
            ranks.append(rank)
        prospect_id = prospect.get("id")
        if not isinstance(prospect_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", prospect_id):
            failures.append(f"{label}.id must be a kebab-case identifier")
        elif prospect_id in seen_ids:
            failures.append(f"{label}.id must be unique")
        else:
            seen_ids.add(prospect_id)
        if not _is_nonempty_string(prospect.get("company_project")):
            failures.append(f"{label}.company_project must be non-empty")
        repo = prospect.get("public_repo")
        _validate_github_url(repo, f"{label}.public_repo", failures)
        if isinstance(repo, str):
            if not REPO_PATTERN.fullmatch(repo):
                failures.append(f"{label}.public_repo must be a repository root URL")
            elif repo in seen_repos:
                failures.append(f"{label}.public_repo must be unique")
            else:
                seen_repos.add(repo)
        if prospect.get("status") != STATUS:
            failures.append(f"{label}.status must be {STATUS}")

        observed = prospect.get("repository_observed")
        if _exact_keys(observed, REPOSITORY_KEYS, f"{label}.repository_observed", failures):
            assert isinstance(observed, dict)
            _validate_date(observed.get("date_checked"), f"{label}.repository_observed.date_checked", failures)
            if observed.get("archived") is not False:
                failures.append(f"{label} must refer to a repository observed as active")
            _validate_timestamp(observed.get("updated_at"), f"{label}.repository_observed.updated_at", failures)

        evidence = prospect.get("evidence")
        if _exact_keys(evidence, EVIDENCE_KEYS, f"{label}.evidence", failures):
            assert isinstance(evidence, dict)
            if evidence.get("signal") not in ALLOWED_SIGNALS:
                failures.append(f"{label}.evidence.signal is unsupported")
            _validate_github_url(evidence.get("url"), f"{label}.evidence.url", failures)
            _validate_date(evidence.get("date_checked"), f"{label}.evidence.date_checked", failures)
            for field in ("title", "summary"):
                if not _is_nonempty_string(evidence.get(field)):
                    failures.append(f"{label}.evidence.{field} must be non-empty")
            supporting = evidence.get("supporting_urls")
            if not isinstance(supporting, list):
                failures.append(f"{label}.evidence.supporting_urls must be an array")
            else:
                for url_index, url in enumerate(supporting):
                    _validate_github_url(url, f"{label}.evidence.supporting_urls[{url_index}]", failures)

        if not _is_nonempty_string(prospect.get("fit_hypothesis")):
            failures.append(f"{label}.fit_hypothesis must be non-empty")
        gaps = prospect.get("qualification_gaps")
        if not isinstance(gaps, list) or len(gaps) < 3 or not all(_is_nonempty_string(gap) for gap in gaps):
            failures.append(f"{label}.qualification_gaps must contain at least three non-empty items")

        route = prospect.get("public_non_email_route")
        if _exact_keys(route, ROUTE_KEYS, f"{label}.public_non_email_route", failures):
            assert isinstance(route, dict)
            if route.get("kind") not in ALLOWED_ROUTES:
                failures.append(f"{label}.public_non_email_route.kind is unsupported")
            _validate_github_url(route.get("url"), f"{label}.public_non_email_route.url", failures)
            use_policy = route.get("use_policy")
            if not isinstance(use_policy, str) or "after the live no-email canary" not in use_policy:
                failures.append(f"{label}.public_non_email_route must remain blocked until the canary")
            elif "unsolicited sales" not in use_policy:
                failures.append(f"{label}.public_non_email_route must prohibit unsolicited sales")

    if ranks != list(range(1, 11)):
        failures.append("prospect ranks must be exactly 1 through 10 in order")

    serialized = json.dumps(payload, sort_keys=True)
    if "mailto:" in serialized.lower() or "@" in serialized or EMAIL_PATTERN.search(serialized):
        failures.append("dossier must not contain mail routes or address-like contact data")
    forbidden_identity_keys = {"person", "personal_name", "contact_name", "handle", "account_owner"}
    if forbidden_identity_keys & set(_walk_strings(payload)):
        failures.append("dossier must not contain personal identity fields")
    return failures


def render_markdown(payload: dict[str, object]) -> str:
    prospects = payload["prospects"]
    assert isinstance(prospects, list)
    lines = [
        "# No-email design-partner prospect research",
        "",
        f"> Status: `{payload['status']}`",
        ">",
        f"> Evidence checked: `{payload['generated_on']}`",
        "",
        "This is organization-level research, not an outreach list or pipeline. No personal names or addresses were collected and no messages were sent. Every route remains blocked until the live no-email canary passes; repository issues must never be used for unsolicited sales.",
        "",
        "## Candidates",
        "",
    ]
    route_labels = {"github_discussions": "GitHub Discussions", "github_issues": "GitHub Issues"}
    for prospect in prospects:
        assert isinstance(prospect, dict)
        evidence = prospect["evidence"]
        route = prospect["public_non_email_route"]
        gaps = prospect["qualification_gaps"]
        assert isinstance(evidence, dict) and isinstance(route, dict) and isinstance(gaps, list)
        lines.extend(
            [
                f"### {prospect['rank']}. [{prospect['company_project']}]({prospect['public_repo']})",
                "",
                f"- Evidence: [{evidence['title']}]({evidence['url']}) — {evidence['summary']}",
                f"- Fit hypothesis: {prospect['fit_hypothesis']}",
                f"- Qualification gaps: {'; '.join(str(gap) for gap in gaps)}.",
                f"- Public route after canary: [{route_labels[str(route['kind'])]}]({route['url']}). {route['use_policy']}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dossier", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args(argv)
    summary_path = args.summary or args.dossier.with_suffix(".md")
    failures: list[str] = []
    try:
        if args.dossier.stat().st_size > MAX_BYTES:
            raise ValueError("dossier exceeds 1 MiB")
        payload = json.loads(args.dossier.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("dossier must contain a JSON object")
        failures.extend(validate(payload))
        if not failures:
            expected = render_markdown(payload)
            actual = summary_path.read_text(encoding="utf-8")
            if actual != expected:
                failures.append(f"summary drift: regenerate {summary_path}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        failures.append(str(exc))
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1
    print("PASS  no-email prospect dossier is blocked, evidence-backed, and summary-synchronized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
