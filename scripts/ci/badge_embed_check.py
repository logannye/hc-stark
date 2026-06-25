#!/usr/bin/env python3
"""Validate the Verified by TinyZKP badge embed contract and snippets."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = Path("site/.well-known/tinyzkp-badge.json")
SCHEMA = Path("site/schemas/tinyzkp-badge.schema.json")
BADGE_PAGE = Path("site/badges.html")
RECIPES_PAGE = Path("site/recipes.html")
SVG = Path("site/badges/verified-by-tinyzkp.svg")
DISCOVERY = Path("site/discovery.json")
INTEGRATIONS = Path("site/integrations.json")
LLMS = Path("site/llms.txt")
ROBOTS = Path("site/robots.txt")


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def tinyzkp_url(value: object, *, label: str) -> str | None:
    if not isinstance(value, str):
        return f"{label} must be a URL string"
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.netloc != "tinyzkp.com":
        return f"{label} must be an https://tinyzkp.com URL"
    if not parsed.path.startswith("/"):
        return f"{label} must include an absolute path"
    return None


def validate_contract(root: Path) -> Check:
    failures: list[str] = []
    contract_path = root / CONTRACT
    schema_path = root / SCHEMA
    if not contract_path.is_file():
        return Check("FAIL", str(CONTRACT), "missing badge contract")
    if not schema_path.is_file():
        failures.append(f"{SCHEMA} is missing")

    contract = load_json(contract_path)
    load_json(schema_path)
    if not isinstance(contract, dict):
        return Check("FAIL", str(CONTRACT), "contract must be a JSON object")

    if contract.get("$schema") != "https://tinyzkp.com/schemas/tinyzkp-badge.schema.json":
        failures.append("contract $schema must point to tinyzkp-badge.schema.json")
    if contract.get("canonical_url") != "https://tinyzkp.com/.well-known/tinyzkp-badge.json":
        failures.append("canonical_url must be the TinyZKP well-known badge URL")
    if contract.get("status") != "live":
        failures.append("status must be live")
    if contract.get("docs_url") != "https://tinyzkp.com/badges":
        failures.append("docs_url must be https://tinyzkp.com/badges")

    asset = contract.get("badge_asset") if isinstance(contract.get("badge_asset"), dict) else {}
    expected_asset = {
        "url": "https://tinyzkp.com/badges/verified-by-tinyzkp.svg",
        "media_type": "image/svg+xml",
        "width": 202,
        "height": 32,
        "alt": "Verified by TinyZKP",
    }
    for key, expected in expected_asset.items():
        if asset.get(key) != expected:
            failures.append(f"badge_asset.{key} must be {expected!r}")

    embed = str(contract.get("default_embed_html", ""))
    for marker in (
        "https://tinyzkp.com/verify?",
        "source=verified_badge",
        "medium={medium}",
        "intent=verify_receipt",
        "#proof={base64url_json_proof}",
        "https://tinyzkp.com/badges/verified-by-tinyzkp.svg",
        "alt=\"Verified by TinyZKP\"",
    ):
        if marker not in embed:
            failures.append(f"default_embed_html missing {marker!r}")

    media = contract.get("allowed_media")
    if not isinstance(media, list) or "embed" not in media or "agent_output" not in media:
        failures.append("allowed_media must include embed and agent_output")

    link_policy = contract.get("link_policy") if isinstance(contract.get("link_policy"), dict) else {}
    preferred = str(link_policy.get("preferred_verifier_url", ""))
    if "source=verified_badge" not in preferred or "intent=verify_receipt" not in preferred:
        failures.append("link_policy.preferred_verifier_url must preserve badge attribution")
    if link_policy.get("do_not_link_directly_to_asset_only") is not True:
        failures.append("link_policy must forbid asset-only badge links")

    attribution = contract.get("attribution") if isinstance(contract.get("attribution"), dict) else {}
    if attribution.get("required_source") != "verified_badge":
        failures.append("attribution.required_source must be verified_badge")
    if attribution.get("recommended_intent") != "verify_receipt":
        failures.append("attribution.recommended_intent must be verify_receipt")
    ctas = attribution.get("conversion_ctas") if isinstance(attribution.get("conversion_ctas"), dict) else {}
    for key in ("signup", "mcp", "receipts"):
        error = tinyzkp_url(ctas.get(key), label=f"attribution.conversion_ctas.{key}")
        if error:
            failures.append(error)
            continue
        query = parse_qs(urlparse(ctas[key]).query)
        if query.get("source") != ["verified_badge"]:
            failures.append(f"attribution.conversion_ctas.{key} must include source=verified_badge")

    boundaries = " ".join(str(item).lower() for item in contract.get("data_boundaries", []))
    for marker in ("transparent", "secrets", "private customer data", "verifier"):
        if marker not in boundaries:
            failures.append(f"data_boundaries must mention {marker!r}")

    related = contract.get("related_assets") if isinstance(contract.get("related_assets"), dict) else {}
    for key in ("receipt_share_contract", "verifier", "receipts", "integrations", "schema"):
        error = tinyzkp_url(related.get(key), label=f"related_assets.{key}")
        if error:
            failures.append(error)

    return Check(
        "FAIL" if failures else "PASS",
        str(CONTRACT),
        "; ".join(failures) if failures else "badge contract is valid",
    )


def validate_public_links(root: Path) -> Check:
    failures: list[str] = []
    marker = ".well-known/tinyzkp-badge.json"
    for rel_path in (DISCOVERY, INTEGRATIONS, LLMS, ROBOTS, BADGE_PAGE):
        path = root / rel_path
        if not path.is_file():
            failures.append(f"{rel_path} is missing")
            continue
        if marker not in path.read_text(encoding="utf-8"):
            failures.append(f"{rel_path} does not link the badge contract")
    return Check(
        "FAIL" if failures else "PASS",
        "public badge discovery links",
        "; ".join(failures) if failures else "badge contract is discoverable",
    )


def validate_embed_snippets(root: Path) -> Check:
    failures: list[str] = []
    required_markers = [
        "https://tinyzkp.com/verify?source=verified_badge&amp;medium=embed&amp;intent=verify_receipt#proof=...",
        "rel=\"noopener\"",
        "https://tinyzkp.com/badges/verified-by-tinyzkp.svg",
        "alt=\"Verified by TinyZKP\"",
    ]
    for rel_path in (BADGE_PAGE, RECIPES_PAGE):
        path = root / rel_path
        if not path.is_file():
            failures.append(f"{rel_path} is missing")
            continue
        text = path.read_text(encoding="utf-8")
        missing = [marker for marker in required_markers if marker not in text]
        if missing:
            failures.append(f"{rel_path} missing markers: {', '.join(missing)}")

    svg_path = root / SVG
    if not svg_path.is_file():
        failures.append(f"{SVG} is missing")
    else:
        svg = svg_path.read_text(encoding="utf-8")
        for marker in (
            'width="202"',
            'height="32"',
            "Verified by TinyZKP",
            "receipt verification result",
        ):
            if marker not in svg:
                failures.append(f"{SVG} missing marker: {marker}")

    return Check(
        "FAIL" if failures else "PASS",
        "badge embed snippets",
        "; ".join(failures) if failures else "badge snippets preserve verifier attribution",
    )


def validate(root: Path = ROOT) -> list[Check]:
    root = root.resolve()
    return [
        validate_contract(root),
        validate_public_links(root),
        validate_embed_snippets(root),
    ]


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} badge embed check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll badge embed checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
