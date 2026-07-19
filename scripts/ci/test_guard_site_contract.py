#!/usr/bin/env python3
"""Contract tests for the static, fail-closed TinyZKP Guard site."""

from __future__ import annotations

import json
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
LAUNCH_GATE = ROOT / "release" / "guard-launch-gates-v1.json"

PUBLIC_PAGES = {
    "index.html",
    "guard.html",
    "compatibility.html",
    "benchmarks.html",
    "pricing.html",
    "docs.html",
    "security.html",
    "releases.html",
    "support.html",
    "terms.html",
    "privacy.html",
    "refunds.html",
    "eula.html",
}


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class CheckoutParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.checkout_controls: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if "data-checkout" in attributes:
            self.checkout_controls.append(attributes)


def test_public_page_set_is_exact() -> None:
    assert {path.name for path in SITE.glob("*.html")} == PUBLIC_PAGES


def test_checkout_is_consistently_fail_closed() -> None:
    gate = load_json(LAUNCH_GATE)
    commerce = load_json(SITE / "commerce.json")
    pricing = load_json(SITE / "pricing.json")
    release = load_json(SITE / "release.json")

    assert gate["checkout_enabled"] is False
    assert commerce["checkout_enabled"] is False
    assert commerce["launch_gate_status"] == "blocked"
    assert pricing["checkout_enabled"] is False
    assert release["checkout_enabled"] is False
    assert release["status"] == gate["status"] == "blocked"
    assert set(release["blocking_gates"]) == set(gate["blocking_gates"])
    assert release["gate_status"] == gate["gate_status"]
    for variant in commerce["variants"].values():
        assert variant == {"reviewed": False, "checkout_url": None}


def test_homepage_describes_the_blocked_launch_state_unambiguously() -> None:
    homepage = (SITE / "index.html").read_text(encoding="utf-8")
    assert "Closed pending evidence" in homepage
    assert "Evidence gates open" not in homepage


def test_checkout_urls_cannot_be_in_page_markup() -> None:
    controls = []
    for page in sorted(PUBLIC_PAGES):
        parser = CheckoutParser()
        parser.feed((SITE / page).read_text(encoding="utf-8"))
        controls.extend((page, attributes) for attributes in parser.checkout_controls)

    assert controls, "site must expose visibly closed Guard purchase controls"
    for page, attributes in controls:
        assert attributes.get("href") is None, f"{page} hardcodes a checkout href"
        assert attributes.get("data-closed-label") in {"Not yet for sale", "Monthly not yet for sale"}


def test_pricing_has_only_community_and_guard() -> None:
    pricing = load_json(SITE / "pricing.json")
    assert [product["id"] for product in pricing["products"]] == ["community", "guard"]
    assert pricing["products"][0]["price_usd"] == 0
    assert pricing["products"][1]["prices"] == {
        "monthly_usd": 499,
        "annual_usd": 4990,
        "annual_recommended": True,
    }
    assert pricing["hosted_proving"] is False
    assert pricing["usage_metering"] is False


def test_machine_assets_are_json_and_public_contracts_have_ids() -> None:
    for name in (
        "pricing.json",
        "discovery.json",
        "commerce.json",
        "compatibility.json",
        "release.json",
        "offers.jsonld",
    ):
        load_json(SITE / name)

    for name in (
        "job-manifest-v1.schema.json",
        "doctor-report-v1.schema.json",
        "compatibility-report-v1.schema.json",
        "reason-v1.schema.json",
        "error-envelope-v1.schema.json",
        "progress-event-v1.schema.json",
        "job-result-v1.schema.json",
        "support-report-v1.schema.json",
        "job-inspect-result-v1.schema.json",
        "guard-channel-v1.schema.json",
        "guard-release-index-v1.schema.json",
        "policy-baseline-v1.schema.json",
        "compatibility-manifest-v1.schema.json",
    ):
        schema = load_json(SITE / "schemas" / name)
        assert schema["$id"] == f"https://tinyzkp.com/schemas/{name}"


def test_compatibility_profile_id_is_canonical_across_contracts() -> None:
    profile_id = "tinyzkp-p3-goldilocks-v1"
    assert load_json(SITE / "compatibility.json")["profile"] == profile_id
    assert load_json(SITE / "release.json")["compatibility_profile"] == profile_id
    assert load_json(SITE / "schemas" / "compatibility-report-v1.schema.json")["$defs"]["CompatibilityManifestV1"]["properties"]["profile"]["const"] == profile_id
    assert load_json(SITE / "schemas" / "compatibility-manifest-v1.schema.json")["properties"]["profile"]["const"] == profile_id
    assert load_json(SITE / "schemas" / "job-manifest-v1.schema.json")["properties"]["compatibility_profile"]["const"] == profile_id
    assert load_json(SITE / "schemas" / "job-result-v1.schema.json")["$defs"]["ReleaseIdentityV1"]["properties"]["compatibility_profile"]["const"] == profile_id
    assert load_json(SITE / "schemas" / "guard-channel-v1.schema.json")["properties"]["compatibility_profile"]["const"] == profile_id


def test_dynamic_and_legacy_business_surfaces_are_absent() -> None:
    assert not (SITE / "functions").exists() or not any((SITE / "functions").rglob("*.js"))
    for name in ("analytics.js", "openapi.json", "contact.html", "requests.html", "status.html", "engine.html", "plonky3.html"):
        assert not (SITE / name).exists()

    published = "\n".join(path.read_text(encoding="utf-8") for path in SITE.glob("*.html")).lower()
    for stale in ("tinyzkp certified", "fleet / oem", "$25k", "$40k", "$60k", "$125k", "proof credits"):
        assert stale not in published


def test_no_checkout_host_or_contact_backend_is_hardcoded() -> None:
    pages = "\n".join(path.read_text(encoding="utf-8") for path in SITE.glob("*.html"))
    assert "lemonsqueezy.com/buy/" not in pages
    assert "/api/contact" not in pages
    assert "/api/events" not in pages
