#!/usr/bin/env python3
"""Render commercial artifacts from site/pricing.json and detect drift."""

from __future__ import annotations

import argparse
from html import escape
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "site" / "pricing.json"
PRICING_HTML = ROOT / "site" / "pricing.html"
JSON_LD = ROOT / "site" / "offers.jsonld"
SALES_MATRIX = ROOT / "commercial" / "generated" / "offer-matrix.md"
BEGIN = "<!-- BEGIN GENERATED OFFERS -->"
END = "<!-- END GENERATED OFFERS -->"
PUBLIC_IDS = (
    "founding_evaluation",
    "standard_evaluation",
    "tinyzkp_certified",
    "tinyzkp_fleet_oem",
)


def money(value: int, *, suffix: str = "") -> str:
    return f"${value:,}{suffix}"


def load_source() -> dict[str, object]:
    value = json.loads(SOURCE.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("pricing source must be an object")
    return value


def validate(source: dict[str, object]) -> list[str]:
    failures: list[str] = []
    expected_flags = {
        "service_status": "backend_recovery",
        "hosted_proving_available": False,
        "hosted_verification_available": False,
        "account_creation_enabled": False,
        "checkout_enabled": False,
    }
    for field, expected in expected_flags.items():
        if source.get(field) != expected:
            failures.append(f"{field} must be {expected!r}")
    offers = source.get("offers")
    if not isinstance(offers, list):
        return failures + ["offers must be a list"]
    by_id = {offer.get("id"): offer for offer in offers if isinstance(offer, dict)}
    expected_prices = {
        "founding_evaluation": 25_000,
        "standard_evaluation": 40_000,
        "tinyzkp_certified": 60_000,
        "tinyzkp_fleet_oem": 125_000,
        "reserved_hosted_capacity": 15_000,
    }
    for offer_id, expected in expected_prices.items():
        offer = by_id.get(offer_id)
        if not isinstance(offer, dict):
            failures.append(f"missing offer {offer_id}")
            continue
        actual = offer.get("price", offer.get("minimum_price"))
        if actual != expected:
            failures.append(f"{offer_id} price must be {expected}")
    certified = by_id.get("tinyzkp_certified", {})
    if certified.get("included_support_hours_per_quarter") != 10:
        failures.append("Certified support cap must be ten hours per quarter")
    fleet = by_id.get("tinyzkp_fleet_oem", {})
    if fleet.get("custom_engineering_minimum_hourly_rate") != 300:
        failures.append("custom engineering floor must be $300/hour")
    hosted = by_id.get("reserved_hosted_capacity", {})
    if hosted.get("required_projected_gross_margin_percent") != 80:
        failures.append("hosted margin gate must be 80%")
    stripe = source.get("stripe_policy", {})
    if not isinstance(stripe, dict) or stripe.get("api_version") != "2026-02-25.clover":
        failures.append("Stripe API version must be 2026-02-25.clover")
    if isinstance(stripe, dict) and stripe.get("public_checkout") is not False:
        failures.append("public Stripe Checkout must remain disabled")
    return failures


def offers_by_id(source: dict[str, object]) -> dict[str, dict[str, object]]:
    return {
        str(offer["id"]): offer
        for offer in source["offers"]
        if isinstance(offer, dict) and "id" in offer
    }


def render_cards(source: dict[str, object]) -> str:
    offers = offers_by_id(source)
    cards: list[str] = []
    for offer_id in PUBLIC_IDS:
        offer = offers[offer_id]
        raw_price = offer.get("price", offer.get("minimum_price"))
        price = money(int(raw_price), suffix="+" if "minimum_price" in offer else "")
        deliverables = "".join(f"<li>{escape(str(item))}</li>" for item in offer["deliverables"])
        cards.append(
            f'<article class="card"><div class="kicker">{escape(str(offer["kicker"]))}</div>'
            f'<h3>{escape(str(offer["name"]))}</h3><p class="price">{price}</p>'
            f'<p class="unit">{escape(str(offer["unit"]))}</p><ul>{deliverables}</ul></article>'
        )
    return f"{BEGIN}\n" + "\n".join(cards) + f"\n{END}"


def replace_generated(html: str, rendered: str) -> str:
    if html.count(BEGIN) != 1 or html.count(END) != 1:
        raise ValueError("pricing.html must contain exactly one generated-offer marker pair")
    before, tail = html.split(BEGIN, 1)
    _, after = tail.split(END, 1)
    return before + rendered + after


def render_jsonld(source: dict[str, object]) -> str:
    items = []
    for offer_id in PUBLIC_IDS:
        offer = offers_by_id(source)[offer_id]
        price = int(offer.get("price", offer.get("minimum_price")))
        items.append({
            "@type": "Offer",
            "name": offer["name"],
            "price": str(price),
            "priceCurrency": source["currency"],
            "url": offer["contact_url"],
            "availability": "https://schema.org/LimitedAvailability",
        })
    payload = {
        "@context": "https://schema.org",
        "@type": "OfferCatalog",
        "name": source["name"],
        "url": source["url"],
        "itemListElement": items,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_sales_matrix(source: dict[str, object]) -> str:
    lines = [
        "# TinyZKP offer matrix",
        "",
        "> Generated from `site/pricing.json`; do not edit by hand.",
        "",
        "| Offer | Price | Billing | Scope control |",
        "|---|---:|---|---|",
    ]
    for offer_id in PUBLIC_IDS:
        offer = offers_by_id(source)[offer_id]
        raw_price = int(offer.get("price", offer.get("minimum_price")))
        price = money(raw_price, suffix="+" if "minimum_price" in offer else "")
        scope = (
            f"≤{offer['engineering_day_cap']} engineering days"
            if "engineering_day_cap" in offer
            else (
                f"≤{offer['included_support_hours_per_quarter']} support hours/quarter"
                if "included_support_hours_per_quarter" in offer
                else "Custom work separately scoped"
            )
        )
        lines.append(f"| {offer['name']} | {price} | {offer['billing']} | {scope} |")
    lines.extend([
        "",
        "Public checkout is disabled. Evaluations use invoicing milestones; annual agreements are prepaid `send_invoice` contracts.",
        "",
    ])
    return "\n".join(lines)


def desired_outputs(source: dict[str, object]) -> dict[Path, str]:
    pricing = PRICING_HTML.read_text(encoding="utf-8")
    return {
        PRICING_HTML: replace_generated(pricing, render_cards(source)),
        JSON_LD: render_jsonld(source),
        SALES_MATRIX: render_sales_matrix(source),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail instead of updating drifted outputs")
    args = parser.parse_args(argv)
    source = load_source()
    problems = validate(source)
    if problems:
        for problem in problems:
            print(f"FAIL  {problem}", file=sys.stderr)
        return 1
    drift: list[str] = []
    for path, desired in desired_outputs(source).items():
        actual = path.read_text(encoding="utf-8") if path.is_file() else ""
        if actual == desired:
            continue
        if args.check:
            drift.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(desired, encoding="utf-8")
            print(f"updated {path.relative_to(ROOT)}")
    if drift:
        for path in drift:
            print(f"FAIL  generated commercial artifact is stale: {path}", file=sys.stderr)
        return 1
    print("PASS  commercial offers are valid and generated artifacts are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
