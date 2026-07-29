#!/usr/bin/env python3
"""Render the current Community/Guard offer catalog and detect drift."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "site" / "pricing.json"
PRICING_HTML = ROOT / "site" / "pricing.html"
JSON_LD = ROOT / "site" / "offers.jsonld"
SALES_MATRIX = ROOT / "commercial" / "generated" / "offer-matrix.md"
COMMUNITY_SOURCE_URL = "https://github.com/logannye/hc-stark"
COMMUNITY_INCLUDES = (
    "proof engine and verifier",
    "public schemas and reference workloads",
    "compatibility checker and doctor",
    "resource estimators",
    "conventional and bounded proving primitives",
    "public benchmark evidence",
)
GUARD_INCLUDES = (
    "foreground process and signal supervision",
    "checkpoint lifecycle and deterministic resume supervision",
    "support-safe diagnostics",
    "CI resource-regression policies",
    "signed artifacts and OCI images",
    "SBOM and provenance",
    "four qualification windows per year",
)
GUARD_EXCLUDES = (
    "hosted proving",
    "usage metering",
    "SLA",
    "onboarding calls",
    "custom AIR development",
    "architecture review",
    "security questionnaires",
    "SSO",
    "redistribution",
    "resale",
    "OEM",
    "service-bureau use",
)
GUARD_ORGANIZATION_SCOPE = (
    "one_legal_organization_unlimited_internal_users_and_runners"
)


def money(value: int, *, suffix: str = "") -> str:
    return f"${value:,}{suffix}"


def load_source() -> dict[str, object]:
    value = json.loads(SOURCE.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("pricing source must be an object")
    return value


def products_by_id(source: dict[str, object]) -> dict[str, dict[str, object]]:
    products = source.get("products")
    if not isinstance(products, list):
        raise ValueError("products must be a list")
    result: dict[str, dict[str, object]] = {}
    for index, product in enumerate(products):
        if not isinstance(product, dict):
            raise ValueError(f"products[{index}] must be an object")
        product_id = product.get("id")
        if not isinstance(product_id, str) or not product_id:
            raise ValueError(f"products[{index}].id must be a non-empty string")
        if product_id in result:
            raise ValueError(f"duplicate product id: {product_id}")
        result[product_id] = product
    return result


def _exact(value: object, expected: object) -> bool:
    """Compare JSON contract values without treating bool as an integer."""

    return type(value) is type(expected) and value == expected


class PricingDOMParser(HTMLParser):
    """Collect visible copy from the two explicitly identified pricing cards."""

    def __init__(self) -> None:
        super().__init__()
        self.all_text: list[str] = []
        self.cards: dict[str, list[str]] = {}
        self.card_counts: dict[str, int] = {}
        self._product_id: str | None = None
        self._article_depth = 0
        self._hidden_text_depth = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag in {"script", "style"}:
            self._hidden_text_depth += 1
            return
        attributes = dict(attrs)
        if tag == "article" and self._product_id is None:
            product_id = attributes.get("data-offer-product")
            if product_id is not None:
                self._product_id = product_id
                self._article_depth = 1
                self.cards.setdefault(product_id, [])
                self.card_counts[product_id] = self.card_counts.get(product_id, 0) + 1
                return
        if tag == "article" and self._product_id is not None:
            self._article_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            if self._hidden_text_depth:
                self._hidden_text_depth -= 1
            return
        if tag != "article" or self._product_id is None:
            return
        self._article_depth -= 1
        if self._article_depth == 0:
            self._product_id = None

    def handle_data(self, data: str) -> None:
        if self._hidden_text_depth:
            return
        self.all_text.append(data)
        if self._product_id is not None:
            self.cards[self._product_id].append(data)


def _visible_text(parts: list[str]) -> str:
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


def validate_pricing_html(
    source: dict[str, object], html: str
) -> list[str]:
    failures: list[str] = []
    try:
        products = products_by_id(source)
    except ValueError as error:
        return [str(error)]
    if set(products) != {"community", "guard"}:
        return ["pricing DOM parity requires exactly community and guard"]

    parser = PricingDOMParser()
    parser.feed(html)
    if set(parser.cards) != {"community", "guard"} or parser.card_counts != {
        "community": 1,
        "guard": 1,
    }:
        failures.append(
            "pricing.html must contain exactly one identified Community and Guard card"
        )
        return failures

    community_text = _visible_text(parser.cards["community"])
    guard_text = _visible_text(parser.cards["guard"])
    community = products["community"]
    guard = products["guard"]
    prices = guard.get("prices")
    if not isinstance(prices, dict):
        return failures + ["guard prices must be an object"]

    for expected in (str(community["name"]), "$0", "MIT licensed"):
        if expected not in community_text:
            failures.append(f"pricing.html Community card is missing {expected!r}")
    for included in community.get("includes", []):
        if str(included).casefold() not in community_text.casefold():
            failures.append(
                f"pricing.html Community card is missing reviewed inclusion {included!r}"
            )

    annual = int(prices["annual_usd"])
    monthly = int(prices["monthly_usd"])
    savings = monthly * 12 - annual
    guard_required = (
        str(guard["name"]),
        f"${annual:,} / year",
        f"Annual recommended · save ${savings:,} versus monthly",
        "One legal organization; unlimited internal users and runners",
        f"Monthly: ${monthly:,}",
    )
    for expected in guard_required:
        if expected not in guard_text:
            failures.append(f"pricing.html Guard card is missing {expected!r}")
    for included in guard.get("includes", []):
        if str(included).casefold() not in guard_text.casefold():
            failures.append(
                f"pricing.html Guard card is missing reviewed inclusion {included!r}"
            )
    page_text = _visible_text(parser.all_text)
    for excluded in guard.get("excludes", []):
        if str(excluded).casefold() not in page_text.casefold():
            failures.append(
                f"pricing.html is missing reviewed exclusion {excluded!r}"
            )
    return failures


def validate(source: dict[str, object]) -> list[str]:
    failures: list[str] = []
    expected_top_level = {
        "schema_version": 5,
        "name": "TinyZKP Community and Guard",
        "canonical_url": "https://tinyzkp.com/pricing",
        "currency": "USD",
        "hosted_proving": False,
        "usage_metering": False,
    }
    for field, expected in expected_top_level.items():
        if not _exact(source.get(field), expected):
            failures.append(f"{field} must be {expected!r}")

    checkout_enabled = source.get("checkout_enabled")
    if not isinstance(checkout_enabled, bool):
        failures.append("checkout_enabled must be a boolean")
        checkout_enabled = False
    sales_state = source.get("sales_state")
    if checkout_enabled and sales_state != "live":
        failures.append("enabled checkout requires sales_state 'live'")
    if not checkout_enabled and sales_state not in {"closed", "frozen", "withdrawn"}:
        failures.append(
            "disabled checkout requires sales_state 'closed', 'frozen', or 'withdrawn'"
        )
    if sales_state == "withdrawn" and checkout_enabled:
        failures.append("a withdrawn SKU can never have checkout enabled")

    try:
        products = products_by_id(source)
    except ValueError as error:
        failures.append(str(error))
        return failures
    if list(products) != ["community", "guard"]:
        failures.append("products must contain exactly community then guard")
        return failures

    community = products["community"]
    if community.get("name") != "TinyZKP Community":
        failures.append("community name must be 'TinyZKP Community'")
    if not _exact(community.get("price_usd"), 0):
        failures.append("community price_usd must be 0")
    if community.get("license") != "MIT":
        failures.append("community license must be MIT")
    if community.get("availability") != "available":
        failures.append("community availability must be available")
    if community.get("includes") != list(COMMUNITY_INCLUDES):
        failures.append("community includes must match the reviewed product scope")

    guard = products["guard"]
    if guard.get("name") != "TinyZKP Guard":
        failures.append("guard name must be 'TinyZKP Guard'")
    prices = guard.get("prices")
    if not isinstance(prices, dict):
        failures.append("guard prices must be an object")
        prices = {}
    if not _exact(prices.get("monthly_usd"), 499):
        failures.append("guard monthly_usd must be 499")
    if not _exact(prices.get("annual_usd"), 4_990):
        failures.append("guard annual_usd must be 4990")
    if prices.get("annual_recommended") is not True:
        failures.append("guard annual_recommended must be true")
    expected_guard_availability = {
        "live": "available",
        "frozen": "sales_frozen",
        "closed": "blocked_until_all_launch_gates_pass",
        # NOT "blocked_until_all_launch_gates_pass": that promises the block
        # lifts once gates pass, which for a withdrawn SKU is a false promise.
        "withdrawn": "withdrawn",
    }.get(str(sales_state))
    if guard.get("availability") != expected_guard_availability:
        failures.append(
            f"guard availability must be {expected_guard_availability!r}"
        )
    if guard.get("license") != "commercial_object_code":
        failures.append("guard license must be commercial_object_code")
    if guard.get("organization_scope") != GUARD_ORGANIZATION_SCOPE:
        failures.append("guard organization_scope must match the reviewed scope")
    if guard.get("includes") != list(GUARD_INCLUDES):
        failures.append("guard includes must match the reviewed product scope")
    if guard.get("excludes") != list(GUARD_EXCLUDES):
        failures.append("guard excludes must match the reviewed product boundary")

    policy = source.get("price_policy")
    if not isinstance(policy, dict):
        failures.append("price_policy must be an object")
        policy = {}
    expected_policy = {
        "monthly_usd": 499,
        "annual_usd": 4_990,
        "annual_default": True,
        "usage_metering": False,
        "trials_allowed": False,
        "coupons_allowed": False,
        "add_ons_allowed": False,
        "enterprise_variants_allowed": False,
        "subscription_pause_offered": False,
        "existing_subscribers_grandfathered": True,
        "existing_variant_ids_retained": True,
        "existing_variant_ids_repurposed": False,
        "future_price_changes_use_new_variant_ids": False,
    }
    for field, expected in expected_policy.items():
        if not _exact(policy.get(field), expected):
            failures.append(f"price_policy.{field} must be {expected!r}")

    if source.get("checkout_enabled") is True:
        if source.get("launch_state") != "qualified":
            failures.append("live checkout requires launch_state qualified")
        if source.get("commerce_state") != "public_live":
            failures.append("live checkout requires commerce_state public_live")
        if source.get("portal_state") != "live":
            failures.append("live checkout requires portal_state live")
    elif sales_state == "frozen":
        if source.get("commerce_state") != "sales_frozen":
            failures.append("frozen sales require commerce_state sales_frozen")
        if source.get("portal_state") != "live":
            failures.append("frozen sales require portal_state live")
    return failures


def render_jsonld(source: dict[str, object]) -> str:
    products = products_by_id(source)
    guard_prices = products["guard"]["prices"]
    # `OutOfStock` means TEMPORARILY unavailable -- Google and every other
    # structured-data consumer reads it as a product that is coming back. A
    # withdrawn SKU is `Discontinued`. Publishing the two Guard offers as
    # OutOfStock after the withdrawal told search engines, for months, that a
    # $499/mo product would return.
    guard_availability = (
        "https://schema.org/Discontinued"
        if source.get("sales_state") == "withdrawn"
        else "https://schema.org/InStock"
        if source["checkout_enabled"]
        else "https://schema.org/OutOfStock"
    )
    items = [
        {
            "@type": "Offer",
            "availability": "https://schema.org/InStock",
            "name": "TinyZKP Community source",
            "price": "0",
            "priceCurrency": source["currency"],
            "url": COMMUNITY_SOURCE_URL,
        },
        {
            "@type": "Offer",
            "availability": guard_availability,
            "name": "TinyZKP Guard annual subscription",
            "price": str(guard_prices["annual_usd"]),
            "priceCurrency": source["currency"],
            "url": source["canonical_url"],
        },
        {
            "@type": "Offer",
            "availability": guard_availability,
            "name": "TinyZKP Guard monthly subscription",
            "price": str(guard_prices["monthly_usd"]),
            "priceCurrency": source["currency"],
            "url": source["canonical_url"],
        },
    ]
    payload = {
        "@context": "https://schema.org",
        "@type": "OfferCatalog",
        "itemListElement": items,
        "name": source["name"],
        "url": source["canonical_url"],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_sales_matrix(source: dict[str, object]) -> str:
    products = products_by_id(source)
    guard = products["guard"]
    prices = guard["prices"]
    guard_status = (
        "Available"
        if source["checkout_enabled"]
        else "Sales frozen"
        if source["sales_state"] == "frozen"
        else "Closed pending launch evidence"
    )
    lines = [
        "# TinyZKP offer matrix",
        "",
        "> Generated from `site/pricing.json`; do not edit by hand.",
        "",
        "| Product | Price | Availability | License | Scope |",
        "|---|---:|---|---|---|",
        "| TinyZKP Community source | $0 | Available | MIT | Open engine and verifier source, public schemas, and reference workloads |",
        f"| TinyZKP Guard annual | {money(int(prices['annual_usd']))}/year | {guard_status} | Commercial object code | One legal organization; unlimited internal users and runners |",
        f"| TinyZKP Guard monthly | {money(int(prices['monthly_usd']))}/month | {guard_status} | Commercial object code | One legal organization; unlimited internal users and runners |",
        "",
        "Guard has no hosted proving, usage meter, trial, coupon, enterprise tier, SLA, or bundled engineering hours.",
        "Checkout URLs are published only when signed launch evidence derives `checkout_enabled: true`.",
        "",
    ]
    return "\n".join(lines)


def desired_outputs(source: dict[str, object]) -> dict[Path, str]:
    return {
        JSON_LD: render_jsonld(source),
        SALES_MATRIX: render_sales_matrix(source),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail instead of updating drifted outputs")
    args = parser.parse_args(argv)
    source = load_source()
    problems = validate(source)
    if not problems:
        try:
            pricing_html = PRICING_HTML.read_text(encoding="utf-8")
        except OSError as error:
            problems.append(f"cannot read pricing.html: {error}")
        else:
            problems.extend(validate_pricing_html(source, pricing_html))
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
    print("PASS  Community/Guard offers are valid and generated artifacts are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
