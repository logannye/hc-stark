#!/usr/bin/env python3
"""Fail CI when a withdrawn SKU is still described as purchasable anywhere.

The Guard subscription was withdrawn, and the withdrawal landed in exactly
one place: human-readable HTML. Every machine-readable surface went on
describing a purchasable product, for months:

    offers.jsonld   two Guard offers, $499/$4990, schema.org/OutOfStock
                    -- which means TEMPORARILY unavailable, i.e. coming back
    pricing.json    guard availability "blocked_until_all_launch_gates_pass"
                    -- which promises the block lifts once gates pass
    commerce.json   price_policy presented as a current price sheet
    llms.txt        "Guard: $499/month or $4,990/year"

The root cause was that the commercial data model had only three states --
live / frozen / closed -- and no way to say "withdrawn". The only check that
touched withdrawal asserted the word "withdraw" appeared somewhere in the
HTML, so it stayed green the entire time.

This gate is bidirectional on purpose. Data-says-withdrawn-but-copy-does-not
is the direction that misleads a buyer; copy-says-withdrawn-but-data-does-not
is the direction that actually happened. Both fail.
"""

from __future__ import annotations

import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
WITHDRAWAL = ROOT / "release" / "guard-sku-withdrawal-v1.json"

DISCONTINUED = "https://schema.org/Discontinued"
# The value that was live and wrong. `OutOfStock` is schema.org for
# "temporarily out of stock"; Google reads it as a product that returns.
OUT_OF_STOCK = "https://schema.org/OutOfStock"

# Surfaces a human reads. If the data says withdrawn, these must say so too.
COPY_SURFACES = ("pricing.html", "guard.html", "llms.txt")


def load(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} root must be a JSON object")
    return data


def sku_withdrawn(withdrawal: dict) -> bool:
    return withdrawal.get("withdrawn") is True


def guard_offer_availabilities(offers: dict) -> list[str]:
    items = offers.get("itemListElement")
    if not isinstance(items, list):
        return []
    return [
        str(item.get("availability"))
        for item in items
        if isinstance(item, dict) and "Guard" in str(item.get("name", ""))
    ]


def guard_product(pricing: dict) -> dict | None:
    products = pricing.get("products")
    if not isinstance(products, list):
        return None
    for product in products:
        if isinstance(product, dict) and product.get("id") == "guard":
            return product
    return None


def check(
    *,
    withdrawal: dict,
    pricing: dict,
    commerce: dict,
    offers: dict,
    copy_texts: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    withdrawn = sku_withdrawn(withdrawal)
    copy_says_withdrawn = {
        name: "withdraw" in text.lower() for name, text in copy_texts.items()
    }

    if withdrawn:
        # --- data must agree with itself -------------------------------
        if pricing.get("sales_state") != "withdrawn":
            failures.append(
                "release/guard-sku-withdrawal-v1.json says withdrawn but "
                f"site/pricing.json sales_state is {pricing.get('sales_state')!r}"
            )
        if commerce.get("sales_state") != "withdrawn":
            failures.append(
                "site/commerce.json sales_state must be 'withdrawn', got "
                f"{commerce.get('sales_state')!r}"
            )
        if commerce.get("checkout_enabled") is not False:
            failures.append("a withdrawn SKU must never have checkout_enabled true")
        if pricing.get("checkout_enabled") is not False:
            failures.append("site/pricing.json checkout_enabled must be false")

        product = guard_product(pricing)
        if product is None:
            failures.append("site/pricing.json has no guard product entry")
        elif product.get("availability") != "withdrawn":
            failures.append(
                "guard availability must be 'withdrawn', got "
                f"{product.get('availability')!r} -- "
                "'blocked_until_all_launch_gates_pass' promises the block lifts"
            )

        availabilities = guard_offer_availabilities(offers)
        if not availabilities:
            failures.append("site/offers.jsonld lists no Guard offer to check")
        for availability in availabilities:
            if availability == OUT_OF_STOCK:
                failures.append(
                    "site/offers.jsonld publishes a Guard offer as OutOfStock; "
                    "that is schema.org for TEMPORARILY unavailable and tells "
                    "search engines the product is returning. Use Discontinued."
                )
            elif availability != DISCONTINUED:
                failures.append(
                    f"unexpected Guard offer availability {availability!r}; "
                    f"a withdrawn SKU must be {DISCONTINUED}"
                )

        # --- copy must agree with the data -----------------------------
        for name, says in sorted(copy_says_withdrawn.items()):
            if not says:
                failures.append(
                    f"site/{name} does not mention the withdrawal while every "
                    f"pricing surface says the SKU is withdrawn"
                )
    else:
        # --- the direction that actually happened ----------------------
        stated = sorted(name for name, says in copy_says_withdrawn.items() if says)
        if stated:
            failures.append(
                f"site/{stated[0]} states a withdrawal but "
                "release/guard-sku-withdrawal-v1.json does not record one; "
                "a withdrawal announced only in copy leaves every machine "
                "surface advertising a purchasable product"
            )
        availabilities = guard_offer_availabilities(offers)
        if DISCONTINUED in availabilities:
            failures.append(
                "site/offers.jsonld marks a Guard offer Discontinued without a "
                "recorded withdrawal"
            )

    return failures


def main(argv: list[str]) -> int:
    try:
        failures = check(
            withdrawal=load(WITHDRAWAL),
            pricing=load(SITE / "pricing.json"),
            commerce=load(SITE / "commerce.json"),
            offers=load(SITE / "offers.jsonld"),
            copy_texts={
                name: (SITE / name).read_text(encoding="utf-8")
                for name in COPY_SURFACES
            },
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"sku withdrawal gate failed to run: {error}", file=sys.stderr)
        return 2

    if failures:
        print("sku withdrawal gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("PASS sku withdrawal gate (copy and every pricing surface agree)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
