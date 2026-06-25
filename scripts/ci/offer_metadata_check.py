#!/usr/bin/env python3
"""Validate the agent-readable TinyZKP offer file."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
OFFERS = SITE / ".well-known" / "tinyzkp-offers.json"
OFFERS_SCHEMA = SITE / "schemas" / "tinyzkp-offers.schema.json"
PRICING = SITE / "pricing.json"
LIMITS = SITE / "limits.json"
EXPECTED_PLAN_IDS = ("free", "developer", "pro", "scale", "compute")
COMMERCIAL_INTENTS = {
    "production_pilot": "paid_pilot_checkout",
    "platform_rollout": "platform_rollout",
    "reserved_capacity": "enterprise_review",
}


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def tinyzkp_url(value: object, *, label: str) -> tuple[str, dict[str, list[str]]] | None:
    if not isinstance(value, str):
        return f"{label} must be a URL string", {}
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.netloc != "tinyzkp.com":
        return f"{label} must be an https://tinyzkp.com URL", {}
    if not parsed.path.startswith("/"):
        return f"{label} must include an absolute path", {}
    return None, parse_qs(parsed.query)


def validate_plan_checkout_urls(
    failures: list[str],
    plans: object,
    *,
    source: str,
    label: str,
) -> None:
    if not isinstance(plans, list):
        failures.append(f"{label} plans must be a list")
        return
    for plan in plans:
        if not isinstance(plan, dict):
            failures.append(f"{label} plan entries must be objects")
            continue
        plan_id = plan.get("id")
        if plan_id not in EXPECTED_PLAN_IDS:
            continue
        error, query = tinyzkp_url(plan.get("checkout_url"), label=f"{label} {plan_id} checkout_url")
        if error:
            failures.append(error)
            continue
        if query.get("source") != [source]:
            failures.append(f"{label} plan {plan_id!r} checkout_url must include source={source}")
        if query.get("medium") != ["metadata"]:
            failures.append(f"{label} plan {plan_id!r} checkout_url must include medium=metadata")
        expected_intent = "free_signup" if plan_id == "free" else "paid_checkout"
        if query.get("intent") != [expected_intent]:
            failures.append(f"{label} plan {plan_id!r} checkout_url must include intent={expected_intent}")
        if plan_id == "free" and "plan" in query:
            failures.append(f"{label} free checkout_url must not include a paid plan parameter")
        if plan_id != "free" and query.get("plan") != [plan_id]:
            failures.append(f"{label} plan {plan_id!r} checkout_url must include plan={plan_id}")


def validate_commercial_checkout_urls(failures: list[str], packages: object) -> None:
    if not isinstance(packages, list):
        failures.append("pricing commercial_packages must be a list")
        return
    for package in packages:
        if not isinstance(package, dict):
            failures.append("pricing commercial package entries must be objects")
            continue
        package_id = package.get("id")
        expected_intent = COMMERCIAL_INTENTS.get(str(package_id))
        if not expected_intent:
            continue
        error, query = tinyzkp_url(package.get("checkout_url"), label=f"pricing commercial package {package_id} checkout_url")
        if error:
            failures.append(error)
            continue
        if query.get("source") != ["pricing_json"]:
            failures.append(f"pricing commercial package {package_id!r} checkout_url must include source=pricing_json")
        if query.get("medium") != ["metadata"]:
            failures.append(f"pricing commercial package {package_id!r} checkout_url must include medium=metadata")
        if query.get("intent") != [expected_intent]:
            failures.append(f"pricing commercial package {package_id!r} checkout_url must include intent={expected_intent}")


def validate() -> list[str]:
    failures: list[str] = []
    if not OFFERS.is_file():
        return [f"{OFFERS.relative_to(ROOT)} is missing"]
    if not OFFERS_SCHEMA.is_file():
        failures.append(f"{OFFERS_SCHEMA.relative_to(ROOT)} is missing")

    offers = load_json(OFFERS)
    pricing = load_json(PRICING)
    limits = load_json(LIMITS)
    load_json(OFFERS_SCHEMA)

    if not isinstance(offers, dict):
        return ["offer file must be a JSON object"]
    if not isinstance(pricing, dict):
        return ["pricing file must be a JSON object"]
    if not isinstance(limits, dict):
        return ["limits file must be a JSON object"]

    if offers.get("$schema") != "https://tinyzkp.com/schemas/tinyzkp-offers.schema.json":
        failures.append("offers $schema must point to tinyzkp-offers.schema.json")
    if offers.get("canonical_url") != "https://tinyzkp.com/.well-known/tinyzkp-offers.json":
        failures.append("offers canonical_url must be the well-known TinyZKP offer URL")
    if offers.get("currency") != pricing.get("currency"):
        failures.append("offers currency must match pricing.json currency")
    if offers.get("human_confirmation_required") is not True:
        failures.append("offers must require human confirmation before checkout")

    confirmation = str(offers.get("human_confirmation_language", "")).lower()
    for marker in ("confirm", "selected", "spend cap", "secrets"):
        if marker not in confirmation:
            failures.append(f"human_confirmation_language must mention {marker!r}")

    pricing_plans = {
        plan.get("id"): plan
        for plan in pricing.get("plans", [])
        if isinstance(plan, dict)
    }
    offer_plans = offers.get("plans", [])
    if not isinstance(offer_plans, list):
        failures.append("offers plans must be a list")
        offer_plans = []
    offer_by_id = {
        plan.get("id"): plan
        for plan in offer_plans
        if isinstance(plan, dict)
    }
    if tuple(offer_by_id.keys()) != EXPECTED_PLAN_IDS:
        failures.append(f"offers plans must be in canonical order: {', '.join(EXPECTED_PLAN_IDS)}")

    for plan_id in EXPECTED_PLAN_IDS:
        offer = offer_by_id.get(plan_id)
        price = pricing_plans.get(plan_id)
        if not isinstance(offer, dict) or not isinstance(price, dict):
            failures.append(f"plan {plan_id!r} must exist in both offers and pricing")
            continue
        for field in (
            "base_monthly",
            "included_receipts_per_month",
            "prove_requests_per_minute",
            "concurrent_jobs",
            "monthly_spend_cap",
            "best_for",
        ):
            if offer.get(field) != price.get(field):
                failures.append(f"plan {plan_id!r} field {field!r} must match pricing.json")
        error, query = tinyzkp_url(offer.get("checkout_url"), label=f"plan {plan_id} checkout_url")
        if error:
            failures.append(error)
            continue
        if query.get("source") != ["agent_offer"]:
            failures.append(f"plan {plan_id!r} checkout_url must include source=agent_offer")
        if query.get("medium") != ["llm"]:
            failures.append(f"plan {plan_id!r} checkout_url must include medium=llm")
        if plan_id != "free" and query.get("plan") != [plan_id]:
            failures.append(f"plan {plan_id!r} checkout_url must include plan={plan_id}")
        if plan_id == "free" and "plan" in query:
            failures.append("free checkout_url must not include a paid plan parameter")
        if not offer.get("agent_recommend_when"):
            failures.append(f"plan {plan_id!r} must include agent_recommend_when guidance")

    validate_plan_checkout_urls(failures, pricing.get("plans", []), source="pricing_json", label="pricing metadata")
    validate_plan_checkout_urls(failures, limits.get("self_serve_plans", []), source="limits_metadata", label="limits metadata")
    validate_commercial_checkout_urls(failures, pricing.get("commercial_packages", []))

    recommended = {
        item.get("recommend")
        for item in offers.get("recommendation_rules", [])
        if isinstance(item, dict)
    }
    package_ids = {
        item.get("id")
        for item in offers.get("commercial_packages", [])
        if isinstance(item, dict)
    }
    allowed_recommendations = set(EXPECTED_PLAN_IDS) | package_ids
    unknown = sorted(str(item) for item in recommended - allowed_recommendations if item)
    if unknown:
        failures.append("recommendation_rules reference unknown offers: " + ", ".join(unknown))

    production_pilot = next(
        (
            item
            for item in offers.get("commercial_packages", [])
            if isinstance(item, dict) and item.get("id") == "production_pilot"
        ),
        None,
    )
    if not production_pilot:
        failures.append("commercial_packages must include production_pilot")
    else:
        error, query = tinyzkp_url(production_pilot.get("checkout_url"), label="production_pilot checkout_url")
        if error:
            failures.append(error)
        else:
            if query.get("source") != ["agent_offer"]:
                failures.append("production_pilot checkout_url must include source=agent_offer")
            if query.get("medium") != ["llm"]:
                failures.append("production_pilot checkout_url must include medium=llm")
            if query.get("intent") != ["paid_pilot_checkout"]:
                failures.append("production_pilot checkout_url must include intent=paid_pilot_checkout")

    boundaries = " ".join(str(item).lower() for item in offers.get("data_boundaries", []))
    for marker in ("transparent", "secrets", "private customer data", "encoded statement"):
        if marker not in boundaries:
            failures.append(f"data_boundaries must mention {marker!r}")

    support = offers.get("support") if isinstance(offers.get("support"), dict) else {}
    for key in ("contact", "trust", "security_review", "status", "pricing", "fit_finder", "roi"):
        error, _query = tinyzkp_url(support.get(key), label=f"support.{key}")
        if error:
            failures.append(error)

    assets = offers.get("machine_readable_assets") if isinstance(offers.get("machine_readable_assets"), dict) else {}
    for key in ("pricing", "discovery", "mcp", "openapi", "agent_policy", "limits", "trust", "schema"):
        error, _query = tinyzkp_url(assets.get(key), label=f"machine_readable_assets.{key}")
        if error:
            failures.append(error)

    return failures


def main() -> int:
    failures = validate()
    if failures:
        print("TinyZKP offer metadata check failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS TinyZKP offer metadata check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
