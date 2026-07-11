#!/usr/bin/env python3
"""Preview or idempotently create the isolated public-beta Customer Portal."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

import stripe

from legacy_billing_containment import STRIPE_API_VERSION, verify_account
from public_beta_catalog import CATALOG_NAMESPACE, _authorization_ready


WRITE_GATE = "TINYZKP_ALLOW_BETA_PORTAL_WRITE"
PORTAL_PURPOSE = "public_beta_portal_v1"
PORTAL_FEATURES = {
    "customer_update": {
        "enabled": True,
        "allowed_updates": ["address", "email", "name", "phone", "tax_id"],
    },
    "invoice_history": {"enabled": True},
    "payment_method_update": {"enabled": True},
    "subscription_cancel": {
        "enabled": True,
        "mode": "at_period_end",
        "proration_behavior": "none",
        "cancellation_reason": {
            "enabled": True,
            "options": [
                "too_expensive",
                "missing_features",
                "switched_service",
                "unused",
                "other",
            ],
        },
    },
    "subscription_update": {
        "enabled": False,
        "default_allowed_updates": [],
        "proration_behavior": "none",
    },
}


def portal_plan() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "catalog_namespace": CATALOG_NAMESPACE,
        "purpose": PORTAL_PURPOSE,
        "api_version": STRIPE_API_VERSION,
        "features": PORTAL_FEATURES,
        "default_return_url": "https://tinyzkp.com/status",
    }


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _mapping(item: Any) -> dict[str, Any]:
    if item is None:
        return {}
    if isinstance(item, dict):
        return dict(item)
    converter = getattr(item, "to_dict_recursive", None)
    if callable(converter):
        return dict(converter())
    return dict(item)


def _all(page: Any) -> list[Any]:
    iterator = getattr(page, "auto_paging_iter", None)
    return list(iterator()) if callable(iterator) else list(_value(page, "data", []))


def _validate_existing(configuration: Any) -> None:
    features = _mapping(_value(configuration, "features", {}))
    customer = _mapping(features.get("customer_update"))
    cancel = _mapping(features.get("subscription_cancel"))
    reasons = _mapping(cancel.get("cancellation_reason"))
    update = _mapping(features.get("subscription_update"))
    if not (
        customer.get("enabled") is True
        and sorted(customer.get("allowed_updates", []))
        == sorted(PORTAL_FEATURES["customer_update"]["allowed_updates"])
        and _mapping(features.get("invoice_history")).get("enabled") is True
        and _mapping(features.get("payment_method_update")).get("enabled") is True
        and cancel.get("enabled") is True
        and cancel.get("mode") == "at_period_end"
        and cancel.get("proration_behavior") == "none"
        and reasons.get("enabled") is True
        and sorted(reasons.get("options", []))
        == sorted(PORTAL_FEATURES["subscription_cancel"]["cancellation_reason"]["options"])
        and update.get("enabled") is False
    ):
        raise RuntimeError("existing public-beta portal configuration drifted")


def apply_portal(expected_account_id: str, expected_display_name: str) -> str:
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not key or os.environ.get(WRITE_GATE) != "1":
        raise RuntimeError(f"STRIPE_SECRET_KEY and {WRITE_GATE}=1 are required")
    if "_live_" in key and not _authorization_ready(
        os.environ.get("TINYZKP_BETA_PORTAL_AUTHORIZATION")
        or os.environ.get("TINYZKP_PUBLIC_BETA_RELEASE_AUTHORIZATION")
    ):
        raise RuntimeError(
            "live portal writes require a signed exact-SHA dark-canary or public-beta authorization"
        )

    stripe.api_key = key
    stripe.api_version = STRIPE_API_VERSION
    verify_account(stripe.Account.retrieve(), expected_account_id, expected_display_name)

    matches = []
    for configuration in _all(
        stripe.billing_portal.Configuration.list(limit=100, active=True)
    ):
        metadata = _mapping(_value(configuration, "metadata", {}))
        if (
            metadata.get("tinyzkp_catalog") == CATALOG_NAMESPACE
            and metadata.get("tinyzkp_purpose") == PORTAL_PURPOSE
        ):
            matches.append(configuration)
    if len(matches) > 1:
        raise RuntimeError("multiple active public-beta portal configurations found")
    if matches:
        _validate_existing(matches[0])
        return str(_value(matches[0], "id"))

    configuration = stripe.billing_portal.Configuration.create(
        name="TinyZKP Public Beta",
        business_profile={
            "headline": "TinyZKP public beta — no SLA; not independently audited.",
            "privacy_policy_url": "https://tinyzkp.com/privacy",
            "terms_of_service_url": "https://tinyzkp.com/terms",
        },
        features=PORTAL_FEATURES,
        default_return_url="https://tinyzkp.com/status",
        metadata={
            "tinyzkp_catalog": CATALOG_NAMESPACE,
            "tinyzkp_purpose": PORTAL_PURPOSE,
        },
        idempotency_key=f"{CATALOG_NAMESPACE}:{PORTAL_PURPOSE}",
    )
    return str(_value(configuration, "id"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--expected-account-id", default=os.environ.get("TINYZKP_STRIPE_ACCOUNT_ID", "")
    )
    parser.add_argument(
        "--expected-display-name",
        default=os.environ.get("TINYZKP_STRIPE_DISPLAY_NAME", ""),
    )
    args = parser.parse_args()
    result = portal_plan()
    if args.apply:
        result["portal_configuration_id"] = apply_portal(
            args.expected_account_id, args.expected_display_name
        )
        result["mode"] = "apply"
    else:
        result["mode"] = "preview"
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
