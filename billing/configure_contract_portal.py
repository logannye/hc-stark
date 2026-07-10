#!/usr/bin/env python3
"""Plan or create a restricted Stripe Customer Portal configuration."""

from __future__ import annotations

import argparse
import json
import os

import stripe

from legacy_billing_containment import STRIPE_API_VERSION, verify_account


PORTAL_FEATURES = {
    "customer_update": {
        "enabled": True,
        "allowed_updates": ["address", "email", "phone", "tax_id"],
    },
    "invoice_history": {"enabled": True},
    "payment_method_update": {"enabled": True},
    "subscription_cancel": {"enabled": False},
    "subscription_update": {"enabled": False},
}


def portal_plan() -> dict[str, object]:
    return {
        "mode": "read_only",
        "api_version": STRIPE_API_VERSION,
        "public_checkout": False,
        "features": PORTAL_FEATURES,
        "default_return_url": "https://tinyzkp.com/status",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-account-id", default=os.environ.get("STRIPE_EXPECTED_ACCOUNT_ID"))
    parser.add_argument(
        "--expected-display-name",
        default=os.environ.get("STRIPE_EXPECTED_DISPLAY_NAME"),
    )
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = portal_plan()
    if not args.apply:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    if os.environ.get("TINYZKP_ALLOW_PORTAL_CONFIGURATION_WRITE") != "1":
        raise SystemExit(
            "refusing Stripe write; set TINYZKP_ALLOW_PORTAL_CONFIGURATION_WRITE=1 after account verification"
        )
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    stripe.api_version = STRIPE_API_VERSION
    if not stripe.api_key:
        raise SystemExit("STRIPE_SECRET_KEY is required")
    account = stripe.Account.retrieve()
    verify_account(account, args.expected_account_id or "", args.expected_display_name or "")

    configuration = stripe.billing_portal.Configuration.create(
        business_profile={
            "headline": "TinyZKP contract billing",
            "privacy_policy_url": "https://tinyzkp.com/privacy",
            "terms_of_service_url": "https://tinyzkp.com/terms",
        },
        features=PORTAL_FEATURES,
        default_return_url="https://tinyzkp.com/status",
        idempotency_key="tinyzkp-contract-portal-v1",
    )
    summary.update({"mode": "apply", "portal_configuration_id": configuration.id})
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
