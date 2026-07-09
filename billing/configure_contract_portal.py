#!/usr/bin/env python3
"""Create a restricted Stripe Customer Portal configuration for contracts."""

from __future__ import annotations

import json
import os

import stripe


def main() -> None:
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    stripe.api_version = "2026-02-25.clover"
    if not stripe.api_key:
        raise SystemExit("STRIPE_SECRET_KEY is required")
    if not os.environ.get("TINYZKP_ALLOW_PORTAL_CONFIGURATION_WRITE") == "1":
        raise SystemExit(
            "refusing Stripe write; set TINYZKP_ALLOW_PORTAL_CONFIGURATION_WRITE=1 after account verification"
        )

    configuration = stripe.billing_portal.Configuration.create(
        business_profile={
            "headline": "TinyZKP contract billing",
            "privacy_policy_url": "https://tinyzkp.com/privacy",
            "terms_of_service_url": "https://tinyzkp.com/terms",
        },
        features={
            "customer_update": {
                "enabled": True,
                "allowed_updates": ["address", "email", "phone", "tax_id"],
            },
            "invoice_history": {"enabled": True},
            "payment_method_update": {"enabled": True},
            "subscription_cancel": {"enabled": False},
            "subscription_update": {"enabled": False},
        },
        default_return_url="https://tinyzkp.com/status",
        idempotency_key="tinyzkp-contract-portal-v1",
    )
    print(json.dumps({"portal_configuration_id": configuration.id}))


if __name__ == "__main__":
    main()
