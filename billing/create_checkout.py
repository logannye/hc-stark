#!/usr/bin/env python3
"""Generate a Stripe Checkout URL for manual tenant onboarding.

Usage:
    STRIPE_SECRET_KEY=sk_... STRIPE_PRICE_ID=price_... python3 create_checkout.py
"""

import os
import stripe

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
stripe.api_version = "2026-02-25.clover"
PRICE_ID = os.environ.get("STRIPE_PRICE_ID")
SUCCESS_URL = os.environ.get("CHECKOUT_SUCCESS_URL", "https://tinyzkp.com?checkout=success")
CANCEL_URL = os.environ.get("CHECKOUT_CANCEL_URL", "https://tinyzkp.com?checkout=cancel")


def main() -> None:
    if "_live_" in (stripe.api_key or ""):
        raise SystemExit("legacy self-serve Checkout is disabled during the Plonky3 backend recovery")
    if os.environ.get("TINYZKP_ALLOW_LEGACY_TEST_CHECKOUT", "").strip() != "1":
        raise SystemExit("legacy Checkout requires TINYZKP_ALLOW_LEGACY_TEST_CHECKOUT=1 in test mode")
    if not stripe.api_key or not PRICE_ID:
        raise SystemExit("STRIPE_SECRET_KEY and STRIPE_PRICE_ID are required for test-mode checkout")
    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": PRICE_ID, "quantity": 1}],
        success_url=SUCCESS_URL,
        cancel_url=CANCEL_URL,
        idempotency_key=os.environ.get("TINYZKP_CHECKOUT_IDEMPOTENCY_KEY", "tinyzkp-test-checkout"),
    )
    print(f"Checkout URL: {session.url}")


if __name__ == "__main__":
    main()
