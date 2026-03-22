#!/usr/bin/env python3
"""Generate a Stripe Checkout URL for manual tenant onboarding.

Usage:
    STRIPE_SECRET_KEY=sk_... STRIPE_PRICE_ID=price_... python3 create_checkout.py
"""

import os
import stripe

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
PRICE_ID = os.environ["STRIPE_PRICE_ID"]
SUCCESS_URL = os.environ.get("CHECKOUT_SUCCESS_URL", "https://tinyzkp.com?checkout=success")
CANCEL_URL = os.environ.get("CHECKOUT_CANCEL_URL", "https://tinyzkp.com?checkout=cancel")


def main() -> None:
    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": PRICE_ID, "quantity": 1}],
        success_url=SUCCESS_URL,
        cancel_url=CANCEL_URL,
    )
    print(f"Checkout URL: {session.url}")


if __name__ == "__main__":
    main()
