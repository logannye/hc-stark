import pytest

import contract_billing as billing


def request(action="evaluation-deposit", offer_id="founding_evaluation", **overrides):
    values = {
        "action": action,
        "offer_id": offer_id,
        "customer_id": "cus_test",
        "agreement_id": "eval-001",
        "days_until_due": 15,
        "stripe_price_id": None,
        "delivery_accepted_at": None,
    }
    values.update(overrides)
    return billing.BillingRequest(**values)


def test_evaluation_plan_is_half_and_never_checkout():
    offers = billing.load_offers()
    req = request()
    offer = req.validate(offers)
    summary = billing.plan(req, offer)
    assert summary["amount_cents"] == 1_250_000
    assert summary["collection_method"] == "send_invoice"
    assert summary["public_checkout"] is False


def test_delivery_requires_acceptance_evidence():
    with pytest.raises(ValueError, match="delivery_accepted_at"):
        request(action="evaluation-delivery").validate(billing.load_offers())


def test_annual_contract_requires_matching_annual_price():
    req = request(
        action="annual-contract",
        offer_id="tinyzkp_certified",
        stripe_price_id="price_certified",
    )
    offer = req.validate(billing.load_offers())
    billing.validate_annual_price(
        {
            "active": True,
            "currency": "usd",
            "unit_amount": 6_000_000,
            "recurring": {"interval": "year", "interval_count": 1},
        },
        offer,
    )
    with pytest.raises(ValueError, match="amount/currency"):
        billing.validate_annual_price(
            {
                "active": True,
                "currency": "usd",
                "unit_amount": 1,
                "recurring": {"interval": "year", "interval_count": 1},
            },
            offer,
        )
