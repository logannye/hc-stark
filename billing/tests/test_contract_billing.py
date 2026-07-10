import pytest
import json

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


def test_annual_contract_is_blocked_while_backend_release_is_blocked(tmp_path, monkeypatch):
    annual = request(
        action="annual-contract",
        offer_id="tinyzkp_certified",
        stripe_price_id="price_certified",
    )
    with pytest.raises(ValueError, match="blocked until every backend-v1 release gate"):
        billing.validate_release_availability(annual)

    ready = tmp_path / "gates.json"
    ready.write_text(
        json.dumps(
            {
                "status": "ready",
                "gates": {"review": {"passed": True, "evidence": "report.pdf"}},
            }
        )
    )
    monkeypatch.setattr(billing, "RELEASE_GATES_PATH", ready)
    billing.validate_release_availability(annual)


def test_evaluation_milestone_isolated_to_its_own_invoice(monkeypatch):
    calls = []
    monkeypatch.setattr(
        billing.stripe.Invoice,
        "create",
        lambda **kwargs: calls.append(("invoice", kwargs)) or {"id": "in_eval"},
    )
    monkeypatch.setattr(
        billing.stripe.InvoiceItem,
        "create",
        lambda **kwargs: calls.append(("item", kwargs)) or {"id": "ii_eval"},
    )
    monkeypatch.setattr(
        billing.stripe.Invoice,
        "finalize_invoice",
        lambda invoice_id, **kwargs: calls.append(("finalize", invoice_id, kwargs))
        or {"id": invoice_id, "status": "open"},
    )
    req = request()
    created = billing.create_invoice(req, req.validate(billing.load_offers()))

    invoice_call = calls[0][1]
    item_call = calls[1][1]
    assert created["id"] == "in_eval"
    assert invoice_call["auto_advance"] is False
    assert "pending_invoice_items_behavior" not in invoice_call
    assert item_call["invoice"] == "in_eval"
    assert calls[2][0:2] == ("finalize", "in_eval")
    assert calls[2][2]["auto_advance"] is True


def test_founding_offer_is_limited_to_two_unique_agreements(monkeypatch):
    invoices = {
        "data": [
            {
                "status": "paid",
                "metadata": {
                    "tinyzkp_offer_id": "founding_evaluation",
                    "tinyzkp_agreement_id": agreement,
                    "tinyzkp_milestone": "deposit",
                },
            }
            for agreement in ("eval-001", "eval-002")
        ]
    }
    monkeypatch.setattr(billing.stripe.Invoice, "list", lambda **kwargs: invoices)

    billing.validate_evaluation_history(request(agreement_id="eval-001"))
    with pytest.raises(ValueError, match="slots are already allocated"):
        billing.validate_evaluation_history(request(agreement_id="eval-003"))


def test_delivery_requires_existing_non_void_deposit(monkeypatch):
    monkeypatch.setattr(
        billing.stripe.Invoice,
        "list",
        lambda **kwargs: {
            "data": [
                {
                    "status": "void",
                    "metadata": {
                        "tinyzkp_offer_id": "standard_evaluation",
                        "tinyzkp_agreement_id": "eval-001",
                        "tinyzkp_milestone": "deposit",
                    },
                }
            ]
        },
    )
    delivery = request(
        action="evaluation-delivery",
        offer_id="standard_evaluation",
        delivery_accepted_at="2026-07-09T12:00:00Z",
    )
    with pytest.raises(ValueError, match="non-void deposit invoice"):
        billing.validate_evaluation_history(delivery)
