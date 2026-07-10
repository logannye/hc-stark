#!/usr/bin/env python3
"""Plan or create tightly scoped Stripe invoices and annual contracts.

The default is read-only. Writes require --apply, exact account identity, and
TINYZKP_ALLOW_CONTRACT_BILLING_WRITE=1. This tool never creates Checkout links.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any

import stripe

from legacy_billing_containment import STRIPE_API_VERSION, verify_account


ROOT = Path(__file__).resolve().parents[1]
OFFERS_PATH = ROOT / "site" / "pricing.json"
RELEASE_GATES_PATH = ROOT / "release" / "backend-v1-gates.json"
EVALUATIONS = {"founding_evaluation", "standard_evaluation"}
ANNUAL = {"tinyzkp_certified", "tinyzkp_fleet_oem"}


def value(item: Any, key: str, default: Any = None) -> Any:
    return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)


def load_offers() -> dict[str, dict[str, Any]]:
    payload = json.loads(OFFERS_PATH.read_text(encoding="utf-8"))
    return {offer["id"]: offer for offer in payload["offers"]}


@dataclass(frozen=True)
class BillingRequest:
    action: str
    offer_id: str
    customer_id: str
    agreement_id: str
    days_until_due: int
    stripe_price_id: str | None = None
    delivery_accepted_at: str | None = None

    def validate(self, offers: dict[str, dict[str, Any]]) -> dict[str, Any]:
        if self.offer_id not in offers:
            raise ValueError("unknown offer")
        if not self.customer_id.startswith("cus_"):
            raise ValueError("customer_id must be a Stripe customer ID")
        if not self.agreement_id or len(self.agreement_id) > 120:
            raise ValueError("agreement_id is required and limited to 120 characters")
        if not 1 <= self.days_until_due <= 60:
            raise ValueError("days_until_due must be between 1 and 60")
        if self.action in {"evaluation-deposit", "evaluation-delivery"}:
            if self.offer_id not in EVALUATIONS:
                raise ValueError("evaluation actions require an evaluation offer")
            if self.action == "evaluation-delivery" and not self.delivery_accepted_at:
                raise ValueError("delivery invoice requires delivery_accepted_at")
        elif self.action == "annual-contract":
            if self.offer_id not in ANNUAL:
                raise ValueError("annual-contract requires Certified or Fleet/OEM")
            if not self.stripe_price_id or not self.stripe_price_id.startswith("price_"):
                raise ValueError("annual-contract requires a Stripe annual price ID")
        else:
            raise ValueError("unsupported billing action")
        return offers[self.offer_id]


def offer_amount(offer: dict[str, Any]) -> int:
    return int(offer.get("price", offer.get("minimum_price")))


def validate_release_availability(request: BillingRequest) -> None:
    if request.action != "annual-contract":
        return
    payload = json.loads(RELEASE_GATES_PATH.read_text(encoding="utf-8"))
    gates = payload.get("gates")
    ready = payload.get("status") == "ready" and isinstance(gates, dict) and bool(gates)
    if ready:
        ready = all(
            isinstance(gate, dict)
            and gate.get("passed") is True
            and isinstance(gate.get("evidence"), str)
            and bool(gate["evidence"].strip())
            for gate in gates.values()
        )
    if not ready:
        raise ValueError(
            "annual Certified and Fleet/OEM billing is blocked until every backend-v1 release gate has evidence"
        )


def plan(request: BillingRequest, offer: dict[str, Any]) -> dict[str, Any]:
    amount_dollars = offer_amount(offer)
    if request.action.startswith("evaluation-"):
        amount_dollars //= 2
    return {
        "mode": "read_only",
        "action": request.action,
        "offer_id": request.offer_id,
        "customer_id": request.customer_id,
        "agreement_id": request.agreement_id,
        "amount_cents": amount_dollars * 100,
        "currency": "usd",
        "collection_method": "send_invoice",
        "days_until_due": request.days_until_due,
        "public_checkout": False,
    }


def validate_annual_price(price: Any, offer: dict[str, Any]) -> None:
    recurring = value(price, "recurring", {}) or {}
    expected = offer_amount(offer) * 100
    if value(price, "active") is not True:
        raise ValueError("annual Stripe price is inactive")
    if value(price, "currency") != "usd" or value(price, "unit_amount") != expected:
        raise ValueError("annual Stripe price amount/currency does not match the offer source")
    if value(recurring, "interval") != "year" or value(recurring, "interval_count", 1) != 1:
        raise ValueError("annual Stripe price must recur exactly yearly")


def listed_invoices(*, customer_id: str | None = None) -> list[Any]:
    params: dict[str, Any] = {"limit": 100}
    if customer_id:
        params["customer"] = customer_id
    page = stripe.Invoice.list(**params)
    auto_paging_iter = getattr(page, "auto_paging_iter", None)
    if callable(auto_paging_iter):
        return list(auto_paging_iter())
    return list(value(page, "data", []) or [])


def validate_evaluation_history(request: BillingRequest) -> None:
    """Enforce founding slots and deposit-before-delivery from Stripe records."""
    if request.action == "evaluation-delivery":
        deposits = [
            invoice
            for invoice in listed_invoices(customer_id=request.customer_id)
            if value(value(invoice, "metadata", {}) or {}, "tinyzkp_offer_id")
            == request.offer_id
            and value(value(invoice, "metadata", {}) or {}, "tinyzkp_agreement_id")
            == request.agreement_id
            and value(value(invoice, "metadata", {}) or {}, "tinyzkp_milestone") == "deposit"
            and value(invoice, "status") != "void"
        ]
        if not deposits:
            raise ValueError("delivery invoice requires a non-void deposit invoice for this agreement")
    if request.action == "evaluation-deposit" and request.offer_id == "founding_evaluation":
        agreements = {
            str(value(metadata, "tinyzkp_agreement_id"))
            for invoice in listed_invoices()
            if value(invoice, "status") != "void"
            if (metadata := value(invoice, "metadata", {}) or {})
            if value(metadata, "tinyzkp_offer_id") == "founding_evaluation"
            and value(metadata, "tinyzkp_milestone") == "deposit"
            and value(metadata, "tinyzkp_agreement_id")
        }
        if request.agreement_id not in agreements and len(agreements) >= 2:
            raise ValueError("the two Founding Evaluation slots are already allocated")


def create_invoice(request: BillingRequest, offer: dict[str, Any]) -> Any:
    amount_cents = offer_amount(offer) * 100 // 2
    milestone = "deposit" if request.action == "evaluation-deposit" else "delivery"
    metadata = {
        "tinyzkp_offer_id": request.offer_id,
        "tinyzkp_agreement_id": request.agreement_id,
        "tinyzkp_milestone": milestone,
    }
    invoice = stripe.Invoice.create(
        customer=request.customer_id,
        collection_method="send_invoice",
        days_until_due=request.days_until_due,
        auto_advance=False,
        metadata=metadata,
        description=f"TinyZKP agreement {request.agreement_id}",
        idempotency_key=f"tinyzkp-{request.agreement_id}-{milestone}-invoice",
    )
    invoice_id = value(invoice, "id")
    if not isinstance(invoice_id, str) or not invoice_id.startswith("in_"):
        raise ValueError("Stripe did not return a valid draft invoice ID")
    stripe.InvoiceItem.create(
        customer=request.customer_id,
        invoice=invoice_id,
        amount=amount_cents,
        currency="usd",
        description=f"{offer['name']} — {milestone}",
        metadata=metadata,
        idempotency_key=f"tinyzkp-{request.agreement_id}-{milestone}-item",
    )
    return stripe.Invoice.finalize_invoice(
        invoice_id,
        auto_advance=True,
        idempotency_key=f"tinyzkp-{request.agreement_id}-{milestone}-finalize",
    )


def create_annual_contract(request: BillingRequest, offer: dict[str, Any]) -> Any:
    price = stripe.Price.retrieve(request.stripe_price_id)
    validate_annual_price(price, offer)
    return stripe.Subscription.create(
        customer=request.customer_id,
        items=[{"price": request.stripe_price_id, "quantity": 1}],
        collection_method="send_invoice",
        days_until_due=request.days_until_due,
        metadata={
            "tinyzkp_offer_id": request.offer_id,
            "tinyzkp_agreement_id": request.agreement_id,
            "tinyzkp_support_hours_per_quarter": str(
                offer.get("included_support_hours_per_quarter", 0)
            ),
        },
        idempotency_key=f"tinyzkp-{request.agreement_id}-annual-subscription",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("evaluation-deposit", "evaluation-delivery", "annual-contract"))
    parser.add_argument("--offer-id", required=True)
    parser.add_argument("--customer-id", required=True)
    parser.add_argument("--agreement-id", required=True)
    parser.add_argument("--days-until-due", type=int, default=15)
    parser.add_argument("--stripe-price-id")
    parser.add_argument("--delivery-accepted-at")
    parser.add_argument("--expected-account-id", default=os.environ.get("STRIPE_EXPECTED_ACCOUNT_ID"))
    parser.add_argument("--expected-display-name", default=os.environ.get("STRIPE_EXPECTED_DISPLAY_NAME"))
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    request = BillingRequest(
        action=args.action,
        offer_id=args.offer_id,
        customer_id=args.customer_id,
        agreement_id=args.agreement_id,
        days_until_due=args.days_until_due,
        stripe_price_id=args.stripe_price_id,
        delivery_accepted_at=args.delivery_accepted_at,
    )
    offer = request.validate(load_offers())
    summary = plan(request, offer)
    if not args.apply:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    if os.environ.get("TINYZKP_ALLOW_CONTRACT_BILLING_WRITE") != "1":
        raise SystemExit("refusing Stripe write without TINYZKP_ALLOW_CONTRACT_BILLING_WRITE=1")
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    stripe.api_version = STRIPE_API_VERSION
    if not stripe.api_key:
        raise SystemExit("STRIPE_SECRET_KEY is required")
    account = stripe.Account.retrieve()
    verify_account(account, args.expected_account_id or "", args.expected_display_name or "")
    validate_release_availability(request)
    if request.action.startswith("evaluation-"):
        validate_evaluation_history(request)
    created = (
        create_annual_contract(request, offer)
        if request.action == "annual-contract"
        else create_invoice(request, offer)
    )
    summary.update({"mode": "apply", "stripe_object_id": value(created, "id")})
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
