#!/usr/bin/env python3
"""Prove that a contracted TinyZKP evaluation or annual entitlement is ready.

This command is read-only. It binds the signed agreement, completed acceptance
matrix, contract evidence, exact Stripe customer, and exact paid deposit invoice
into one machine-readable readiness report. It performs no Stripe mutation.
For Certified/Fleet contracts it instead binds the exact subscription and
requires its initial subscription invoice to be fully paid before entitlement.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any

import contract_billing as billing
from legacy_billing_containment import verify_account


def validate_paid_deposit_invoice(
    invoice: Any,
    *,
    invoice_id: str,
    request: billing.BillingRequest,
    offer: dict[str, Any],
    plan_sha256: str,
) -> None:
    metadata = billing.value(invoice, "metadata", {}) or {}
    expected_amount = billing.evaluation_milestone_amount_cents(
        offer,
        "evaluation-deposit",
    )
    checks = (
        billing.value(invoice, "id") == invoice_id,
        billing.value(invoice, "customer") == request.customer_id,
        billing.value(invoice, "status") == "paid",
        billing.value(invoice, "currency") == "usd",
        billing.value(invoice, "amount_paid") == expected_amount,
        billing.value(invoice, "amount_remaining", 0) == 0,
        billing.value(invoice, "collection_method") == "send_invoice",
        billing.value(invoice, "auto_advance") is False,
        billing.value(metadata, "tinyzkp_offer_id") == request.offer_id,
        billing.value(metadata, "tinyzkp_agreement_id") == request.agreement_id,
        billing.value(metadata, "tinyzkp_milestone") == "deposit",
        billing.value(metadata, "tinyzkp_plan_sha256") == plan_sha256,
        billing.value(metadata, "tinyzkp_contract_evidence_sha256")
        == request.evidence.digest(),
        billing.value(metadata, "tinyzkp_scope_sha256") == request.evidence.scope_sha256,
    )
    if not all(checks):
        raise ValueError(
            "deposit invoice is not an exact paid, send-invoice milestone for this contract plan"
        )


def readiness_report(
    *,
    account: Any,
    invoice: Any,
    request: billing.BillingRequest,
    offer: dict[str, Any],
    acceptance: dict[str, Any],
    plan_sha256: str,
) -> dict[str, Any]:
    workload = acceptance["workload"]
    baseline = acceptance["baseline"]
    candidate = acceptance["candidate"]
    return {
        "schema_version": 1,
        "readiness_kind": "evaluation_start",
        "ready": True,
        "checked_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        "stripe_account_id": billing.value(account, "id"),
        "agreement_id": request.agreement_id,
        "offer_id": request.offer_id,
        "stripe_customer_id": request.customer_id,
        "deposit_invoice_id": billing.value(invoice, "id"),
        "deposit_amount_paid": billing.value(invoice, "amount_paid"),
        "contract_evidence_sha256": request.evidence.digest(),
        "agreement_sha256": request.evidence.agreement_sha256,
        "acceptance_matrix_sha256": request.evidence.scope_sha256,
        "agreement_gate_sha256": request.evidence.agreement_gate_sha256,
        "qualification_sha256": request.evidence.qualification_sha256,
        "partner_preflight_sha256": request.evidence.partner_preflight_sha256,
        "stripe_test_drill_sha256": request.evidence.stripe_test_drill_sha256,
        "deposit_plan_sha256": plan_sha256,
        "workload_manifest_sha256": workload["manifest_sha256"],
        "workload_revision": workload["revision"],
        "logical_rows": workload["logical_rows"],
        "baseline_host_id": baseline["host_id"],
        "max_resident_bytes": candidate["max_resident_bytes"],
        "max_scratch_bytes": candidate["max_scratch_bytes"],
    }


def object_id(value: Any) -> str:
    if isinstance(value, str):
        return value
    return str(billing.value(value, "id", "") or "")


def invoice_subscription_id(invoice: Any) -> str:
    direct = object_id(billing.value(invoice, "subscription"))
    if direct:
        return direct
    parent = billing.value(invoice, "parent", {}) or {}
    details = billing.value(parent, "subscription_details", {}) or {}
    return object_id(billing.value(details, "subscription"))


def validate_paid_annual_entitlement(
    subscription: Any,
    invoice: Any,
    *,
    subscription_id: str,
    invoice_id: str,
    request: billing.BillingRequest,
    offer: dict[str, Any],
    plan_sha256: str,
    release_binding: billing.ReleaseBindingV1,
) -> None:
    metadata = billing.value(subscription, "metadata", {}) or {}
    items = billing.value(billing.value(subscription, "items", {}) or {}, "data", []) or []
    exact_items = [
        item
        for item in items
        if object_id(billing.value(item, "price")) == request.stripe_price_id
        and billing.value(item, "quantity") == 1
    ]
    expected_amount = billing.contract_amount_cents(request, offer)
    checks = (
        object_id(subscription) == subscription_id,
        object_id(billing.value(subscription, "customer")) == request.customer_id,
        billing.value(subscription, "status") == "active",
        billing.value(subscription, "collection_method") == "send_invoice",
        object_id(billing.value(subscription, "latest_invoice")) == invoice_id,
        len(items) == 1,
        len(exact_items) == 1,
        billing.value(metadata, "tinyzkp_offer_id") == request.offer_id,
        billing.value(metadata, "tinyzkp_agreement_id") == request.agreement_id,
        billing.value(metadata, "tinyzkp_milestone") == "annual",
        billing.value(metadata, "tinyzkp_plan_sha256") == plan_sha256,
        billing.value(metadata, "tinyzkp_contract_evidence_sha256")
        == request.evidence.digest(),
        billing.value(metadata, "tinyzkp_scope_sha256") == request.evidence.scope_sha256,
        billing.value(metadata, "tinyzkp_negotiated_annual_amount_cents")
        == str(expected_amount),
        billing.value(metadata, "tinyzkp_backend_authorization_sha256")
        == release_binding.authorization_sha256,
        billing.value(metadata, "tinyzkp_backend_authorization_bundle_sha256")
        == release_binding.authorization_bundle_sha256,
        billing.value(metadata, "tinyzkp_backend_release_sha")
        == release_binding.release_sha,
        billing.value(metadata, "tinyzkp_backend_source_tree_sha256")
        == release_binding.source_tree_sha256,
        object_id(invoice) == invoice_id,
        object_id(billing.value(invoice, "customer")) == request.customer_id,
        invoice_subscription_id(invoice) == subscription_id,
        billing.value(invoice, "status") == "paid",
        billing.value(invoice, "currency") == "usd",
        billing.value(invoice, "total") == expected_amount,
        billing.value(invoice, "amount_paid") == expected_amount,
        billing.value(invoice, "amount_remaining") == 0,
        billing.value(invoice, "collection_method") == "send_invoice",
        billing.value(invoice, "billing_reason") == "subscription_create",
    )
    if not all(checks):
        raise ValueError(
            "annual entitlement requires the exact active subscription and fully paid initial invoice"
        )


def annual_entitlement_report(
    *,
    account: Any,
    subscription: Any,
    invoice: Any,
    request: billing.BillingRequest,
    plan_sha256: str,
    release_binding: billing.ReleaseBindingV1,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "readiness_kind": "annual_entitlement",
        "ready": True,
        "checked_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        "stripe_account_id": billing.value(account, "id"),
        "agreement_id": request.agreement_id,
        "offer_id": request.offer_id,
        "stripe_customer_id": request.customer_id,
        "subscription_id": object_id(subscription),
        "initial_invoice_id": object_id(invoice),
        "initial_amount_paid": billing.value(invoice, "amount_paid"),
        "contract_evidence_sha256": request.evidence.digest(),
        "agreement_sha256": request.evidence.agreement_sha256,
        "scope_sha256": request.evidence.scope_sha256,
        "annual_plan_sha256": plan_sha256,
        "negotiated_annual_amount_cents": (
            request.evidence.negotiated_annual_amount_cents
        ),
        "backend_release_authorization_sha256": (
            release_binding.authorization_sha256
        ),
        "backend_release_authorization_bundle_sha256": (
            release_binding.authorization_bundle_sha256
        ),
        "backend_release_sha": release_binding.release_sha,
        "backend_source_tree_sha256": release_binding.source_tree_sha256,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offer-id",
        required=True,
        choices=sorted(billing.EVALUATIONS | billing.ANNUAL),
    )
    parser.add_argument("--customer-id", required=True)
    parser.add_argument("--agreement-id", required=True)
    parser.add_argument("--deposit-invoice-id")
    parser.add_argument("--annual-subscription-id")
    parser.add_argument("--annual-invoice-id")
    parser.add_argument("--stripe-price-id")
    parser.add_argument("--stripe-product-id")
    parser.add_argument("--days-until-due", type=int, default=15)
    parser.add_argument("--contract-evidence", type=Path, required=True)
    parser.add_argument("--agreement-document", type=Path, required=True)
    parser.add_argument("--scope-document", type=Path, required=True)
    parser.add_argument("--agreement-gate-document", type=Path)
    parser.add_argument("--qualification-document", type=Path)
    parser.add_argument("--partner-preflight-document", type=Path)
    parser.add_argument("--stripe-test-drill-document", type=Path)
    parser.add_argument(
        "--expected-account-id", default=os.environ.get("STRIPE_EXPECTED_ACCOUNT_ID")
    )
    parser.add_argument(
        "--expected-display-name", default=os.environ.get("STRIPE_EXPECTED_DISPLAY_NAME")
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    evidence = billing.load_contract_evidence(args.contract_evidence)
    annual = args.offer_id in billing.ANNUAL
    action = "annual-contract" if annual else "evaluation-deposit"
    billing.verify_contract_documents(
        evidence,
        action,
        agreement_document=args.agreement_document,
        scope_document=args.scope_document,
        delivery_acceptance_document=None,
        agreement_gate_document=getattr(args, "agreement_gate_document", None),
        qualification_document=getattr(args, "qualification_document", None),
        partner_preflight_document=getattr(args, "partner_preflight_document", None),
        stripe_test_drill_document=getattr(args, "stripe_test_drill_document", None),
        expected_stripe_account_id=args.expected_account_id,
        expected_stripe_display_name=args.expected_display_name,
        stripe_price_id=args.stripe_price_id,
        stripe_product_id=args.stripe_product_id,
    )
    request = billing.BillingRequest(
        action=action,
        offer_id=args.offer_id,
        customer_id=args.customer_id,
        agreement_id=args.agreement_id,
        days_until_due=args.days_until_due,
        evidence=evidence,
        stripe_price_id=args.stripe_price_id,
        stripe_product_id=args.stripe_product_id,
    )
    offer = request.validate(billing.load_offers())
    summary, release_binding = billing.prepare_plan(request, offer)
    plan_sha256 = summary["plan_sha256"]
    acceptance = (
        None
        if annual
        else billing.validate_acceptance_matrix(
            args.scope_document,
            evidence,
            expected_sha256=evidence.scope_sha256,
        )
    )

    if not args.expected_account_id or not args.expected_display_name:
        raise SystemExit("exact expected Stripe account ID and display name are required")
    api_key = os.environ.get("STRIPE_SECRET_KEY")
    if not api_key:
        raise SystemExit("STRIPE_SECRET_KEY is required for the read-only readiness check")
    client = billing.create_stripe_client(api_key)
    account = client.v1.accounts.retrieve_current()
    verify_account(account, args.expected_account_id, args.expected_display_name)
    customer = client.v1.customers.retrieve(request.customer_id)
    billing.validate_contract_customer(customer, request)
    if annual:
        if (
            not args.annual_subscription_id
            or not args.annual_invoice_id
            or release_binding is None
        ):
            raise SystemExit(
                "annual readiness requires subscription/invoice IDs and release binding"
            )
        subscription = client.v1.subscriptions.retrieve(
            args.annual_subscription_id,
            {"expand": ["latest_invoice", "items.data.price"]},
        )
        invoice = client.v1.invoices.retrieve(args.annual_invoice_id)
        validate_paid_annual_entitlement(
            subscription,
            invoice,
            subscription_id=args.annual_subscription_id,
            invoice_id=args.annual_invoice_id,
            request=request,
            offer=offer,
            plan_sha256=plan_sha256,
            release_binding=release_binding,
        )
        print(
            json.dumps(
                annual_entitlement_report(
                    account=account,
                    subscription=subscription,
                    invoice=invoice,
                    request=request,
                    plan_sha256=plan_sha256,
                    release_binding=release_binding,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if not args.deposit_invoice_id or acceptance is None:
        raise SystemExit("evaluation readiness requires --deposit-invoice-id")
    invoice = client.v1.invoices.retrieve(args.deposit_invoice_id)
    validate_paid_deposit_invoice(
        invoice,
        invoice_id=args.deposit_invoice_id,
        request=request,
        offer=offer,
        plan_sha256=plan_sha256,
    )
    print(
        json.dumps(
            readiness_report(
                account=account,
                invoice=invoice,
                request=request,
                offer=offer,
                acceptance=acceptance,
                plan_sha256=plan_sha256,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
