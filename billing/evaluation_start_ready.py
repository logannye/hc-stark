#!/usr/bin/env python3
"""Prove that a contracted TinyZKP evaluation is ready to start.

This command is read-only. It binds the signed agreement, completed acceptance
matrix, contract evidence, exact Stripe customer, and exact paid deposit invoice
into one machine-readable readiness report. It performs no Stripe mutation.
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
    expected_amount = billing.offer_amount(offer) * 100 // 2
    checks = (
        billing.value(invoice, "id") == invoice_id,
        billing.value(invoice, "customer") == request.customer_id,
        billing.value(invoice, "status") == "paid",
        billing.value(invoice, "currency") == "usd",
        billing.value(invoice, "amount_paid") == expected_amount,
        billing.value(invoice, "amount_remaining", 0) == 0,
        billing.value(invoice, "collection_method") == "send_invoice",
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
        "deposit_plan_sha256": plan_sha256,
        "workload_manifest_sha256": workload["manifest_sha256"],
        "workload_revision": workload["revision"],
        "logical_rows": workload["logical_rows"],
        "baseline_host_id": baseline["host_id"],
        "max_resident_bytes": candidate["max_resident_bytes"],
        "max_scratch_bytes": candidate["max_scratch_bytes"],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offer-id", required=True, choices=sorted(billing.EVALUATIONS))
    parser.add_argument("--customer-id", required=True)
    parser.add_argument("--agreement-id", required=True)
    parser.add_argument("--deposit-invoice-id", required=True)
    parser.add_argument("--days-until-due", type=int, default=15)
    parser.add_argument("--contract-evidence", type=Path, required=True)
    parser.add_argument("--agreement-document", type=Path, required=True)
    parser.add_argument("--scope-document", type=Path, required=True)
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
    billing.verify_contract_documents(
        evidence,
        "evaluation-deposit",
        agreement_document=args.agreement_document,
        scope_document=args.scope_document,
        delivery_acceptance_document=None,
    )
    request = billing.BillingRequest(
        action="evaluation-deposit",
        offer_id=args.offer_id,
        customer_id=args.customer_id,
        agreement_id=args.agreement_id,
        days_until_due=args.days_until_due,
        evidence=evidence,
    )
    offer = request.validate(billing.load_offers())
    plan_sha256 = billing.plan(request, offer)["plan_sha256"]
    acceptance = billing.validate_acceptance_matrix(args.scope_document, evidence)

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
