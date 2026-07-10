#!/usr/bin/env python3
"""Plan or create tightly scoped Stripe invoices and annual contracts.

The default is read-only. Writes require --apply, exact account identity, and
TINYZKP_ALLOW_CONTRACT_BILLING_WRITE=1. This tool never creates Checkout links.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from urllib.parse import urlparse

import stripe

from legacy_billing_containment import STRIPE_API_VERSION, verify_account


ROOT = Path(__file__).resolve().parents[1]
OFFERS_PATH = ROOT / "site" / "pricing.json"
RELEASE_GATES_PATH = ROOT / "release" / "backend-v1-gates.json"
EVALUATIONS = {"founding_evaluation", "standard_evaluation"}
ANNUAL = {"tinyzkp_certified", "tinyzkp_fleet_oem"}
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
AGREEMENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_CONTRACT_DOCUMENT_BYTES = 16 * 1024 * 1024
CONTRACT_EVIDENCE_KEYS = {
    "schema_version",
    "agreement_id",
    "offer_id",
    "stripe_customer_id",
    "agreement_sha256",
    "scope_sha256",
    "signed_at",
    "delivery_acceptance_sha256",
    "delivery_accepted_at",
}


def value(item: Any, key: str, default: Any = None) -> Any:
    return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)


def load_offers() -> dict[str, dict[str, Any]]:
    payload = json.loads(OFFERS_PATH.read_text(encoding="utf-8"))
    return {offer["id"]: offer for offer in payload["offers"]}


def canonical_timestamp(raw: str, field: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.microsecond != 0:
        raise ValueError(f"{field} must include a UTC offset and second precision")
    canonical = parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if raw != canonical:
        raise ValueError(f"{field} must use canonical UTC Z form")
    return canonical


@dataclass(frozen=True)
class ContractEvidenceV1:
    schema_version: int
    agreement_id: str
    offer_id: str
    stripe_customer_id: str
    agreement_sha256: str
    scope_sha256: str
    signed_at: str
    delivery_acceptance_sha256: str | None
    delivery_accepted_at: str | None

    @classmethod
    def from_mapping(cls, payload: Any) -> "ContractEvidenceV1":
        if not isinstance(payload, dict) or set(payload) != CONTRACT_EVIDENCE_KEYS:
            raise ValueError("contract evidence fields are missing or unknown")
        return cls(**payload)

    def validate_for(self, action: str) -> None:
        if not isinstance(self.schema_version, int) or isinstance(self.schema_version, bool) or self.schema_version != 1:
            raise ValueError("contract evidence schema_version must equal 1")
        if not isinstance(self.agreement_id, str) or not AGREEMENT_ID.fullmatch(
            self.agreement_id
        ):
            raise ValueError("contract evidence agreement_id is malformed")
        if not isinstance(self.offer_id, str) or self.offer_id not in EVALUATIONS | ANNUAL:
            raise ValueError("contract evidence offer_id is unsupported")
        if not isinstance(self.stripe_customer_id, str) or not self.stripe_customer_id.startswith(
            "cus_"
        ):
            raise ValueError("contract evidence stripe_customer_id is malformed")
        for field in ("agreement_sha256", "scope_sha256"):
            raw = getattr(self, field)
            if not isinstance(raw, str) or not HEX_SHA256.fullmatch(raw):
                raise ValueError(f"contract evidence {field} must be lowercase SHA-256")
        canonical_timestamp(self.signed_at, "signed_at")
        signed_at = datetime.fromisoformat(self.signed_at.replace("Z", "+00:00"))
        if signed_at > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("signed_at cannot be in the future")
        if action == "evaluation-delivery":
            if not isinstance(self.delivery_acceptance_sha256, str) or not HEX_SHA256.fullmatch(
                self.delivery_acceptance_sha256
            ):
                raise ValueError("delivery invoice requires delivery acceptance SHA-256")
            canonical_timestamp(self.delivery_accepted_at or "", "delivery_accepted_at")
            accepted_at = datetime.fromisoformat(
                (self.delivery_accepted_at or "").replace("Z", "+00:00")
            )
            if accepted_at < signed_at:
                raise ValueError("delivery_accepted_at cannot precede signed_at")
        elif self.delivery_acceptance_sha256 is not None or self.delivery_accepted_at is not None:
            raise ValueError("delivery acceptance evidence is valid only for a delivery invoice")

    def digest(self) -> str:
        canonical = json.dumps(asdict(self), separators=(",", ":"), sort_keys=True).encode()
        return hashlib.sha256(canonical).hexdigest()


def load_contract_evidence(path: Path) -> ContractEvidenceV1:
    try:
        if path.is_symlink():
            raise ValueError("contract evidence must be a regular non-symlink file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("contract evidence must be a regular non-symlink file")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ValueError("contract evidence must be owner-only (0600 or stricter)")
            raw = handle.read(MAX_EVIDENCE_BYTES + 1)
        if not 0 < len(raw) <= MAX_EVIDENCE_BYTES:
            raise ValueError("contract evidence is empty or exceeds 64 KiB")
        payload = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("contract evidence is not valid JSON") from error
    return ContractEvidenceV1.from_mapping(payload)


def private_document_sha256(path: Path, label: str) -> str:
    try:
        if path.is_symlink():
            raise ValueError(f"{label} must be a regular non-symlink file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"{label} must be a regular non-symlink file")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ValueError(f"{label} must be owner-only (0600 or stricter)")
            if not 0 < metadata.st_size <= MAX_CONTRACT_DOCUMENT_BYTES:
                raise ValueError(f"{label} is empty or exceeds 16 MiB")
            digest = hashlib.sha256()
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
            return digest.hexdigest()
    except OSError as error:
        raise ValueError(f"{label} is unavailable or unsafe") from error


def verify_contract_documents(
    evidence: ContractEvidenceV1,
    action: str,
    *,
    agreement_document: Path,
    scope_document: Path,
    delivery_acceptance_document: Path | None,
) -> None:
    if private_document_sha256(agreement_document, "agreement document") != evidence.agreement_sha256:
        raise ValueError("agreement document does not match contract evidence")
    if private_document_sha256(scope_document, "scope document") != evidence.scope_sha256:
        raise ValueError("scope document does not match contract evidence")
    if action == "evaluation-delivery":
        if delivery_acceptance_document is None:
            raise ValueError("delivery invoice requires the written acceptance document")
        if (
            private_document_sha256(
                delivery_acceptance_document, "delivery acceptance document"
            )
            != evidence.delivery_acceptance_sha256
        ):
            raise ValueError("delivery acceptance document does not match contract evidence")
    elif delivery_acceptance_document is not None:
        raise ValueError("delivery acceptance document is valid only for a delivery invoice")


@dataclass(frozen=True)
class BillingRequest:
    action: str
    offer_id: str
    customer_id: str
    agreement_id: str
    days_until_due: int
    evidence: ContractEvidenceV1
    stripe_price_id: str | None = None

    def validate(self, offers: dict[str, dict[str, Any]]) -> dict[str, Any]:
        if self.offer_id not in offers:
            raise ValueError("unknown offer")
        if not isinstance(self.customer_id, str) or not self.customer_id.startswith("cus_"):
            raise ValueError("customer_id must be a Stripe customer ID")
        if not isinstance(self.agreement_id, str) or not AGREEMENT_ID.fullmatch(
            self.agreement_id
        ):
            raise ValueError("agreement_id must use 1-80 safe identifier characters")
        if (
            not isinstance(self.days_until_due, int)
            or isinstance(self.days_until_due, bool)
            or not 1 <= self.days_until_due <= 60
        ):
            raise ValueError("days_until_due must be between 1 and 60")
        self.evidence.validate_for(self.action)
        if (
            self.evidence.agreement_id != self.agreement_id
            or self.evidence.offer_id != self.offer_id
            or self.evidence.stripe_customer_id != self.customer_id
        ):
            raise ValueError("contract evidence does not bind this agreement, offer, and customer")
        if self.action in {"evaluation-deposit", "evaluation-delivery"}:
            if self.offer_id not in EVALUATIONS:
                raise ValueError("evaluation actions require an evaluation offer")
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


def validate_sender_identity_gate() -> None:
    """Prevent Stripe from sending under an unrelated business identity."""
    if os.environ.get("TINYZKP_CONTRACT_SENDER_IDENTITY_CONFIRMED") != "1":
        raise ValueError(
            "contract billing is blocked until Stripe's customer-facing sender identity "
            "is verified as TinyZKP"
        )


def validate_customer_facing_sender_identity(account: Any) -> None:
    profile = value(account, "business_profile", {}) or {}
    public_name = str(value(profile, "name", "")).strip()
    support_email = str(value(profile, "support_email", "")).strip().lower()
    support_url = str(value(profile, "support_url", "")).strip()
    email_local, email_separator, email_domain = support_email.rpartition("@")
    parsed_url = urlparse(support_url)
    hostname = (parsed_url.hostname or "").lower()
    if (
        public_name.casefold() != "tinyzkp"
        or not email_local
        or email_separator != "@"
        or email_domain != "tinyzkp.com"
        or parsed_url.scheme != "https"
        or hostname not in {"tinyzkp.com", "www.tinyzkp.com"}
    ):
        raise ValueError(
            "Stripe customer-facing business name, support email, and URL must identify TinyZKP"
        )


def plan(request: BillingRequest, offer: dict[str, Any]) -> dict[str, Any]:
    amount_dollars = offer_amount(offer)
    if request.action.startswith("evaluation-"):
        amount_dollars //= 2
    bound = {
        "action": request.action,
        "offer_id": request.offer_id,
        "customer_id": request.customer_id,
        "agreement_id": request.agreement_id,
        "amount_cents": amount_dollars * 100,
        "currency": "usd",
        "collection_method": "send_invoice",
        "days_until_due": request.days_until_due,
        "public_checkout": False,
        "stripe_price_id": request.stripe_price_id,
        "contract_evidence_sha256": request.evidence.digest(),
        "agreement_sha256": request.evidence.agreement_sha256,
        "scope_sha256": request.evidence.scope_sha256,
        "signed_at": request.evidence.signed_at,
        "delivery_acceptance_sha256": request.evidence.delivery_acceptance_sha256,
        "delivery_accepted_at": request.evidence.delivery_accepted_at,
    }
    plan_sha256 = hashlib.sha256(
        json.dumps(bound, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    return {"mode": "read_only", **bound, "plan_sha256": plan_sha256}


def contract_metadata(
    request: BillingRequest, milestone: str, plan_sha256: str
) -> dict[str, str]:
    metadata = {
        "tinyzkp_offer_id": request.offer_id,
        "tinyzkp_agreement_id": request.agreement_id,
        "tinyzkp_milestone": milestone,
        "tinyzkp_contract_evidence_sha256": request.evidence.digest(),
        "tinyzkp_agreement_sha256": request.evidence.agreement_sha256,
        "tinyzkp_scope_sha256": request.evidence.scope_sha256,
        "tinyzkp_signed_at": request.evidence.signed_at,
        "tinyzkp_plan_sha256": plan_sha256,
    }
    if request.evidence.delivery_acceptance_sha256:
        metadata["tinyzkp_delivery_acceptance_sha256"] = (
            request.evidence.delivery_acceptance_sha256
        )
        metadata["tinyzkp_delivery_accepted_at"] = request.evidence.delivery_accepted_at or ""
    return metadata


def validate_contract_customer(customer: Any, request: BillingRequest) -> None:
    metadata = value(customer, "metadata", {}) or {}
    email = value(customer, "email")
    if (
        value(customer, "id") != request.customer_id
        or value(customer, "deleted") is True
        or not isinstance(email, str)
        or "@" not in email
        or value(metadata, "tinyzkp_contract_customer") != "true"
        or value(metadata, "tinyzkp_agreement_id") != request.agreement_id
        or value(metadata, "tinyzkp_offer_id") != request.offer_id
    ):
        raise ValueError(
            "Stripe customer is not an active, contract-tagged TinyZKP customer for this agreement"
        )


def create_stripe_client(api_key: str) -> Any:
    return stripe.StripeClient(
        api_key,
        stripe_version=STRIPE_API_VERSION,
        max_network_retries=2,
    )


def validate_annual_price(price: Any, offer: dict[str, Any]) -> None:
    recurring = value(price, "recurring", {}) or {}
    expected = offer_amount(offer) * 100
    if value(price, "active") is not True:
        raise ValueError("annual Stripe price is inactive")
    if value(price, "currency") != "usd" or value(price, "unit_amount") != expected:
        raise ValueError("annual Stripe price amount/currency does not match the offer source")
    if value(recurring, "interval") != "year" or value(recurring, "interval_count", 1) != 1:
        raise ValueError("annual Stripe price must recur exactly yearly")


def listed_invoices(client: Any, *, customer_id: str | None = None) -> list[Any]:
    params: dict[str, Any] = {"limit": 100}
    if customer_id:
        params["customer"] = customer_id
    page = client.v1.invoices.list(params)
    auto_paging_iter = getattr(page, "auto_paging_iter", None)
    if callable(auto_paging_iter):
        return list(auto_paging_iter())
    return list(value(page, "data", []) or [])


def validate_evaluation_history(
    request: BillingRequest, client: Any, plan_sha256: str
) -> None:
    """Enforce founding slots and deposit-before-delivery from Stripe records."""
    milestone = "deposit" if request.action == "evaluation-deposit" else "delivery"
    customer_invoices = listed_invoices(client, customer_id=request.customer_id)
    for invoice in customer_invoices:
        metadata = value(invoice, "metadata", {}) or {}
        if (
            value(invoice, "status") != "void"
            and value(metadata, "tinyzkp_offer_id") == request.offer_id
            and value(metadata, "tinyzkp_agreement_id") == request.agreement_id
            and value(metadata, "tinyzkp_milestone") == milestone
            and value(metadata, "tinyzkp_plan_sha256") != plan_sha256
        ):
            raise ValueError(
                "an existing invoice for this agreement milestone has a different plan"
            )
    if request.action == "evaluation-delivery":
        deposits = [
            invoice
            for invoice in customer_invoices
            if value(value(invoice, "metadata", {}) or {}, "tinyzkp_offer_id")
            == request.offer_id
            and value(value(invoice, "metadata", {}) or {}, "tinyzkp_agreement_id")
            == request.agreement_id
            and value(value(invoice, "metadata", {}) or {}, "tinyzkp_milestone") == "deposit"
            and value(invoice, "status") == "paid"
        ]
        if not deposits:
            raise ValueError("delivery invoice requires a paid deposit invoice for this agreement")
    if request.action == "evaluation-deposit" and request.offer_id == "founding_evaluation":
        agreements = {
            str(value(metadata, "tinyzkp_agreement_id"))
            for invoice in listed_invoices(client)
            if value(invoice, "status") != "void"
            if (metadata := value(invoice, "metadata", {}) or {})
            if value(metadata, "tinyzkp_offer_id") == "founding_evaluation"
            and value(metadata, "tinyzkp_milestone") == "deposit"
            and value(metadata, "tinyzkp_agreement_id")
        }
        if request.agreement_id not in agreements and len(agreements) >= 2:
            raise ValueError("the two Founding Evaluation slots are already allocated")


def create_invoice(
    request: BillingRequest,
    offer: dict[str, Any],
    client: Any,
    plan_sha256: str,
) -> Any:
    amount_cents = offer_amount(offer) * 100 // 2
    milestone = "deposit" if request.action == "evaluation-deposit" else "delivery"
    metadata = contract_metadata(request, milestone, plan_sha256)
    idempotency = f"tinyzkp-{request.agreement_id}-{milestone}-{plan_sha256[:24]}"
    invoice = client.v1.invoices.create(
        {
            "customer": request.customer_id,
            "collection_method": "send_invoice",
            "days_until_due": request.days_until_due,
            "auto_advance": False,
            "metadata": metadata,
            "description": f"TinyZKP agreement {request.agreement_id}",
        },
        {"idempotency_key": f"{idempotency}-invoice"},
    )
    invoice_id = value(invoice, "id")
    if not isinstance(invoice_id, str) or not invoice_id.startswith("in_"):
        raise ValueError("Stripe did not return a valid draft invoice ID")
    client.v1.invoice_items.create(
        {
            "customer": request.customer_id,
            "invoice": invoice_id,
            "amount": amount_cents,
            "currency": "usd",
            "description": f"{offer['name']} — {milestone}",
            "metadata": metadata,
        },
        {"idempotency_key": f"{idempotency}-item"},
    )
    return client.v1.invoices.finalize_invoice(
        invoice_id,
        {"auto_advance": True},
        {"idempotency_key": f"{idempotency}-finalize"},
    )


def listed_subscriptions(client: Any, customer_id: str) -> list[Any]:
    page = client.v1.subscriptions.list(
        {"customer": customer_id, "status": "all", "limit": 100}
    )
    auto_paging_iter = getattr(page, "auto_paging_iter", None)
    if callable(auto_paging_iter):
        return list(auto_paging_iter())
    return list(value(page, "data", []) or [])


def validate_annual_history(
    request: BillingRequest, client: Any, plan_sha256: str
) -> None:
    for subscription in listed_subscriptions(client, request.customer_id):
        metadata = value(subscription, "metadata", {}) or {}
        if (
            value(subscription, "status") not in {"canceled", "incomplete_expired"}
            and value(metadata, "tinyzkp_offer_id") == request.offer_id
            and value(metadata, "tinyzkp_agreement_id") == request.agreement_id
            and value(metadata, "tinyzkp_plan_sha256") != plan_sha256
        ):
            raise ValueError(
                "an existing annual subscription for this agreement has a different plan"
            )


def create_annual_contract(
    request: BillingRequest,
    offer: dict[str, Any],
    client: Any,
    plan_sha256: str,
) -> Any:
    price = client.v1.prices.retrieve(request.stripe_price_id)
    validate_annual_price(price, offer)
    metadata = contract_metadata(request, "annual", plan_sha256)
    metadata["tinyzkp_support_hours_per_quarter"] = str(
        offer.get("included_support_hours_per_quarter", 0)
    )
    return client.v1.subscriptions.create(
        {
            "customer": request.customer_id,
            "items": [{"price": request.stripe_price_id, "quantity": 1}],
            "collection_method": "send_invoice",
            "days_until_due": request.days_until_due,
            "metadata": metadata,
        },
        {
            "idempotency_key": (
                f"tinyzkp-{request.agreement_id}-annual-{plan_sha256[:24]}-subscription"
            )
        },
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("evaluation-deposit", "evaluation-delivery", "annual-contract"))
    parser.add_argument("--offer-id", required=True)
    parser.add_argument("--customer-id", required=True)
    parser.add_argument("--agreement-id", required=True)
    parser.add_argument("--days-until-due", type=int, default=15)
    parser.add_argument("--stripe-price-id")
    parser.add_argument("--contract-evidence", type=Path, required=True)
    parser.add_argument("--agreement-document", type=Path, required=True)
    parser.add_argument("--scope-document", type=Path, required=True)
    parser.add_argument("--delivery-acceptance-document", type=Path)
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--expected-account-id", default=os.environ.get("STRIPE_EXPECTED_ACCOUNT_ID"))
    parser.add_argument("--expected-display-name", default=os.environ.get("STRIPE_EXPECTED_DISPLAY_NAME"))
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    evidence = load_contract_evidence(args.contract_evidence)
    verify_contract_documents(
        evidence,
        args.action,
        agreement_document=args.agreement_document,
        scope_document=args.scope_document,
        delivery_acceptance_document=args.delivery_acceptance_document,
    )
    request = BillingRequest(
        action=args.action,
        offer_id=args.offer_id,
        customer_id=args.customer_id,
        agreement_id=args.agreement_id,
        days_until_due=args.days_until_due,
        evidence=evidence,
        stripe_price_id=args.stripe_price_id,
    )
    offer = request.validate(load_offers())
    summary = plan(request, offer)
    if not args.apply:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    if (
        not isinstance(args.expected_plan_sha256, str)
        or not HEX_SHA256.fullmatch(args.expected_plan_sha256)
        or args.expected_plan_sha256 != summary["plan_sha256"]
    ):
        raise SystemExit("refusing Stripe write without the exact preview plan SHA-256")
    if os.environ.get("TINYZKP_ALLOW_CONTRACT_BILLING_WRITE") != "1":
        raise SystemExit("refusing Stripe write without TINYZKP_ALLOW_CONTRACT_BILLING_WRITE=1")
    validate_sender_identity_gate()
    if not args.expected_account_id or not args.expected_display_name:
        raise SystemExit("exact expected Stripe account ID and display name are required")
    api_key = os.environ.get("STRIPE_SECRET_KEY")
    if not api_key:
        raise SystemExit("STRIPE_SECRET_KEY is required")
    client = create_stripe_client(api_key)
    account = client.v1.accounts.retrieve_current()
    verify_account(account, args.expected_account_id or "", args.expected_display_name or "")
    validate_customer_facing_sender_identity(account)
    validate_release_availability(request)
    customer = client.v1.customers.retrieve(request.customer_id)
    validate_contract_customer(customer, request)
    if request.action.startswith("evaluation-"):
        validate_evaluation_history(request, client, summary["plan_sha256"])
    else:
        validate_annual_history(request, client, summary["plan_sha256"])
    created = (
        create_annual_contract(request, offer, client, summary["plan_sha256"])
        if request.action == "annual-contract"
        else create_invoice(request, offer, client, summary["plan_sha256"])
    )
    summary.update({"mode": "apply", "stripe_object_id": value(created, "id")})
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
