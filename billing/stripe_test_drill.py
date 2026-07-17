#!/usr/bin/env python3
"""Run or verify a fail-closed Stripe *test-mode* evaluation-invoice drill.

Verification is offline. The networked drill is available only with ``--apply``,
an ``sk_test_`` key, an explicit write gate, and exact test account/customer
identity. It derives the exact deposit from the selected evaluation offer,
then proves two isolated lifecycles without customer email: one invoice is
created, finalized, paid, and retrieved; the other is created, finalized,
retrieved, and voided. It never calls Stripe's invoice-send API or creates
Checkout objects.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any

import stripe

from legacy_billing_containment import (
    STRIPE_API_VERSION,
    account_display_name,
    verify_account,
)


SCHEMA_VERSION = "tinyzkp-stripe-test-drill-v3"
CURRENCY = "usd"
TEST_PAYMENT_METHOD = "pm_card_visa"
WRITE_GATE_ENV = "TINYZKP_ALLOW_STRIPE_TEST_DRILL_WRITE"
ROOT = Path(__file__).resolve().parents[1]
OFFERS_PATH = ROOT / "site" / "pricing.json"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
EVIDENCE_KEYS = {
    "schema_version",
    "status",
    "stripe_api_version",
    "stripe_sdk_version",
    "stripe_account_id",
    "stripe_display_name",
    "stripe_customer_id",
    "stripe_paid_invoice_id",
    "stripe_void_invoice_id",
    "drill_id",
    "offer_id",
    "offer_sha256",
    "amount_cents",
    "currency",
    "collection_method",
    "days_until_due",
    "auto_advance",
    "livemode",
    "hosted_paid_invoice_url_sha256",
    "hosted_void_invoice_url_sha256",
    "paid_created_status",
    "paid_finalized_status",
    "payment_status",
    "paid_retrieved_status",
    "void_created_status",
    "void_finalized_status",
    "void_retrieved_status",
    "voided_status",
    "payment_method",
    "customer_email_present",
    "duplicate_prevention_verified",
    "send_api_invoked",
    "checkout_created",
    "void_cleanup_complete",
    "started_at",
    "completed_at",
    "release_sha",
    "operation_digest",
}


def value(item: Any, key: str, default: Any = None) -> Any:
    return (
        item.get(key, default)
        if isinstance(item, dict)
        else getattr(item, key, default)
    )


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def load_offer(offer_id: str) -> dict[str, Any]:
    payload = json.loads(OFFERS_PATH.read_text(encoding="utf-8"))
    matches = [
        offer
        for offer in payload.get("offers", [])
        if isinstance(offer, dict) and offer.get("id") == offer_id
    ]
    if len(matches) != 1 or offer_id not in {
        "founding_evaluation",
        "standard_evaluation",
    }:
        raise ValueError("Stripe test drill requires an exact evaluation offer")
    offer = matches[0]
    price = offer.get("price")
    milestones = offer.get("billing_milestones")
    if (
        not isinstance(price, int)
        or isinstance(price, bool)
        or price <= 0
        or not isinstance(milestones, dict)
        or set(milestones) != {"deposit_percent", "delivery_percent"}
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
            for value in milestones.values()
        )
        or sum(milestones.values()) != 100
    ):
        raise ValueError("evaluation offer has invalid price or billing milestones")
    return offer


def offer_digest(offer: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(offer))


def deposit_amount_cents(offer: dict[str, Any]) -> int:
    numerator = int(offer["price"]) * 100 * int(
        offer["billing_milestones"]["deposit_percent"]
    )
    if numerator % 100:
        raise ValueError("evaluation deposit does not resolve to whole cents")
    return numerator // 100


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_timestamp(raw: Any, field: str) -> datetime:
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
    return parsed


def evidence_digest(payload: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(payload))


def validate_evidence(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != EVIDENCE_KEYS:
        raise ValueError("Stripe test drill evidence fields are missing or unknown")
    if payload["schema_version"] != SCHEMA_VERSION or payload["status"] != "passed":
        raise ValueError("Stripe test drill evidence is not a passing v3 record")
    if payload["stripe_api_version"] != STRIPE_API_VERSION:
        raise ValueError("Stripe test drill API version does not match production")
    if not isinstance(payload["stripe_sdk_version"], str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", payload["stripe_sdk_version"]
    ):
        raise ValueError("Stripe test drill SDK version is malformed")
    if not isinstance(payload["stripe_account_id"], str) or not payload[
        "stripe_account_id"
    ].startswith("acct_"):
        raise ValueError("Stripe test drill account ID is malformed")
    if (
        not isinstance(payload["stripe_display_name"], str)
        or not payload["stripe_display_name"].strip()
    ):
        raise ValueError("Stripe test drill display name is required")
    if not isinstance(payload["stripe_customer_id"], str) or not payload[
        "stripe_customer_id"
    ].startswith("cus_"):
        raise ValueError("Stripe test drill customer ID is malformed")
    for field in ("stripe_paid_invoice_id", "stripe_void_invoice_id"):
        if not isinstance(payload[field], str) or not payload[field].startswith("in_"):
            raise ValueError(f"Stripe test drill {field} is malformed")
    if payload["stripe_paid_invoice_id"] == payload["stripe_void_invoice_id"]:
        raise ValueError("Stripe test drill requires separate paid and void invoices")
    if (
        not isinstance(payload["drill_id"], str)
        or SAFE_ID.fullmatch(payload["drill_id"]) is None
    ):
        raise ValueError("Stripe test drill ID is malformed")
    offer = load_offer(payload["offer_id"])
    if payload["offer_sha256"] != offer_digest(offer):
        raise ValueError("Stripe test drill offer digest does not match pricing source")
    exact = {
        "amount_cents": deposit_amount_cents(offer),
        "currency": CURRENCY,
        "collection_method": "send_invoice",
        "days_until_due": 15,
        "auto_advance": False,
        "livemode": False,
        "paid_created_status": "draft",
        "paid_finalized_status": "open",
        "payment_status": "paid",
        "paid_retrieved_status": "paid",
        "void_created_status": "draft",
        "void_finalized_status": "open",
        "voided_status": "void",
        "payment_method": TEST_PAYMENT_METHOD,
        "customer_email_present": False,
        "duplicate_prevention_verified": True,
        "send_api_invoked": False,
        "checkout_created": False,
        "void_cleanup_complete": True,
    }
    for field, expected in exact.items():
        if payload[field] != expected:
            raise ValueError(f"Stripe test drill {field} must equal {expected!r}")
    if payload["void_retrieved_status"] not in {"open", "void"}:
        raise ValueError(
            "Stripe test drill void_retrieved_status must be open or void"
        )
    for field in (
        "hosted_paid_invoice_url_sha256",
        "hosted_void_invoice_url_sha256",
        "operation_digest",
    ):
        if (
            not isinstance(payload[field], str)
            or HEX_SHA256.fullmatch(payload[field]) is None
        ):
            raise ValueError(f"Stripe test drill {field} must be lowercase SHA-256")
    if (
        not isinstance(payload["release_sha"], str)
        or re.fullmatch(r"[0-9a-f]{40}", payload["release_sha"]) is None
    ):
        raise ValueError("Stripe test drill release_sha must be a full Git SHA")
    started = canonical_timestamp(payload["started_at"], "started_at")
    completed = canonical_timestamp(payload["completed_at"], "completed_at")
    if completed < started:
        raise ValueError("Stripe test drill completed_at cannot precede started_at")
    return payload


def load_evidence(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink():
            raise ValueError("Stripe test drill evidence must not be a symlink")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("Stripe test drill evidence must be a regular file")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ValueError("Stripe test drill evidence must be owner-only")
            if metadata.st_uid != os.geteuid():
                raise ValueError("Stripe test drill evidence must be operator-owned")
            raw = handle.read(64 * 1024 + 1)
        if not raw or len(raw) > 64 * 1024:
            raise ValueError("Stripe test drill evidence is empty or oversized")
        payload = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"forbidden JSON number: {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(
            "Stripe test drill evidence is unavailable or invalid"
        ) from error
    return validate_evidence(payload)


def atomic_write_owner_only(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.stat()
    if stat.S_IMODE(parent.st_mode) & 0o077 or parent.st_uid != os.geteuid():
        raise ValueError("Stripe test drill evidence directory must be owner-only")
    if path.exists() or path.is_symlink():
        raise ValueError("refusing to replace existing Stripe test drill evidence")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def create_client(api_key: str) -> Any:
    return stripe.StripeClient(
        api_key,
        stripe_version=STRIPE_API_VERSION,
        max_network_retries=2,
    )


def _assert_test_object(item: Any, label: str) -> None:
    if value(item, "livemode") is not False:
        raise ValueError(f"{label} is not a Stripe test-mode object")


def _validate_invoice(
    invoice: Any,
    *,
    invoice_id: str,
    customer_id: str,
    drill_id: str,
    lifecycle: str,
    status: str,
    amount_cents: int,
    offer_id: str,
    offer_sha256: str,
) -> None:
    _assert_test_object(invoice, "invoice")
    metadata = value(invoice, "metadata", {}) or {}
    if (
        value(invoice, "id") != invoice_id
        or value(invoice, "customer") != customer_id
        or value(invoice, "status") != status
        or value(invoice, "collection_method") != "send_invoice"
        or value(invoice, "auto_advance") is not False
        or value(metadata, "tinyzkp_test_drill") != "true"
        or value(metadata, "tinyzkp_test_drill_id") != drill_id
        or value(metadata, "tinyzkp_test_drill_lifecycle") != lifecycle
        or value(metadata, "tinyzkp_offer_id") != offer_id
        or value(metadata, "tinyzkp_offer_sha256") != offer_sha256
    ):
        raise ValueError(
            f"Stripe test invoice is not the expected {status} drill object"
        )
    if status != "draft" and value(invoice, "total") != amount_cents:
        raise ValueError("Stripe test invoice total differs from the selected offer")
    if status == "paid" and (
        value(invoice, "amount_paid") != amount_cents
        or value(invoice, "amount_remaining") != 0
    ):
        raise ValueError("Stripe test invoice was not paid in full")


def _timestamp_now() -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def run_drill(
    client: Any,
    *,
    account_id: str,
    display_name: str,
    customer_id: str,
    drill_id: str,
    offer_id: str,
    release_sha: str,
) -> dict[str, Any]:
    started_at = _timestamp_now()
    offer = load_offer(offer_id)
    offer_sha256 = offer_digest(offer)
    amount_cents = deposit_amount_cents(offer)
    account = client.v1.accounts.retrieve_current()
    verify_account(account, account_id, display_name)
    if account_display_name(account) != display_name:
        raise ValueError("Stripe test account display name changed during verification")
    customer = client.v1.customers.retrieve(customer_id)
    _assert_test_object(customer, "customer")
    if value(customer, "id") != customer_id or value(customer, "deleted") is True:
        raise ValueError("Stripe test customer is missing or deleted")
    if value(customer, "email") not in (None, ""):
        raise ValueError("Stripe test drill requires a customer without email")
    base_metadata = {
        "tinyzkp_test_drill": "true",
        "tinyzkp_test_drill_id": drill_id,
        "tinyzkp_offer_id": offer_id,
        "tinyzkp_offer_sha256": offer_sha256,
        "tinyzkp_release_sha": release_sha,
    }
    operation = {
        "account_id": account_id,
        "customer_id": customer_id,
        "drill_id": drill_id,
        "offer_id": offer_id,
        "offer_sha256": offer_sha256,
        "release_sha": release_sha,
        "amount_cents": amount_cents,
        "currency": CURRENCY,
        "stripe_api_version": STRIPE_API_VERSION,
    }
    operation_digest = sha256_bytes(canonical_json(operation))
    idempotency = f"tinyzkp-test-drill-{operation_digest[:32]}"
    invoice_ids: dict[str, str] = {}
    paid_invoice: Any | None = None
    paid_finalized: Any | None = None
    paid_result: Any | None = None
    paid_retrieved: Any | None = None
    void_invoice: Any | None = None
    void_finalized: Any | None = None
    void_retrieved: Any | None = None
    voided: Any | None = None

    def create_finalized_invoice(lifecycle: str) -> tuple[Any, Any, str]:
        metadata = {
            **base_metadata,
            "tinyzkp_test_drill_lifecycle": lifecycle,
        }
        invoice_params = {
            "customer": customer_id,
            "collection_method": "send_invoice",
            "days_until_due": 15,
            "auto_advance": False,
            "metadata": metadata,
            "description": (
                f"TinyZKP test-mode {offer['name']} deposit drill ({lifecycle})"
            ),
        }
        invoice_options = {
            "idempotency_key": f"{idempotency}-{lifecycle}-invoice"
        }
        created = client.v1.invoices.create(invoice_params, invoice_options)
        invoice_id = str(value(created, "id", ""))
        if not invoice_id.startswith("in_"):
            raise ValueError("Stripe test drill did not create an invoice")
        invoice_ids[lifecycle] = invoice_id
        _validate_invoice(
            created,
            invoice_id=invoice_id,
            customer_id=customer_id,
            drill_id=drill_id,
            lifecycle=lifecycle,
            status="draft",
            amount_cents=amount_cents,
            offer_id=offer_id,
            offer_sha256=offer_sha256,
        )
        duplicate = client.v1.invoices.create(invoice_params, invoice_options)
        if value(duplicate, "id") != invoice_id:
            raise ValueError("Stripe invoice idempotency did not prevent a duplicate")
        _validate_invoice(
            duplicate,
            invoice_id=invoice_id,
            customer_id=customer_id,
            drill_id=drill_id,
            lifecycle=lifecycle,
            status="draft",
            amount_cents=amount_cents,
            offer_id=offer_id,
            offer_sha256=offer_sha256,
        )
        item = client.v1.invoice_items.create(
            {
                "customer": customer_id,
                "invoice": invoice_id,
                "amount": amount_cents,
                "currency": CURRENCY,
                "description": (
                    f"TinyZKP {offer['name']} — test deposit ({lifecycle})"
                ),
                "metadata": metadata,
            },
            {"idempotency_key": f"{idempotency}-{lifecycle}-item"},
        )
        _assert_test_object(item, "invoice item")
        if (
            value(item, "invoice") != invoice_id
            or value(item, "amount") != amount_cents
        ):
            raise ValueError("Stripe test drill invoice item is malformed")
        finalized = client.v1.invoices.finalize_invoice(
            invoice_id,
            {"auto_advance": False},
            {"idempotency_key": f"{idempotency}-{lifecycle}-finalize"},
        )
        _validate_invoice(
            finalized,
            invoice_id=invoice_id,
            customer_id=customer_id,
            drill_id=drill_id,
            lifecycle=lifecycle,
            status="open",
            amount_cents=amount_cents,
            offer_id=offer_id,
            offer_sha256=offer_sha256,
        )
        hosted_url = value(finalized, "hosted_invoice_url")
        if not isinstance(hosted_url, str) or not hosted_url.startswith(
            "https://invoice.stripe.com/"
        ):
            raise ValueError("Stripe test drill invoice has no valid hosted URL")
        return created, finalized, hosted_url

    try:
        void_invoice, void_finalized, void_hosted_url = create_finalized_invoice(
            "void"
        )
        void_invoice_id = str(value(void_invoice, "id"))
        void_retrieved = client.v1.invoices.retrieve(void_invoice_id)
        void_retrieved_status = value(void_retrieved, "status")
        if void_retrieved_status not in {"open", "void"}:
            raise ValueError("Stripe void drill invoice has an unexpected status")
        _validate_invoice(
            void_retrieved,
            invoice_id=void_invoice_id,
            customer_id=customer_id,
            drill_id=drill_id,
            lifecycle="void",
            status=str(void_retrieved_status),
            amount_cents=amount_cents,
            offer_id=offer_id,
            offer_sha256=offer_sha256,
        )
        voided = (
            void_retrieved
            if void_retrieved_status == "void"
            else client.v1.invoices.void_invoice(
                void_invoice_id,
                {},
                {"idempotency_key": f"{idempotency}-void"},
            )
        )
        _validate_invoice(
            voided,
            invoice_id=void_invoice_id,
            customer_id=customer_id,
            drill_id=drill_id,
            lifecycle="void",
            status="void",
            amount_cents=amount_cents,
            offer_id=offer_id,
            offer_sha256=offer_sha256,
        )

        paid_invoice, paid_finalized, paid_hosted_url = create_finalized_invoice(
            "paid"
        )
        paid_invoice_id = str(value(paid_invoice, "id"))
        paid_result = client.v1.invoices.pay(
            paid_invoice_id,
            {"payment_method": TEST_PAYMENT_METHOD},
            {"idempotency_key": f"{idempotency}-pay"},
        )
        _validate_invoice(
            paid_result,
            invoice_id=paid_invoice_id,
            customer_id=customer_id,
            drill_id=drill_id,
            lifecycle="paid",
            status="paid",
            amount_cents=amount_cents,
            offer_id=offer_id,
            offer_sha256=offer_sha256,
        )
        paid_retrieved = client.v1.invoices.retrieve(paid_invoice_id)
        _validate_invoice(
            paid_retrieved,
            invoice_id=paid_invoice_id,
            customer_id=customer_id,
            drill_id=drill_id,
            lifecycle="paid",
            status="paid",
            amount_cents=amount_cents,
            offer_id=offer_id,
            offer_sha256=offer_sha256,
        )
    finally:
        for lifecycle, invoice_id in invoice_ids.items():
            current = client.v1.invoices.retrieve(invoice_id)
            status = value(current, "status")
            if status == "draft":
                client.v1.invoices.delete(invoice_id)
            elif status == "open":
                client.v1.invoices.void_invoice(
                    invoice_id,
                    {},
                    {
                        "idempotency_key": (
                            f"{idempotency}-{lifecycle}-cleanup-void"
                        )
                    },
                )
    if (
        paid_invoice is None
        or paid_finalized is None
        or paid_result is None
        or paid_retrieved is None
        or void_invoice is None
        or void_finalized is None
        or void_retrieved is None
        or voided is None
    ):
        raise ValueError("Stripe test drill did not complete both lifecycles")
    paid_invoice_id = str(value(paid_invoice, "id"))
    void_invoice_id = str(value(void_invoice, "id"))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "stripe_api_version": STRIPE_API_VERSION,
        "stripe_sdk_version": importlib.metadata.version("stripe"),
        "stripe_account_id": account_id,
        "stripe_display_name": display_name,
        "stripe_customer_id": customer_id,
        "stripe_paid_invoice_id": paid_invoice_id,
        "stripe_void_invoice_id": void_invoice_id,
        "drill_id": drill_id,
        "offer_id": offer_id,
        "offer_sha256": offer_sha256,
        "amount_cents": amount_cents,
        "currency": CURRENCY,
        "collection_method": "send_invoice",
        "days_until_due": 15,
        "auto_advance": False,
        "livemode": False,
        "hosted_paid_invoice_url_sha256": sha256_bytes(
            paid_hosted_url.encode("utf-8")
        ),
        "hosted_void_invoice_url_sha256": sha256_bytes(
            void_hosted_url.encode("utf-8")
        ),
        "paid_created_status": "draft",
        "paid_finalized_status": "open",
        "payment_status": "paid",
        "paid_retrieved_status": "paid",
        "void_created_status": "draft",
        "void_finalized_status": "open",
        "void_retrieved_status": str(value(void_retrieved, "status")),
        "voided_status": "void",
        "payment_method": TEST_PAYMENT_METHOD,
        "customer_email_present": False,
        "duplicate_prevention_verified": True,
        "send_api_invoked": False,
        "checkout_created": False,
        "void_cleanup_complete": True,
        "started_at": started_at,
        "completed_at": _timestamp_now(),
        "release_sha": release_sha,
        "operation_digest": operation_digest,
    }
    return validate_evidence(payload)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="verify an existing record offline")
    verify.add_argument("--evidence", type=Path, required=True)
    run = subparsers.add_parser("run", help="run an explicit Stripe test-mode drill")
    run.add_argument("--account-id", required=True)
    run.add_argument("--display-name", required=True)
    run.add_argument("--customer-id", required=True)
    run.add_argument("--drill-id", required=True)
    run.add_argument("--offer-id", required=True)
    run.add_argument("--release-sha", required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "verify":
        payload = load_evidence(args.evidence)
        print(
            json.dumps(
                {"status": "passed", "evidence_sha256": evidence_digest(payload)},
                sort_keys=True,
            )
        )
        return
    if not args.apply:
        raise SystemExit("refusing Stripe test mutation without --apply")
    if os.environ.get(WRITE_GATE_ENV) != "1":
        raise SystemExit(f"refusing Stripe test mutation without {WRITE_GATE_ENV}=1")
    api_key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not api_key.startswith("sk_test_") or api_key.startswith("sk_live_"):
        raise SystemExit(
            "Stripe test drill requires an sk_test_ key and rejects live keys"
        )
    if re.fullmatch(r"[0-9a-f]{40}", args.release_sha or "") is None:
        raise SystemExit("--release-sha must be a full lowercase Git SHA")
    if SAFE_ID.fullmatch(args.drill_id or "") is None:
        raise SystemExit("--drill-id is malformed")
    payload = run_drill(
        create_client(api_key),
        account_id=args.account_id,
        display_name=args.display_name,
        customer_id=args.customer_id,
        drill_id=args.drill_id,
        offer_id=args.offer_id,
        release_sha=args.release_sha,
    )
    atomic_write_owner_only(args.output, payload)
    print(
        json.dumps(
            {"status": "passed", "evidence_sha256": evidence_digest(payload)},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
