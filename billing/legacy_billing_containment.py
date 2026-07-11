#!/usr/bin/env python3
"""Inventory and contain an exact, reviewed set of legacy Stripe objects.

Read-only inventory is the default. No name, event-name, or price heuristic is
ever used to select a write target. An apply run requires an owner-reviewed
scope manifest bound to the complete live inventory digest, the exact preview
plan digest, a second environment write gate, and (for subscriptions) a strict
no-email notification/resolution ledger.
"""

from __future__ import annotations

import argparse
import datetime as dt
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterable

import stripe


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
from deploy_readiness_check import (  # noqa: E402
    load_private_env_file,
    reject_conflicting_inherited_environment,
)


STRIPE_API_VERSION = "2026-02-25.clover"
WRITE_GATE_ENV = "TINYZKP_ALLOW_LEGACY_BILLING_WRITE"
CHARGEABLE_SUBSCRIPTION_STATES = {"active", "trialing", "past_due", "unpaid", "paused"}
ALLOWED_RESOLUTIONS = {"refund", "credit", "none_due"}
ALLOWED_NOTIFICATION_CHANNELS = {
    "github",
    "linkedin",
    "signal",
    "discord",
    "telegram",
    "matrix",
    "phone",
    "certified_mail",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_PREFIXES = {
    "product_ids": "prod_",
    "price_ids": "price_",
    "payment_link_ids": "plink_",
    "meter_ids": "mtr_",
    "subscription_ids": "sub_",
    "open_invoice_ids": "in_",
}
SCOPE_KEYS = {
    "schema_version",
    "stripe_account_id",
    "stripe_display_name",
    "inventory_sha256",
    "selections",
}
LEDGER_KEYS = {"schema_version", "stripe_account_id", "inventory_sha256", "subscriptions"}
LEDGER_RECORD_KEYS = {
    "subscription_id",
    "customer_id",
    "notified_at",
    "notification_channel",
    "notification_evidence_sha256",
    "resolution",
    "resolution_object_id",
    "resolution_amount",
    "currency",
    "resolution_evidence_sha256",
    "approved_open_invoice_ids",
}


def _value(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        current = _value(current, key)
        if current is None:
            return None
    return current


def _all(page: Any) -> list[Any]:
    iterator = getattr(page, "auto_paging_iter", None)
    return list(iterator()) if callable(iterator) else list(_value(page, "data", []))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _metadata(value: Any) -> dict[str, str]:
    raw = _value(value, "metadata", {}) or {}
    if not isinstance(raw, dict):
        raw = dict(raw)
    return {str(key): str(item) for key, item in sorted(raw.items())}


def _object_id(value: Any) -> str:
    return str(_value(value, "id", "")).strip()


def _related_id(value: Any) -> str:
    if isinstance(value, str):
        return value
    return _object_id(value)


def account_display_name(account: Any) -> str:
    return str(
        _nested(account, "settings", "dashboard", "display_name")
        or _nested(account, "business_profile", "name")
        or ""
    ).strip()


def verify_account(account: Any, expected_account_id: str, expected_display_name: str) -> None:
    actual_id = _object_id(account)
    actual_name = account_display_name(account)
    if not expected_account_id or not expected_display_name:
        raise RuntimeError("expected account ID and display name are required")
    if actual_id != expected_account_id or actual_name.casefold() != expected_display_name.casefold():
        raise RuntimeError(
            f"Stripe account mismatch: expected {expected_account_id!r}/{expected_display_name!r}, "
            f"got {actual_id!r}/{actual_name!r}"
        )


def subscription_product_ids(subscription: Any) -> set[str]:
    items = _nested(subscription, "items", "data") or []
    return {
        product_id
        for item in items
        if (product_id := _related_id(_nested(item, "price", "product")))
    }


def payment_link_product_ids(link: Any) -> set[str]:
    items = _nested(link, "line_items", "data") or []
    return {
        product_id
        for item in items
        if (product_id := _related_id(_nested(item, "price", "product")))
    }


@dataclass(frozen=True)
class Inventory:
    products: list[Any]
    prices: list[Any]
    payment_links: list[Any]
    subscriptions: list[Any]
    meters: list[Any]
    open_invoices: list[Any]

    def document(self, account: Any) -> dict[str, Any]:
        def sorted_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
            return sorted(records, key=lambda item: str(item["id"]))

        return {
            "schema_version": 1,
            "stripe_account_id": _object_id(account),
            "stripe_display_name": account_display_name(account),
            "objects": {
                "products": sorted_records(
                    {
                        "id": _object_id(item),
                        "name": str(_value(item, "name", "")),
                        "active": bool(_value(item, "active", False)),
                        "metadata": _metadata(item),
                    }
                    for item in self.products
                ),
                "prices": sorted_records(
                    {
                        "id": _object_id(item),
                        "product_id": _related_id(_value(item, "product")),
                        "active": bool(_value(item, "active", False)),
                        "currency": str(_value(item, "currency", "")),
                        "lookup_key": str(_value(item, "lookup_key", "") or ""),
                        "metadata": _metadata(item),
                    }
                    for item in self.prices
                ),
                "payment_links": sorted_records(
                    {
                        "id": _object_id(item),
                        "active": bool(_value(item, "active", False)),
                        "product_ids": sorted(payment_link_product_ids(item)),
                    }
                    for item in self.payment_links
                ),
                "subscriptions": sorted_records(
                    {
                        "id": _object_id(item),
                        "customer_id": _related_id(_value(item, "customer")),
                        "status": str(_value(item, "status", "")),
                        "pause_collection_behavior": str(
                            _nested(item, "pause_collection", "behavior") or ""
                        ),
                        "product_ids": sorted(subscription_product_ids(item)),
                    }
                    for item in self.subscriptions
                ),
                "meters": sorted_records(
                    {
                        "id": _object_id(item),
                        "event_name": str(_value(item, "event_name", "")),
                        "status": str(_value(item, "status", "")),
                    }
                    for item in self.meters
                ),
                "open_invoices": sorted_records(
                    {
                        "id": _object_id(item),
                        "customer_id": _related_id(_value(item, "customer")),
                        "subscription_id": _related_id(
                            _value(item, "subscription")
                            or _nested(item, "parent", "subscription_details", "subscription")
                        ),
                        "status": str(_value(item, "status", "")),
                        "amount_remaining": int(_value(item, "amount_remaining", 0) or 0),
                        "currency": str(_value(item, "currency", "")),
                    }
                    for item in self.open_invoices
                ),
            },
        }


def collect_inventory(verified_account: Any) -> Inventory:
    """List complete active/chargeable state only after account verification."""
    if not _object_id(verified_account):
        raise RuntimeError("verified Stripe account is required before inventory")
    products = _all(stripe.Product.list(active=True, limit=100))
    prices = _all(stripe.Price.list(active=True, limit=100))
    payment_links = []
    for link in _all(stripe.PaymentLink.list(active=True, limit=100)):
        payment_links.append(
            stripe.PaymentLink.retrieve(
                _object_id(link), expand=["line_items.data.price.product"]
            )
        )
    subscriptions = [
        item
        for item in _all(
            stripe.Subscription.list(
                status="all", limit=100, expand=["data.items.data.price.product"]
            )
        )
        if str(_value(item, "status", "")) in CHARGEABLE_SUBSCRIPTION_STATES
    ]
    meters = _all(stripe.billing.Meter.list(status="active", limit=100))
    open_invoices = _all(stripe.Invoice.list(status="open", limit=100))
    return Inventory(products, prices, payment_links, subscriptions, meters, open_invoices)


def inventory_digest(account: Any, inventory: Inventory) -> str:
    return _sha256(inventory.document(account))


def write_private_json(path: Path, value: Any) -> None:
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"refusing to replace symlink: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RuntimeError(f"inventory output is not owner-only: {path}")


def build_scope_template(account: Any, inventory: Inventory) -> dict[str, Any]:
    """Return an inventory-bound, deliberately empty review scope.

    Object selection is a human authorization boundary.  The generator binds
    the current account and complete inventory but never guesses which Stripe
    objects belong to TinyZKP.
    """

    return {
        "schema_version": 1,
        "stripe_account_id": _object_id(account),
        "stripe_display_name": account_display_name(account),
        "inventory_sha256": inventory_digest(account, inventory),
        "selections": {field: [] for field in ID_PREFIXES},
    }


def build_notification_ledger_template(
    account: Any,
    inventory: Inventory,
    scope: Scope,
) -> dict[str, Any]:
    """Return a fail-closed skeleton for selected legacy subscriptions.

    The skeleton copies only Stripe object identifiers and their relationships.
    Notification, approval, and refund/credit evidence remain invalid
    placeholders until an operator records actions performed outside this
    program through an approved no-email channel.
    """

    plan = build_plan(account, inventory, scope)
    actions = {(item["action"], item["object_id"]) for item in plan["actions"]}
    selected_subscriptions = sorted(
        object_id
        for action, object_id in actions
        if action == "pause_subscription"
    )
    selected_invoices = {
        object_id for action, object_id in actions if action == "void_open_invoice"
    }
    subscriptions = _objects_by_id(inventory.subscriptions)
    invoices = _objects_by_id(inventory.open_invoices)
    records: list[dict[str, Any]] = []
    for subscription_id in selected_subscriptions:
        subscription = subscriptions[subscription_id]
        approved_invoice_ids = sorted(
            invoice_id
            for invoice_id in selected_invoices
            if _related_id(_value(invoices[invoice_id], "subscription"))
            == subscription_id
        )
        records.append(
            {
                "subscription_id": subscription_id,
                "customer_id": _related_id(_value(subscription, "customer")),
                "notified_at": "REPLACE_RFC3339_UTC",
                "notification_channel": "REPLACE_NO_EMAIL_CHANNEL",
                "notification_evidence_sha256": "REPLACE_SHA256",
                "resolution": "REPLACE_refund_credit_or_none_due",
                "resolution_object_id": "REPLACE_OR_EMPTY_FOR_NONE_DUE",
                "resolution_amount": -1,
                "currency": "usd",
                "resolution_evidence_sha256": "REPLACE_SHA256",
                "approved_open_invoice_ids": approved_invoice_ids,
            }
        )
    return {
        "schema_version": 2,
        "stripe_account_id": _object_id(account),
        "inventory_sha256": inventory_digest(account, inventory),
        "subscriptions": records,
    }


@dataclass(frozen=True)
class Scope:
    stripe_account_id: str
    stripe_display_name: str
    inventory_sha256: str
    selections: dict[str, tuple[str, ...]]


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} must be a regular non-symlink file")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return payload


def load_scope_manifest(path: Path) -> Scope:
    payload = _load_json_object(path, "scope manifest")
    if set(payload) != SCOPE_KEYS or payload.get("schema_version") != 1:
        raise RuntimeError("scope manifest fields/schema_version are invalid")
    account_id = str(payload.get("stripe_account_id", "")).strip()
    display_name = str(payload.get("stripe_display_name", "")).strip()
    digest = str(payload.get("inventory_sha256", "")).strip().lower()
    if not account_id.startswith("acct_") or not display_name or not SHA256_RE.fullmatch(digest):
        raise RuntimeError("scope manifest account identity or inventory digest is invalid")
    raw_selections = payload.get("selections")
    if not isinstance(raw_selections, dict) or set(raw_selections) != set(ID_PREFIXES):
        raise RuntimeError(f"scope selections must contain exactly {sorted(ID_PREFIXES)}")
    selections: dict[str, tuple[str, ...]] = {}
    for field, prefix in ID_PREFIXES.items():
        raw_ids = raw_selections[field]
        if not isinstance(raw_ids, list) or not all(isinstance(item, str) for item in raw_ids):
            raise RuntimeError(f"scope selection {field} must be a string array")
        ids = tuple(item.strip() for item in raw_ids)
        if len(ids) != len(set(ids)) or any(not item.startswith(prefix) for item in ids):
            raise RuntimeError(f"scope selection {field} contains duplicate or malformed IDs")
        selections[field] = tuple(sorted(ids))
    return Scope(account_id, display_name, digest, selections)


def build_plan(account: Any, inventory: Inventory, scope: Scope) -> dict[str, Any]:
    document = inventory.document(account)
    digest = _sha256(document)
    if scope.stripe_account_id != _object_id(account):
        raise RuntimeError("scope manifest Stripe account ID mismatch")
    if scope.stripe_display_name.casefold() != account_display_name(account).casefold():
        raise RuntimeError("scope manifest Stripe display name mismatch")
    if scope.inventory_sha256 != digest:
        raise RuntimeError("scope manifest inventory digest is stale or mismatched")

    object_fields = {
        "product_ids": "products",
        "price_ids": "prices",
        "payment_link_ids": "payment_links",
        "meter_ids": "meters",
        "subscription_ids": "subscriptions",
        "open_invoice_ids": "open_invoices",
    }
    available: dict[str, dict[str, dict[str, Any]]] = {
        selection: {record["id"]: record for record in document["objects"][object_field]}
        for selection, object_field in object_fields.items()
    }
    for field, selected in scope.selections.items():
        missing = sorted(set(selected) - set(available[field]))
        if missing:
            raise RuntimeError(f"scope manifest {field} contains absent IDs: {missing}")

    selected_products = set(scope.selections["product_ids"])
    for price_id in scope.selections["price_ids"]:
        if available["price_ids"][price_id]["product_id"] not in selected_products:
            raise RuntimeError(f"selected price {price_id} is not bound to a selected product")
    for link_id in scope.selections["payment_link_ids"]:
        if not set(available["payment_link_ids"][link_id]["product_ids"]) <= selected_products:
            raise RuntimeError(f"selected Payment Link {link_id} references an unselected product")
    for subscription_id in scope.selections["subscription_ids"]:
        if not set(available["subscription_ids"][subscription_id]["product_ids"]) <= selected_products:
            raise RuntimeError(f"selected subscription {subscription_id} references an unselected product")
    selected_subscriptions = set(scope.selections["subscription_ids"])
    for invoice_id in scope.selections["open_invoice_ids"]:
        if available["open_invoice_ids"][invoice_id]["subscription_id"] not in selected_subscriptions:
            raise RuntimeError(f"selected invoice {invoice_id} is not bound to a selected subscription")

    actions = []
    for field, action in (
        ("payment_link_ids", "archive_payment_link"),
        ("price_ids", "archive_price"),
        ("product_ids", "archive_product"),
        ("meter_ids", "deactivate_meter"),
        ("subscription_ids", "pause_subscription"),
        ("open_invoice_ids", "void_open_invoice"),
    ):
        actions.extend({"action": action, "object_id": item} for item in scope.selections[field])
    plan = {
        "schema_version": 1,
        "stripe_account_id": _object_id(account),
        "stripe_display_name": account_display_name(account),
        "inventory_sha256": digest,
        "actions": actions,
    }
    return {**plan, "plan_sha256": _sha256(plan)}


def _parse_timestamp(value: Any) -> str:
    text = str(value or "").strip()
    if not text.endswith("Z"):
        raise RuntimeError("notification timestamps must be RFC3339 UTC values ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise RuntimeError("notification timestamp is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise RuntimeError("notification timestamp must be UTC")
    return text


def load_notification_ledger(
    path: Path | None,
    *,
    expected_account_id: str | None = None,
    expected_inventory_sha256: str | None = None,
) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    payload = _load_json_object(path, "notification ledger")
    if set(payload) != LEDGER_KEYS or payload.get("schema_version") != 2:
        raise RuntimeError("notification ledger fields/schema_version are invalid")
    if expected_account_id and payload.get("stripe_account_id") != expected_account_id:
        raise RuntimeError("notification ledger Stripe account mismatch")
    if expected_inventory_sha256 and payload.get("inventory_sha256") != expected_inventory_sha256:
        raise RuntimeError("notification ledger inventory digest mismatch")
    if not SHA256_RE.fullmatch(str(payload.get("inventory_sha256", ""))):
        raise RuntimeError("notification ledger inventory digest is invalid")
    records = payload.get("subscriptions")
    if not isinstance(records, list):
        raise RuntimeError("notification ledger subscriptions must be an array")
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != LEDGER_RECORD_KEYS:
            raise RuntimeError("notification ledger record fields are invalid")
        subscription_id = str(record["subscription_id"]).strip()
        customer_id = str(record["customer_id"]).strip()
        channel = str(record["notification_channel"]).strip()
        resolution = str(record["resolution"]).strip()
        currency = str(record["currency"]).strip().lower()
        amount = record["resolution_amount"]
        approved_invoices = record["approved_open_invoice_ids"]
        if subscription_id in result:
            raise RuntimeError(f"duplicate notification record for {subscription_id}")
        if not subscription_id.startswith("sub_") or not customer_id.startswith("cus_"):
            raise RuntimeError("notification ledger subscription/customer IDs are malformed")
        if channel not in ALLOWED_NOTIFICATION_CHANNELS or resolution not in ALLOWED_RESOLUTIONS:
            raise RuntimeError("notification channel or resolution is unsupported")
        if not isinstance(amount, int) or amount < 0 or not re.fullmatch(r"[a-z]{3}", currency):
            raise RuntimeError("resolution amount/currency are invalid")
        if resolution == "none_due":
            if amount != 0 or str(record["resolution_object_id"]).strip():
                raise RuntimeError("none_due requires zero amount and no resolution object")
        elif amount <= 0 or not str(record["resolution_object_id"]).strip():
            raise RuntimeError("refund/credit requires a positive amount and resolution object")
        for digest_field in ("notification_evidence_sha256", "resolution_evidence_sha256"):
            if not SHA256_RE.fullmatch(str(record[digest_field])):
                raise RuntimeError(f"{digest_field} must be a SHA-256 digest")
        if not isinstance(approved_invoices, list) or not all(
            isinstance(item, str) and item.startswith("in_") for item in approved_invoices
        ):
            raise RuntimeError("approved_open_invoice_ids must be an invoice ID array")
        if len(approved_invoices) != len(set(approved_invoices)):
            raise RuntimeError("approved_open_invoice_ids contains duplicates")
        result[subscription_id] = {
            **record,
            "notified_at": _parse_timestamp(record["notified_at"]),
            "approved_open_invoice_ids": sorted(approved_invoices),
        }
    return result


def _idempotency_key(action: str, object_id: str, plan_sha256: str) -> str:
    return f"tinyzkp-recovery-{action}-{object_id}-{plan_sha256[:16]}"


def _objects_by_id(values: Iterable[Any]) -> dict[str, Any]:
    return {_object_id(value): value for value in values}


def archive_catalog(inventory: Inventory, plan: dict[str, Any]) -> None:
    actions = {(item["action"], item["object_id"]) for item in plan["actions"]}
    digest = plan["plan_sha256"]
    for action, values, modify in (
        ("archive_payment_link", inventory.payment_links, stripe.PaymentLink.modify),
        ("archive_price", inventory.prices, stripe.Price.modify),
        ("archive_product", inventory.products, stripe.Product.modify),
    ):
        by_id = _objects_by_id(values)
        for _, object_id in sorted(item for item in actions if item[0] == action):
            if object_id not in by_id:
                raise RuntimeError(f"planned object disappeared before apply: {object_id}")
            modify(
                object_id,
                active=False,
                idempotency_key=_idempotency_key(action, object_id, digest),
            )
    for _, object_id in sorted(item for item in actions if item[0] == "deactivate_meter"):
        if object_id not in _objects_by_id(inventory.meters):
            raise RuntimeError(f"planned meter disappeared before apply: {object_id}")
        stripe.billing.Meter.deactivate(
            object_id,
            idempotency_key=_idempotency_key("deactivate_meter", object_id, digest),
        )


def pause_notified_subscriptions(
    inventory: Inventory,
    plan: dict[str, Any],
    ledger: dict[str, dict[str, Any]],
) -> None:
    actions = {(item["action"], item["object_id"]) for item in plan["actions"]}
    digest = plan["plan_sha256"]
    subscriptions = _objects_by_id(inventory.subscriptions)
    invoices = _objects_by_id(inventory.open_invoices)
    selected_subscriptions = sorted(item[1] for item in actions if item[0] == "pause_subscription")
    selected_invoices = sorted(item[1] for item in actions if item[0] == "void_open_invoice")
    approved_invoice_ids: set[str] = set()
    for subscription_id in selected_subscriptions:
        subscription = subscriptions.get(subscription_id)
        record = ledger.get(subscription_id)
        if subscription is None or record is None:
            raise RuntimeError(f"refusing to pause {subscription_id}: exact notification record missing")
        if record["customer_id"] != _related_id(_value(subscription, "customer")):
            raise RuntimeError(f"refusing to pause {subscription_id}: customer identity mismatch")
        approved_invoice_ids.update(record["approved_open_invoice_ids"])
    if approved_invoice_ids != set(selected_invoices):
        raise RuntimeError("notification ledger invoice approvals do not exactly match the plan")

    for subscription_id in selected_subscriptions:
        stripe.Subscription.modify(
            subscription_id,
            pause_collection={"behavior": "void"},
            metadata={
                "tinyzkp_backend_recovery": "2026-07",
                "tinyzkp_plan_sha256": digest,
            },
            idempotency_key=_idempotency_key("pause_subscription", subscription_id, digest),
        )
    for invoice_id in selected_invoices:
        if invoice_id not in invoices:
            raise RuntimeError(f"planned invoice disappeared before apply: {invoice_id}")
        stripe.Invoice.void_invoice(
            invoice_id,
            idempotency_key=_idempotency_key("void_open_invoice", invoice_id, digest),
        )


def require_apply_authorization(expected_plan_sha256: str | None, plan: dict[str, Any]) -> None:
    if os.environ.get(WRITE_GATE_ENV, "").strip() != "1":
        raise RuntimeError(f"apply requires {WRITE_GATE_ENV}=1")
    expected = str(expected_plan_sha256 or "").strip().lower()
    if not SHA256_RE.fullmatch(expected) or expected != plan["plan_sha256"]:
        raise RuntimeError("apply requires the exact reviewed --expected-plan-sha256")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-account-id", default=os.environ.get("STRIPE_EXPECTED_ACCOUNT_ID"))
    parser.add_argument(
        "--expected-display-name", default=os.environ.get("STRIPE_EXPECTED_DISPLAY_NAME")
    )
    parser.add_argument("--inventory-output", type=Path)
    parser.add_argument(
        "--scope-template-output",
        type=Path,
        help=(
            "Write an owner-only, current-inventory-bound scope skeleton with "
            "no selected objects"
        ),
    )
    parser.add_argument("--scope-manifest", type=Path)
    parser.add_argument(
        "--notification-template-output",
        type=Path,
        help=(
            "Write an owner-only fail-closed notification/resolution skeleton "
            "for the exact selected subscriptions"
        ),
    )
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--apply-catalog", action="store_true")
    parser.add_argument("--pause-notified-subscriptions", action="store_true")
    parser.add_argument("--notification-ledger", type=Path)
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Owner-only production environment file; avoids shell-sourcing Stripe credentials",
    )
    return parser.parse_args(argv)


def validate_artifact_paths(args: argparse.Namespace) -> None:
    """Reject output aliasing before reading Stripe or touching the filesystem."""

    outputs = {
        label: path.resolve(strict=False)
        for label, path in (
            ("inventory output", args.inventory_output),
            ("scope template output", args.scope_template_output),
            ("notification template output", args.notification_template_output),
        )
        if path is not None
    }
    if len(set(outputs.values())) != len(outputs):
        raise RuntimeError("legacy containment outputs must use distinct paths")
    inputs = {
        label: path.resolve(strict=False)
        for label, path in (
            ("environment file", args.env_file),
            ("scope manifest", args.scope_manifest),
            ("notification ledger", args.notification_ledger),
        )
        if path is not None
    }
    for output_label, output_path in outputs.items():
        for input_label, input_path in inputs.items():
            if output_path == input_path:
                raise RuntimeError(
                    f"{output_label} must not overwrite the {input_label}"
                )


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    validate_artifact_paths(args)
    configured: dict[str, str] = {}
    if args.env_file is not None:
        configured = load_private_env_file(args.env_file)
        reject_conflicting_inherited_environment(
            configured,
            dict(os.environ),
            keys={
                "STRIPE_SECRET_KEY",
                "STRIPE_EXPECTED_ACCOUNT_ID",
                "STRIPE_EXPECTED_DISPLAY_NAME",
            },
        )
    stripe.api_key = configured.get("STRIPE_SECRET_KEY") or os.environ.get(
        "STRIPE_SECRET_KEY"
    )
    stripe.api_version = STRIPE_API_VERSION
    if not stripe.api_key:
        raise SystemExit("STRIPE_SECRET_KEY is required")

    account = stripe.Account.retrieve()
    verify_account(
        account,
        args.expected_account_id
        or configured.get("STRIPE_EXPECTED_ACCOUNT_ID", ""),
        args.expected_display_name
        or configured.get("STRIPE_EXPECTED_DISPLAY_NAME", ""),
    )
    inventory = collect_inventory(account)
    document = inventory.document(account)
    digest = _sha256(document)
    if args.inventory_output:
        write_private_json(args.inventory_output, {**document, "inventory_sha256": digest})

    applying = args.apply_catalog or args.pause_notified_subscriptions
    generating_templates = bool(
        args.scope_template_output or args.notification_template_output
    )
    if applying and generating_templates:
        raise RuntimeError("template generation cannot be combined with Stripe writes")
    if args.scope_template_output:
        write_private_json(
            args.scope_template_output,
            build_scope_template(account, inventory),
        )
    if args.notification_template_output and args.scope_manifest is None:
        raise RuntimeError(
            "notification template generation requires --scope-manifest"
        )
    if applying and args.scope_manifest is None:
        raise RuntimeError("apply requires --scope-manifest")
    plan = None
    scope = None
    if args.scope_manifest is not None:
        scope = load_scope_manifest(args.scope_manifest)
        plan = build_plan(account, inventory, scope)
    if args.notification_template_output:
        assert scope is not None
        write_private_json(
            args.notification_template_output,
            build_notification_ledger_template(account, inventory, scope),
        )

    output = {
        "mode": "apply" if applying else "read_only",
        "stripe_account_id": _object_id(account),
        "stripe_display_name": account_display_name(account),
        "inventory_sha256": digest,
        "counts": {key: len(value) for key, value in document["objects"].items()},
        "inventory_output": str(args.inventory_output) if args.inventory_output else None,
        "scope_template_output": (
            str(args.scope_template_output) if args.scope_template_output else None
        ),
        "notification_template_output": (
            str(args.notification_template_output)
            if args.notification_template_output
            else None
        ),
        "plan": plan,
    }
    print(json.dumps(output, indent=2, sort_keys=True))

    if applying:
        assert plan is not None
        require_apply_authorization(args.expected_plan_sha256, plan)
    if args.apply_catalog:
        archive_catalog(inventory, plan)
    if args.pause_notified_subscriptions:
        ledger = load_notification_ledger(
            args.notification_ledger,
            expected_account_id=_object_id(account),
            expected_inventory_sha256=digest,
        )
        pause_notified_subscriptions(inventory, plan, ledger)


if __name__ == "__main__":
    main()
