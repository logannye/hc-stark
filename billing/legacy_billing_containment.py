#!/usr/bin/env python3
"""Inventory and safely contain TinyZKP's legacy Stripe catalog.

The command is read-only unless an explicit apply flag is supplied. It always
verifies the connected Stripe account first, scopes mutations to legacy
TinyZKP products/meters, and will not pause a customer subscription until an
operator-provided notification ledger records the promised resolution.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any, Iterable

import stripe


STRIPE_API_VERSION = "2026-02-25.clover"
LEGACY_PRODUCT_NAMES = {
    "Compute",
    "TinyZKP Developer",
    "TinyZKP Pro",
    "TinyZKP Pro Plan",
    "TinyZKP Proof Generation",
    "TinyZKP Scale",
    "TinyZKP Team",
}
LEGACY_METER_EVENT_NAMES = {"proof_usage", "trace_step_usage"}
CHARGEABLE_SUBSCRIPTION_STATES = {"active", "trialing", "past_due", "unpaid", "paused"}
ALLOWED_RESOLUTIONS = {"refund", "credit", "none_due"}


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


def account_display_name(account: Any) -> str:
    return str(
        _nested(account, "settings", "dashboard", "display_name")
        or _nested(account, "business_profile", "name")
        or ""
    ).strip()


def verify_account(account: Any, expected_account_id: str, expected_display_name: str) -> None:
    actual_id = str(_value(account, "id", ""))
    actual_name = account_display_name(account)
    if not expected_account_id or not expected_display_name:
        raise RuntimeError("expected account ID and display name are required")
    if actual_id != expected_account_id or actual_name.casefold() != expected_display_name.casefold():
        raise RuntimeError(
            f"Stripe account mismatch: expected {expected_account_id!r}/{expected_display_name!r}, "
            f"got {actual_id!r}/{actual_name!r}"
        )


def is_legacy_product(product: Any) -> bool:
    name = str(_value(product, "name", "")).strip()
    return name in LEGACY_PRODUCT_NAMES or name.startswith("TinyZKP ")


def subscription_product_ids(subscription: Any) -> set[str]:
    items = _nested(subscription, "items", "data") or []
    product_ids: set[str] = set()
    for item in items:
        product = _nested(item, "price", "product")
        product_id = _value(product, "id") if product is not None else None
        if product_id is None and isinstance(product, str):
            product_id = product
        if product_id:
            product_ids.add(str(product_id))
    return product_ids


def load_notification_ledger(path: Path | None) -> dict[str, dict[str, str]]:
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise RuntimeError("notification ledger must be an object with schema_version=1")
    records = payload.get("subscriptions")
    if not isinstance(records, list):
        raise RuntimeError("notification ledger subscriptions must be an array")
    result: dict[str, dict[str, str]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise RuntimeError("notification ledger records must be objects")
        subscription_id = str(record.get("subscription_id", "")).strip()
        notified_at = str(record.get("notified_at", "")).strip()
        resolution = str(record.get("resolution", "")).strip()
        if not subscription_id or not notified_at or resolution not in ALLOWED_RESOLUTIONS:
            raise RuntimeError(
                "each notification record requires subscription_id, notified_at, and "
                f"resolution in {sorted(ALLOWED_RESOLUTIONS)}"
            )
        result[subscription_id] = {
            "notified_at": notified_at,
            "resolution": resolution,
        }
    return result


@dataclass
class Inventory:
    products: list[Any]
    prices: list[Any]
    payment_links: list[Any]
    subscriptions: list[Any]
    meters: list[Any]
    open_invoices: list[Any]

    def summary(self, account: Any) -> dict[str, Any]:
        return {
            "stripe_account_id": _value(account, "id"),
            "stripe_display_name": account_display_name(account),
            "legacy_active_products": len(self.products),
            "legacy_active_prices": len(self.prices),
            "legacy_active_payment_links": len(self.payment_links),
            "legacy_chargeable_subscriptions": len(self.subscriptions),
            "legacy_active_meters": len(self.meters),
            "open_invoice_count": len(self.open_invoices),
            "safe_to_cancel_subscriptions": False,
        }


def collect_inventory() -> tuple[Any, Inventory]:
    account = stripe.Account.retrieve()
    products = [
        product
        for product in _all(stripe.Product.list(active=True, limit=100))
        if is_legacy_product(product)
    ]
    product_ids = {str(_value(product, "id")) for product in products}
    prices = [
        price
        for price in _all(stripe.Price.list(active=True, limit=100))
        if str(_value(price, "product", "")) in product_ids
    ]

    payment_links: list[Any] = []
    for link in _all(stripe.PaymentLink.list(active=True, limit=100)):
        expanded = stripe.PaymentLink.retrieve(
            str(_value(link, "id")), expand=["line_items.data.price.product"]
        )
        line_items = _nested(expanded, "line_items", "data") or []
        if any(
            str(_nested(item, "price", "product", "id") or _nested(item, "price", "product"))
            in product_ids
            for item in line_items
        ):
            payment_links.append(expanded)

    subscriptions = [
        subscription
        for subscription in _all(
            stripe.Subscription.list(
                status="all", limit=100, expand=["data.items.data.price.product"]
            )
        )
        if str(_value(subscription, "status", "")) in CHARGEABLE_SUBSCRIPTION_STATES
        and subscription_product_ids(subscription) & product_ids
    ]
    meters = [
        meter
        for meter in _all(stripe.billing.Meter.list(status="active", limit=100))
        if str(_value(meter, "event_name", "")) in LEGACY_METER_EVENT_NAMES
    ]
    open_invoices = _all(stripe.Invoice.list(status="open", limit=100))
    return account, Inventory(products, prices, payment_links, subscriptions, meters, open_invoices)


def _idempotency_key(action: str, object_id: str) -> str:
    return f"tinyzkp-backend-recovery-{action}-{object_id}"


def archive_catalog(inventory: Inventory) -> None:
    for link in inventory.payment_links:
        object_id = str(_value(link, "id"))
        stripe.PaymentLink.modify(
            object_id, active=False, idempotency_key=_idempotency_key("link", object_id)
        )
    for price in inventory.prices:
        object_id = str(_value(price, "id"))
        stripe.Price.modify(
            object_id, active=False, idempotency_key=_idempotency_key("price", object_id)
        )
    for product in inventory.products:
        object_id = str(_value(product, "id"))
        stripe.Product.modify(
            object_id, active=False, idempotency_key=_idempotency_key("product", object_id)
        )
    for meter in inventory.meters:
        object_id = str(_value(meter, "id"))
        stripe.billing.Meter.deactivate(
            object_id, idempotency_key=_idempotency_key("meter", object_id)
        )


def pause_notified_subscriptions(
    subscriptions: Iterable[Any], ledger: dict[str, dict[str, str]]
) -> None:
    for subscription in subscriptions:
        object_id = str(_value(subscription, "id"))
        if object_id not in ledger:
            raise RuntimeError(
                f"refusing to pause {object_id}: no notification and refund/credit record"
            )
    for subscription in subscriptions:
        object_id = str(_value(subscription, "id"))
        stripe.Subscription.modify(
            object_id,
            pause_collection={"behavior": "void"},
            metadata={"tinyzkp_backend_recovery": "2026-07"},
            idempotency_key=_idempotency_key("pause", object_id),
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-account-id", default=os.environ.get("STRIPE_EXPECTED_ACCOUNT_ID"))
    parser.add_argument(
        "--expected-display-name", default=os.environ.get("STRIPE_EXPECTED_DISPLAY_NAME")
    )
    parser.add_argument("--apply-catalog", action="store_true")
    parser.add_argument("--pause-notified-subscriptions", action="store_true")
    parser.add_argument("--notification-ledger", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    stripe.api_version = STRIPE_API_VERSION
    if not stripe.api_key:
        raise SystemExit("STRIPE_SECRET_KEY is required")

    account, inventory = collect_inventory()
    verify_account(account, args.expected_account_id or "", args.expected_display_name or "")
    summary = inventory.summary(account)
    summary["mode"] = "apply" if args.apply_catalog or args.pause_notified_subscriptions else "read_only"
    print(json.dumps(summary, indent=2, sort_keys=True))

    if args.apply_catalog:
        archive_catalog(inventory)
    if args.pause_notified_subscriptions:
        ledger = load_notification_ledger(args.notification_ledger)
        pause_notified_subscriptions(inventory.subscriptions, ledger)


if __name__ == "__main__":
    main()
