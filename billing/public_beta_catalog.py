#!/usr/bin/env python3
"""Preview or idempotently create the isolated TinyZKP public-beta catalog.

Preview is the default. Writes require an explicit environment gate and exact
Stripe account identity. Live writes additionally require a signed/hashed
public-beta release authorization whose status is `ready`.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

import stripe

from legacy_billing_containment import STRIPE_API_VERSION, verify_account


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "billing" / "public_beta_catalog.json"
WRITE_GATE = "TINYZKP_ALLOW_BETA_CATALOG_WRITE"
CATALOG_NAMESPACE = "tinyzkp_public_beta_v1"
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, Any]:
    catalog = json.loads(path.read_text(encoding="utf-8"))
    if catalog.get("schema_version") != 1 or catalog.get("namespace") != CATALOG_NAMESPACE:
        raise ValueError("unexpected public-beta catalog schema or namespace")
    if catalog.get("currency") != "usd":
        raise ValueError("public-beta catalog must use USD")
    expected = {
        "builder_monthly": (4_900, 49),
        "pro_monthly": (19_900, 210),
        "scale_beta_monthly": (49_900, 550),
        "topup_25": (2_500, 25),
        "topup_100": (10_000, 100),
        "topup_500": (50_000, 500),
    }
    items = list(catalog.get("plans", [])) + list(catalog.get("topups", []))
    if {item.get("sku") for item in items} != set(expected):
        raise ValueError("public-beta catalog SKU set changed")
    for item in items:
        amount, credits = expected[item["sku"]]
        actual_credits = item.get("monthly_credits", item.get("credits"))
        if item.get("unit_amount_cents") != amount or actual_credits != credits:
            raise ValueError(f"unexpected economics for {item['sku']}")
    return catalog


def checkout_parameters(
    sku: str,
    price_id: str,
    tenant_id: str,
    customer_id: str,
    success_url: str,
    cancel_url: str,
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    catalog = catalog or load_catalog()
    item = next(
        (
            entry
            for entry in list(catalog["plans"]) + list(catalog["topups"])
            if entry["sku"] == sku
        ),
        None,
    )
    if item is None:
        raise ValueError("unknown public-beta SKU")
    if not price_id.startswith("price_") or not tenant_id or not customer_id.startswith("cus_"):
        raise ValueError("price, tenant, and Stripe customer are required")
    metadata = {
        "tinyzkp_catalog": CATALOG_NAMESPACE,
        "tinyzkp_sku": sku,
        "tinyzkp_tenant_id": tenant_id,
    }
    params: dict[str, Any] = {
        "mode": item["kind"],
        "customer": customer_id,
        "line_items": [{"price": price_id, "quantity": 1}],
        "client_reference_id": tenant_id,
        "success_url": success_url,
        "cancel_url": cancel_url,
        "automatic_tax": {"enabled": True},
        "billing_address_collection": "required",
        "customer_update": {"address": "auto"},
        "metadata": metadata,
    }
    if item["kind"] == "subscription":
        params["subscription_data"] = {"metadata": metadata}
    else:
        params["payment_intent_data"] = {"metadata": metadata}
    return params


def _authorization_ready(path: str | None) -> bool:
    if not path:
        return False
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    release_sha = os.environ.get("HC_RELEASE_SHA", "")
    public_ready = payload.get("status") == "ready"
    dark_canary = (
        payload.get("status") == "dark_canary"
        and payload.get("purpose") == "stripe_live_canary"
        and payload.get("public_activation") is False
    )
    if not (
        payload.get("schema_version") == 1
        and payload.get("release_channel") == "public_beta"
        and (public_ready or dark_canary)
        and GIT_SHA.fullmatch(release_sha) is not None
        and payload.get("release_sha") == release_sha
    ):
        return False
    bundle = os.environ.get("TINYZKP_BETA_CATALOG_AUTHORIZATION_BUNDLE", "")
    identity = os.environ.get("TINYZKP_BETA_CATALOG_SIGNING_IDENTITY_REGEXP", "")
    issuer = os.environ.get(
        "TINYZKP_BETA_CATALOG_SIGNING_ISSUER",
        "https://token.actions.githubusercontent.com",
    )
    cosign = os.environ.get("TINYZKP_COSIGN_BIN", "/usr/local/bin/cosign")
    if not bundle or not identity or not Path(bundle).is_file():
        return False
    try:
        result = subprocess.run(
            [
                cosign,
                "verify-blob",
                "--bundle",
                bundle,
                "--certificate-identity-regexp",
                identity,
                "--certificate-oidc-issuer",
                issuer,
                path,
            ],
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _all(page: Any) -> list[Any]:
    iterator = getattr(page, "auto_paging_iter", None)
    return list(iterator()) if callable(iterator) else list(getattr(page, "data", []))


def _metadata(item: Any) -> dict[str, str]:
    raw = item.get("metadata", {}) if isinstance(item, dict) else getattr(item, "metadata", {})
    return dict(raw or {})


def apply_catalog(catalog: dict[str, Any]) -> dict[str, dict[str, str]]:
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not key or os.environ.get(WRITE_GATE) != "1":
        raise RuntimeError(f"STRIPE_SECRET_KEY and {WRITE_GATE}=1 are required")
    if "_live_" in key and not _authorization_ready(
        os.environ.get("TINYZKP_BETA_CATALOG_AUTHORIZATION")
        or os.environ.get("TINYZKP_PUBLIC_BETA_RELEASE_AUTHORIZATION")
    ):
        raise RuntimeError(
            "live catalog writes require a signed exact-SHA dark-canary or public-beta authorization"
        )
    stripe.api_key = key
    tax_code = os.environ.get("TINYZKP_STRIPE_PRODUCT_TAX_CODE", "").strip()
    if not re.fullmatch(r"txcd_[A-Za-z0-9_]+", tax_code):
        raise RuntimeError("TINYZKP_STRIPE_PRODUCT_TAX_CODE must be operator-approved")
    if os.environ.get("TINYZKP_STRIPE_TAX_SETTINGS_APPROVED") != "1":
        raise RuntimeError("TINYZKP_STRIPE_TAX_SETTINGS_APPROVED=1 is required")
    stripe.api_version = STRIPE_API_VERSION
    account = stripe.Account.retrieve()
    verify_account(
        account,
        os.environ.get("TINYZKP_STRIPE_ACCOUNT_ID", ""),
        os.environ.get("TINYZKP_STRIPE_DISPLAY_NAME", ""),
    )
    products = _all(stripe.Product.list(limit=100, active=True))
    prices = _all(stripe.Price.list(limit=100, active=True))
    result: dict[str, dict[str, str]] = {}
    for item in list(catalog["plans"]) + list(catalog["topups"]):
        sku = item["sku"]
        product = next(
            (
                product
                for product in products
                if _metadata(product).get("tinyzkp_catalog") == CATALOG_NAMESPACE
                and _metadata(product).get("tinyzkp_sku") == sku
            ),
            None,
        )
        if product is None:
            product = stripe.Product.create(
                name=item["name"],
                description="Paid public beta; no SLA; not independently audited.",
                tax_code=tax_code,
                metadata={"tinyzkp_catalog": CATALOG_NAMESPACE, "tinyzkp_sku": sku},
                idempotency_key=f"{CATALOG_NAMESPACE}:product:{sku}",
            )
            products.append(product)
        product_id = product["id"] if isinstance(product, dict) else product.id
        product_tax_code = product.get("tax_code") if isinstance(product, dict) else getattr(product, "tax_code", None)
        if product_tax_code != tax_code:
            stripe.Product.modify(
                product_id,
                tax_code=tax_code,
                idempotency_key=f"{CATALOG_NAMESPACE}:tax-code:{sku}:{tax_code}",
            )
        price = next(
            (
                price
                for price in prices
                if _metadata(price).get("tinyzkp_catalog") == CATALOG_NAMESPACE
                and _metadata(price).get("tinyzkp_sku") == sku
            ),
            None,
        )
        if price is None:
            params: dict[str, Any] = {
                "product": product_id,
                "currency": catalog["currency"],
                "unit_amount": item["unit_amount_cents"],
                "metadata": {"tinyzkp_catalog": CATALOG_NAMESPACE, "tinyzkp_sku": sku},
                "idempotency_key": f"{CATALOG_NAMESPACE}:price:{sku}",
            }
            if item["kind"] == "subscription":
                params["recurring"] = {"interval": "month"}
            price = stripe.Price.create(**params)
            prices.append(price)
        price_id = price["id"] if isinstance(price, dict) else price.id
        result[sku] = {"product_id": product_id, "price_id": price_id}
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=CATALOG_PATH)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    catalog = load_catalog(args.catalog)
    if args.apply:
        print(json.dumps(apply_catalog(catalog), indent=2, sort_keys=True))
    else:
        print(json.dumps(catalog, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
