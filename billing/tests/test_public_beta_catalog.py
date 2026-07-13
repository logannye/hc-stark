import json
import subprocess

import public_beta_catalog as catalog


def test_catalog_is_frozen_to_public_beta_economics():
    payload = catalog.load_catalog()
    assert payload["namespace"] == "tinyzkp_public_beta_v1"
    assert payload["sandbox"] == {
        "hosted_sample_jobs": 1,
        "renewing": False,
        "maximum_rows": 65536,
        "workloads": "built_in_samples_only",
    }


def test_checkout_uses_checkout_sessions_without_automatic_overage():
    params = catalog.checkout_parameters(
        "builder_monthly",
        "price_beta",
        "tenant-1",
        "cus_beta",
        "https://tinyzkp.com/dashboard?checkout=success",
        "https://tinyzkp.com/pricing?checkout=cancelled",
    )
    assert params["mode"] == "subscription"
    assert params["line_items"] == [{"price": "price_beta", "quantity": 1}]
    assert "payment_method_collection" not in params
    assert "usage" not in str(params).lower()
    assert params["subscription_data"]["metadata"]["tinyzkp_sku"] == "builder_monthly"
    assert params["automatic_tax"] == {"enabled": True}
    assert params["billing_address_collection"] == "required"
    assert params["customer_update"] == {"address": "auto"}


def test_topup_uses_one_time_checkout_and_tenant_metadata():
    params = catalog.checkout_parameters(
        "topup_25",
        "price_topup",
        "tenant-2",
        "cus_topup",
        "https://tinyzkp.com/dashboard?checkout=success",
        "https://tinyzkp.com/pricing?checkout=cancelled",
    )
    assert params["mode"] == "payment"
    assert params["payment_intent_data"]["metadata"]["tinyzkp_tenant_id"] == "tenant-2"


def test_live_write_authorization_is_fail_closed(tmp_path):
    assert not catalog._authorization_ready(None)
    path = tmp_path / "authorization.json"
    path.write_text(
        '{"schema_version":1,"release_channel":"public_beta","status":"blocked","release_sha":"abcdef0"}',
        encoding="utf-8",
    )
    assert not catalog._authorization_ready(str(path))


def test_signed_dark_canary_authorization_allows_only_exact_release(
    tmp_path, monkeypatch
):
    path = tmp_path / "authorization.json"
    bundle = tmp_path / "authorization.sigstore.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "release_channel": "public_beta",
                "status": "dark_canary",
                "purpose": "stripe_live_canary",
                "release_sha": "a" * 40,
                "public_activation": False,
            }
        ),
        encoding="utf-8",
    )
    bundle.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("HC_RELEASE_SHA", "a" * 40)
    monkeypatch.setenv("TINYZKP_BETA_CATALOG_AUTHORIZATION_BUNDLE", str(bundle))
    monkeypatch.setenv(
        "TINYZKP_BETA_CATALOG_SIGNING_IDENTITY_REGEXP",
        r"^https://github\\.com/logannye/hc-stark/",
    )
    monkeypatch.setattr(
        catalog.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0),
    )
    assert catalog._authorization_ready(str(path))
    monkeypatch.setenv("HC_RELEASE_SHA", "b" * 40)
    assert not catalog._authorization_ready(str(path))


def test_apply_repairs_only_beta_product_tax_code_under_write_gate(monkeypatch):
    class Page:
        def __init__(self, values):
            self.values = values

        def auto_paging_iter(self):
            return iter(self.values)

    modified = []
    products = []
    prices = []
    for item in catalog.load_catalog()["plans"] + catalog.load_catalog()["topups"]:
        products.append(
            {
                "id": f"prod_{item['sku']}",
                "tax_code": "txcd_old",
                "metadata": {
                    "tinyzkp_catalog": catalog.CATALOG_NAMESPACE,
                    "tinyzkp_sku": item["sku"],
                },
            }
        )
        prices.append(
            {
                "id": f"price_{item['sku']}",
                "metadata": {
                    "tinyzkp_catalog": catalog.CATALOG_NAMESPACE,
                    "tinyzkp_sku": item["sku"],
                },
            }
        )

    class Product:
        list = staticmethod(lambda **kwargs: Page(products))
        create = staticmethod(lambda **kwargs: pytest.fail("must reuse beta product"))
        modify = staticmethod(lambda product_id, **kwargs: modified.append((product_id, kwargs)))

    class Price:
        list = staticmethod(lambda **kwargs: Page(prices))
        create = staticmethod(lambda **kwargs: pytest.fail("must reuse beta price"))

    class Account:
        retrieve = staticmethod(lambda: {"id": "acct_test", "settings": {"dashboard": {"display_name": "TinyZKP Test"}}})

    import pytest

    monkeypatch.setattr(catalog.stripe, "Product", Product)
    monkeypatch.setattr(catalog.stripe, "Price", Price)
    monkeypatch.setattr(catalog.stripe, "Account", Account)
    monkeypatch.setattr(catalog, "verify_account", lambda *args: None)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_catalog")
    monkeypatch.setenv(catalog.WRITE_GATE, "1")
    monkeypatch.setenv("TINYZKP_STRIPE_PRODUCT_TAX_CODE", "txcd_approved")
    monkeypatch.setenv("TINYZKP_STRIPE_TAX_SETTINGS_APPROVED", "1")

    result = catalog.apply_catalog(catalog.load_catalog())
    assert set(result) == {item["sku"] for item in catalog.load_catalog()["plans"] + catalog.load_catalog()["topups"]}
    assert len(modified) == 6
    assert all(values["tax_code"] == "txcd_approved" for _, values in modified)
    assert all("tinyzkp_public_beta_v1:tax-code:" in values["idempotency_key"] for _, values in modified)
