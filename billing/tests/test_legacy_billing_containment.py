import json
from pathlib import Path
import stat

import pytest

import legacy_billing_containment as containment


ACCOUNT = {
    "id": "acct_tinyzkp",
    "settings": {"dashboard": {"display_name": "TinyZKP"}},
}


def inventory() -> containment.Inventory:
    return containment.Inventory(
        products=[
            {"id": "prod_legacy", "name": "TinyZKP Developer", "active": True, "metadata": {}},
            {"id": "prod_unrelated", "name": "Unrelated Active Product", "active": True, "metadata": {}},
        ],
        prices=[
            {
                "id": "price_legacy",
                "product": "prod_legacy",
                "active": True,
                "currency": "usd",
                "metadata": {},
            },
            {
                "id": "price_unrelated",
                "product": "prod_unrelated",
                "active": True,
                "currency": "usd",
                "metadata": {},
            },
        ],
        payment_links=[
            {
                "id": "plink_legacy",
                "active": True,
                "line_items": {"data": [{"price": {"product": {"id": "prod_legacy"}}}]},
            }
        ],
        subscriptions=[
            {
                "id": "sub_legacy",
                "customer": "cus_legacy",
                "status": "active",
                "items": {"data": [{"price": {"product": "prod_legacy"}}]},
            }
        ],
        meters=[{"id": "mtr_legacy", "event_name": "proof_usage", "status": "active"}],
        open_invoices=[
            {
                "id": "in_legacy",
                "customer": "cus_legacy",
                "subscription": "sub_legacy",
                "status": "open",
                "amount_remaining": 1000,
                "currency": "usd",
            }
        ],
    )


def scope_payload(inv=None):
    inv = inv or inventory()
    return {
        "schema_version": 1,
        "stripe_account_id": "acct_tinyzkp",
        "stripe_display_name": "TinyZKP",
        "inventory_sha256": containment.inventory_digest(ACCOUNT, inv),
        "selections": {
            "product_ids": ["prod_legacy"],
            "price_ids": ["price_legacy"],
            "payment_link_ids": ["plink_legacy"],
            "meter_ids": ["mtr_legacy"],
            "subscription_ids": ["sub_legacy"],
            "open_invoice_ids": ["in_legacy"],
        },
    }


def load_scope(tmp_path: Path, payload=None):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(payload or scope_payload()), encoding="utf-8")
    return containment.load_scope_manifest(path)


def valid_ledger_payload(inv=None):
    inv = inv or inventory()
    return {
        "schema_version": 2,
        "stripe_account_id": "acct_tinyzkp",
        "inventory_sha256": containment.inventory_digest(ACCOUNT, inv),
        "subscriptions": [
            {
                "subscription_id": "sub_legacy",
                "customer_id": "cus_legacy",
                "notified_at": "2026-07-09T00:00:00Z",
                "notification_channel": "signal",
                "notification_evidence_sha256": "a" * 64,
                "resolution": "credit",
                "resolution_object_id": "cn_legacy",
                "resolution_amount": 1000,
                "currency": "usd",
                "resolution_evidence_sha256": "b" * 64,
                "approved_open_invoice_ids": ["in_legacy"],
            }
        ],
    }


def test_account_identity_requires_exact_id_and_name():
    containment.verify_account(ACCOUNT, "acct_tinyzkp", "TinyZKP")
    with pytest.raises(RuntimeError, match="account mismatch"):
        containment.verify_account(ACCOUNT, "acct_other", "TinyZKP")


def test_account_is_verified_before_any_catalog_listing(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fake")
    monkeypatch.setattr(containment.stripe.Account, "retrieve", lambda: ACCOUNT)
    monkeypatch.setattr(
        containment.stripe.Product,
        "list",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("catalog must not be listed")),
    )
    with pytest.raises(RuntimeError, match="account mismatch"):
        containment.main(
            ["--expected-account-id", "acct_wrong", "--expected-display-name", "TinyZKP"]
        )


def test_exact_scope_never_selects_unrelated_product(tmp_path: Path):
    inv = inventory()
    scope = load_scope(tmp_path)
    plan = containment.build_plan(ACCOUNT, inv, scope)
    actions = {(item["action"], item["object_id"]) for item in plan["actions"]}

    assert ("archive_product", "prod_legacy") in actions
    assert all("unrelated" not in object_id for _, object_id in actions)
    assert len(plan["plan_sha256"]) == 64


def test_scope_rejects_stale_inventory_and_cross_product_price(tmp_path: Path):
    inv = inventory()
    payload = scope_payload(inv)
    payload["inventory_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="inventory digest"):
        containment.build_plan(ACCOUNT, inv, load_scope(tmp_path, payload))

    payload = scope_payload(inv)
    payload["selections"]["price_ids"] = ["price_unrelated"]
    payload["selections"]["product_ids"] = ["prod_legacy"]
    with pytest.raises(RuntimeError, match="not bound to a selected product"):
        containment.build_plan(ACCOUNT, inv, load_scope(tmp_path, payload))


def test_apply_requires_independent_gate_and_exact_plan_hash(tmp_path: Path, monkeypatch):
    plan = containment.build_plan(ACCOUNT, inventory(), load_scope(tmp_path))
    monkeypatch.delenv(containment.WRITE_GATE_ENV, raising=False)
    with pytest.raises(RuntimeError, match=containment.WRITE_GATE_ENV):
        containment.require_apply_authorization(plan["plan_sha256"], plan)

    monkeypatch.setenv(containment.WRITE_GATE_ENV, "1")
    with pytest.raises(RuntimeError, match="exact reviewed"):
        containment.require_apply_authorization("0" * 64, plan)
    containment.require_apply_authorization(plan["plan_sha256"], plan)


def test_notification_ledger_is_strict_and_digest_bound(tmp_path: Path):
    path = tmp_path / "ledger.json"
    payload = valid_ledger_payload()
    path.write_text(json.dumps(payload), encoding="utf-8")
    ledger = containment.load_notification_ledger(
        path,
        expected_account_id="acct_tinyzkp",
        expected_inventory_sha256=payload["inventory_sha256"],
    )
    assert ledger["sub_legacy"]["resolution"] == "credit"

    payload["subscriptions"].append(dict(payload["subscriptions"][0]))
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RuntimeError, match="duplicate notification"):
        containment.load_notification_ledger(path)

    payload = valid_ledger_payload()
    payload["subscriptions"][0]["unexpected"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RuntimeError, match="record fields"):
        containment.load_notification_ledger(path)


def test_pause_and_open_invoice_void_require_exact_ledger_approval(tmp_path: Path, monkeypatch):
    inv = inventory()
    plan = containment.build_plan(ACCOUNT, inv, load_scope(tmp_path))
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(valid_ledger_payload(inv)), encoding="utf-8")
    ledger = containment.load_notification_ledger(
        ledger_path,
        expected_account_id="acct_tinyzkp",
        expected_inventory_sha256=containment.inventory_digest(ACCOUNT, inv),
    )
    subscription_calls = []
    invoice_calls = []
    monkeypatch.setattr(
        containment.stripe.Subscription,
        "modify",
        lambda *args, **kwargs: subscription_calls.append((args, kwargs)),
    )
    monkeypatch.setattr(
        containment.stripe.Invoice,
        "void_invoice",
        lambda *args, **kwargs: invoice_calls.append((args, kwargs)),
    )

    containment.pause_notified_subscriptions(inv, plan, ledger)
    assert subscription_calls[0][0] == ("sub_legacy",)
    assert subscription_calls[0][1]["pause_collection"] == {"behavior": "void"}
    assert invoice_calls[0][0] == ("in_legacy",)

    ledger["sub_legacy"]["approved_open_invoice_ids"] = []
    with pytest.raises(RuntimeError, match="do not exactly match"):
        containment.pause_notified_subscriptions(inv, plan, ledger)


def test_private_inventory_output_is_owner_only_and_rejects_symlink(tmp_path: Path):
    output = tmp_path / "private" / "inventory.json"
    containment.write_private_json(output, {"safe": True})
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(target)
    with pytest.raises(RuntimeError, match="symlink"):
        containment.write_private_json(linked, {"unsafe": False})
