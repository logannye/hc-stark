"""invoice.payment_failed dunning behavior (audit BILL-07).

A first failed charge must NOT hard-suspend a paying customer — Stripe Smart
Retries recover most transient declines (expired cards, momentary insufficient
funds). Hard-suspending on the first failure turns a recoverable hiccup into
involuntary churn + a support ticket. We suspend only when the subscription
reaches a terminal state: deleted (already handled), or updated to
unpaid/canceled (Stripe's dunning give-up signals).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_fake")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test_fake")

import sync_keys
import tenant_store
import provision_tenant


@pytest.fixture(autouse=True)
def _temp_db(monkeypatch, tmp_path):
    db_path = str(tmp_path / "ts.sqlite")
    real_open = tenant_store.open_db
    monkeypatch.setattr(tenant_store, "open_db", lambda path=None: real_open(db_path))
    monkeypatch.setattr(sync_keys, "regenerate", lambda *a, **kw: 0)
    yield db_path


def _make_tenant(sub_id, plan="developer"):
    conn = tenant_store.open_db()
    tenant_store.create_tenant(
        conn,
        tenant_id="t_test",
        email="payer@example.com",
        api_key="tzk_testkey_0000000000000000",
        stripe_customer_id="cus_1",
        stripe_subscription_id=sub_id,
        stripe_subscription_item_id="si_1",
        plan=plan,
    )
    conn.close()


def _field(name, tenant_id="t_test"):
    conn = tenant_store.open_db()
    row = tenant_store.get_tenant(conn, tenant_id)
    conn.close()
    return row[name]


def test_payment_failed_does_not_suspend():
    _make_tenant("sub_pf")
    provision_tenant._handle_payment_failed(
        {"id": "evt_pf_1", "data": {"object": {"subscription": "sub_pf"}}}
    )
    assert _field("status") == "active", "a single failed charge must not hard-suspend (let dunning retry)"


def test_subscription_updated_unpaid_suspends():
    _make_tenant("sub_unpaid")
    provision_tenant._handle_subscription_updated(
        {"id": "evt_su_1", "data": {"object": {"id": "sub_unpaid", "status": "unpaid", "metadata": {"plan": "developer"}}}}
    )
    assert _field("status") == "suspended", "dunning give-up (status=unpaid) must suspend"


def test_subscription_updated_canceled_suspends():
    _make_tenant("sub_cancel")
    provision_tenant._handle_subscription_updated(
        {"id": "evt_su_2", "data": {"object": {"id": "sub_cancel", "status": "canceled", "metadata": {"plan": "developer"}}}}
    )
    assert _field("status") == "suspended", "dunning give-up (status=canceled) must suspend"


def test_subscription_updated_active_updates_plan_and_keeps_active():
    # Regression guard: a normal portal plan change must still update the plan
    # and must NOT suspend.
    _make_tenant("sub_active", plan="developer")
    provision_tenant._handle_subscription_updated(
        {"id": "evt_su_3", "data": {"object": {"id": "sub_active", "status": "active", "metadata": {"plan": "scale"}}}}
    )
    assert _field("plan") == "scale", "a normal active update should still change the plan"
    assert _field("status") == "active", "a normal active update must not suspend"
