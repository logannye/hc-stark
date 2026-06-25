"""Tests for Stripe-webhook plan-slug normalization (audit BILL-01).

create-checkout.js emits metadata.plan in {developer, pro, scale, compute}. The
webhook must resolve those to canonical pricing.json plans, and legacy team
metadata must resolve to pro.
"""

import os
import sys

import pytest

# Add billing/ to sys.path so we can import provision_tenant.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# provision_tenant reads these at module level; set before import.
os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_fake")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test_fake")

import provision_tenant
import tenant_store


# What create-checkout.js can emit into metadata.plan  ->  canonical stored plan.
# The load-bearing cases are pro and compute: they must NOT become "developer".
CHECKOUT_SLUG_TO_PLAN = [
    ("developer", "developer"),
    ("pro", "pro"),
    ("scale", "scale"),
    ("compute", "compute"),
    ("team", "pro"),
]


@pytest.mark.parametrize("emitted,expected", CHECKOUT_SLUG_TO_PLAN)
def test_normalize_plan_resolves_every_checkout_slug(emitted, expected):
    assert provision_tenant._normalize_plan(emitted) == expected


def test_normalize_plan_pro_and_compute_never_become_developer():
    # The exact BILL-01 regression: pro/compute silently downgraded to developer.
    assert provision_tenant._normalize_plan("pro") != "developer"
    assert provision_tenant._normalize_plan("compute") != "developer"


def test_normalize_plan_passes_through_canonical_plans():
    for plan in ("developer", "pro", "scale", "compute"):
        assert provision_tenant._normalize_plan(plan) == plan


def test_normalize_plan_legacy_standard_alias_maps_to_developer():
    assert provision_tenant._normalize_plan("standard") == "developer"


def test_normalize_plan_unknown_or_missing_falls_back_to_developer():
    assert provision_tenant._normalize_plan(None) == "developer"
    assert provision_tenant._normalize_plan("") == "developer"
    assert provision_tenant._normalize_plan("garbage") == "developer"


def test_plan_from_subscription_resolves_pro_and_compute_metadata():
    assert (
        provision_tenant._plan_from_subscription({"metadata": {"plan": "pro"}})
        == "pro"
    )
    assert (
        provision_tenant._plan_from_subscription({"metadata": {"plan": "compute"}})
        == "compute"
    )
    assert (
        provision_tenant._plan_from_subscription({"metadata": {"plan": "developer"}})
        == "developer"
    )
    assert (
        provision_tenant._plan_from_subscription({"metadata": {"plan": "team"}})
        == "pro"
    )


def test_plan_from_subscription_item_count_fallback_preserved():
    # No usable metadata -> fall back to the line-item-count heuristic (2+ => pro).
    assert (
        provision_tenant._plan_from_subscription(
            {"metadata": {}, "items": {"data": [{"id": "si_1"}, {"id": "si_2"}]}}
        )
        == "pro"
    )
    # Unknown metadata + single item -> developer floor.
    assert (
        provision_tenant._plan_from_subscription(
            {"metadata": {"plan": "garbage"}, "items": {"data": [{"id": "si_1"}]}}
        )
        == "developer"
    )


class _NoopThread:
    def __init__(self, target, daemon=False):
        self.target = target
        self.daemon = daemon

    def start(self):
        return None


class _ImmediateThread:
    def __init__(self, target, daemon=False):
        self.target = target
        self.daemon = daemon

    def start(self):
        self.target()


def test_checkout_completed_persists_paid_attribution(monkeypatch, tmp_path):
    db_path = str(tmp_path / "tenant_store.sqlite")
    real_open = tenant_store.open_db
    monkeypatch.setattr(tenant_store, "open_db", lambda path=None: real_open(db_path))
    monkeypatch.setattr(provision_tenant.sync_keys, "regenerate", lambda *a, **kw: 0)
    monkeypatch.setattr(
        provision_tenant.stripe.Subscription,
        "retrieve",
        lambda _subscription_id: {"items": {"data": [{"id": "si_attr"}]}},
    )
    monkeypatch.setattr(provision_tenant, "generate_tenant_id", lambda: "t_paid_attr")
    monkeypatch.setattr(provision_tenant, "generate_api_key", lambda: "tzk_paid_attr_key")
    monkeypatch.setattr(provision_tenant.threading, "Thread", _NoopThread)

    text, status = provision_tenant._handle_checkout_completed({
        "id": "evt_checkout_attr",
        "data": {
            "object": {
                "subscription": "sub_attr",
                "customer": "cus_attr",
                "customer_email": "buyer@example.com",
                "metadata": {
                    "plan": "pro",
                    "source": "smithery_mcp",
                    "medium": "mcp_directory",
                    "campaign": "q3_agent_distribution",
                    "platform": "cursor",
                    "use_case": "agent_receipts",
                    "workflow": "tool_call_receipt",
                    "intent": "paid_checkout",
                    "landing_path": "/integrations/cursor",
                    "referrer_host": "smithery.ai",
                    "first_seen_at": "2026-06-25T12:00:00.000Z",
                    "api_key": "tzk_never_store_this",
                },
            },
        },
    })

    assert status == 200
    assert text == ""

    conn = real_open(db_path)
    try:
        tenant = tenant_store.get_tenant(conn, "t_paid_attr")
        assert tenant is not None
        assert tenant["email"] == "buyer@example.com"
        assert tenant["plan"] == "pro"
        assert tenant["stripe_customer_id"] == "cus_attr"
        assert tenant["stripe_subscription_id"] == "sub_attr"
        assert tenant["stripe_subscription_item_id"] == "si_attr"
        assert tenant["attribution_source"] == "smithery_mcp"
        assert tenant["attribution_medium"] == "mcp_directory"
        assert tenant["attribution_campaign"] == "q3_agent_distribution"
        assert tenant["attribution_platform"] == "cursor"
        assert tenant["attribution_use_case"] == "agent_receipts"
        assert tenant["attribution_workflow"] == "tool_call_receipt"
        assert tenant["attribution_intent"] == "paid_checkout"
        assert tenant["attribution_landing_path"] == "/integrations/cursor"
        assert tenant["attribution_referrer_host"] == "smithery.ai"
        assert tenant["attribution_first_seen_at"] == "2026-06-25T12:00:00.000Z"
        assert tenant_store.is_event_processed(conn, "evt_checkout_attr")
    finally:
        conn.close()


def test_checkout_completed_routes_one_time_pilot_payment(monkeypatch, tmp_path):
    db_path = str(tmp_path / "tenant_store.sqlite")
    real_open = tenant_store.open_db
    captured = {}

    def fake_send(name, sender_email, category, message, qualification=None):
        captured.update({
            "name": name,
            "email": sender_email,
            "category": category,
            "message": message,
            "qualification": qualification or {},
        })
        return True

    monkeypatch.setattr(tenant_store, "open_db", lambda path=None: real_open(db_path))
    monkeypatch.setattr(provision_tenant, "_send_contact_email", fake_send)
    monkeypatch.setattr(provision_tenant.threading, "Thread", _ImmediateThread)

    text, status = provision_tenant._handle_checkout_completed({
        "id": "evt_pilot_checkout",
        "data": {
            "object": {
                "id": "cs_pilot",
                "mode": "payment",
                "customer": "cus_pilot",
                "customer_email": "pilot@example.com",
                "customer_details": {"name": "Pilot Buyer", "email": "pilot@example.com"},
                "payment_intent": "pi_pilot",
                "amount_total": 500_000,
                "metadata": {
                    "plan": "production_pilot",
                    "source": "agent_offer",
                    "medium": "llm",
                    "campaign": "paid_pilot",
                    "platform": "openai_agents",
                    "workflow": "agent_policy_rollout",
                    "pilot_workflow": "Receipt every payout approval",
                    "intent": "paid_pilot_checkout",
                    "use_case": "AI-agent state receipts",
                    "api_key": "tzk_never_forward",
                },
            },
        },
    })

    assert status == 200
    assert text == "pilot payment captured"
    assert captured["name"] == "Pilot Buyer"
    assert captured["email"] == "pilot@example.com"
    assert captured["category"] == "Paid Pilot"
    assert "Production Pilot payment completed" in captured["message"]
    assert "cs_pilot" in captured["message"]
    assert "$5,000.00" in captured["message"]
    assert captured["qualification"]["plan"] == "production_pilot"
    assert captured["qualification"]["source"] == "agent_offer"
    assert captured["qualification"]["medium"] == "llm"
    assert captured["qualification"]["platform"] == "openai_agents"
    assert captured["qualification"]["workflow"] == "agent_policy_rollout"
    assert captured["qualification"]["intent"] == "paid_pilot_checkout"
    assert captured["qualification"]["use_case"] == "AI-agent state receipts"
    assert "api_key" not in captured["qualification"]

    conn = real_open(db_path)
    try:
        assert tenant_store.is_event_processed(conn, "evt_pilot_checkout")
        assert tenant_store.get_by_email(conn, "pilot@example.com") is None
    finally:
        conn.close()
