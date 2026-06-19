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
