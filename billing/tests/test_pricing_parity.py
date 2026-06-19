"""Parity test: in-code pricing/discount tables in sync_usage.py MUST
match the canonical pricing.json at the repo root.

The Rust side has equivalent tests in
crates/hc-server/src/lib.rs::pricing_parity_tests. Drift between any
two of {pricing.json, hc-server, sync_usage.py} fails CI loudly,
preventing the colleague-flagged scenario where a plan ships in one
language and is forgotten in the other.

Edit pricing.json FIRST when changing pricing; this test will fail
loudly until the Python side catches up.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# sync_usage reads STRIPE_SECRET_KEY at import time.
os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_fake")

import sync_usage  # noqa: E402


def _pricing_json() -> dict:
    """Locate pricing.json at the repo root (two dirs up from this test)."""
    repo_root = Path(__file__).resolve().parents[2]
    path = repo_root / "pricing.json"
    return json.loads(path.read_text())


class TestDiscountFactorParity:
    def test_every_plan_matches(self):
        cfg = _pricing_json()
        for plan_name, plan_data in cfg["plans"].items():
            want = plan_data["discount"]
            got = sync_usage.DISCOUNT_FACTORS.get(plan_name, 1.0)
            assert got == want, (
                f"plan {plan_name}: sync_usage.py DISCOUNT_FACTORS[{plan_name}]={got} "
                f"≠ pricing.json {want}"
            )

    def test_aliases_resolve_to_same_factor_as_target(self):
        # Legacy plan aliases (e.g. "standard" → "developer") must
        # resolve to the same discount as their target. The Python
        # discounted_price_cents falls back to 1.0 when missing, which
        # matches the developer factor (1.0). Verify.
        cfg = _pricing_json()
        for alias, target in cfg.get("plan_aliases", {}).items():
            if alias.startswith("_"):
                continue  # comment field
            target_factor = cfg["plans"][target]["discount"]
            got = sync_usage.DISCOUNT_FACTORS.get(alias, 1.0)
            assert got == target_factor, (
                f"alias {alias} → {target}: discount {got} ≠ target's {target_factor}"
            )


class TestPriceTiersParity:
    def test_every_tier_matches(self):
        cfg = _pricing_json()
        for tier in cfg["tiers_cents"]:
            cents = tier["cents"]
            upper = tier["max_steps_exclusive"]
            # Probe just below the tier's upper bound (or a very large
            # value for the unbounded last tier). price_cents must
            # return this tier's cents value.
            probe = upper - 1 if upper is not None else 100_000_000
            got = sync_usage.price_cents(probe)
            assert got == cents, (
                f"trace_length={probe}: sync_usage.py price_cents={got} ≠ pricing.json {cents}"
            )

    def test_tier_count_matches(self):
        # Both sides should have the same number of tiers — extra or
        # missing tiers indicate someone added a band without updating
        # the canonical config.
        cfg = _pricing_json()
        assert len(sync_usage.TIERS) == len(cfg["tiers_cents"]), (
            f"sync_usage.TIERS has {len(sync_usage.TIERS)} entries; "
            f"pricing.json has {len(cfg['tiers_cents'])}"
        )


class TestComputePlanParity:
    """Verify the compute plan is present with the correct limits/discount on
    both the Python (sync_usage) and SSOT (pricing.json) sides.  The Rust
    side is covered by pricing_parity_tests::plan_limits_match_pricing_json
    (iterates all pricing.json plans) plus the new explicit assertions."""

    def test_compute_plan_in_pricing_json(self):
        cfg = _pricing_json()
        assert "compute" in cfg["plans"], "pricing.json must define a 'compute' plan"
        p = cfg["plans"]["compute"]
        assert p["prove_rpm"] == 100
        assert p["verify_rpm"] == 300
        assert p["max_inflight"] == 8
        assert p["monthly_cap_cents"] == 10_000_000
        assert p["max_prove_seconds"] == 3600
        assert p["discount"] == 1.0

    def test_compute_discount_in_sync_usage(self):
        got = sync_usage.DISCOUNT_FACTORS.get("compute")
        assert got == 1.0, (
            f"sync_usage.DISCOUNT_FACTORS['compute']={got} ≠ 1.0 (compute is metered by steps)"
        )

    def test_pro_has_intermediate_discount(self):
        """Pro is the public self-serve intermediate tier at 25% off."""
        cfg = _pricing_json()
        pro_discount = cfg["plans"]["pro"]["discount"]
        got = sync_usage.DISCOUNT_FACTORS.get("pro", 1.0)
        assert got == pro_discount == 0.75, (
            f"sync_usage.DISCOUNT_FACTORS['pro']={got} ≠ pro discount {pro_discount}"
        )


class TestBillingMetersParity:
    """Verify the billing_meters SSOT in pricing.json is consistent with
    sync_usage.py's BILLING_METERS routing table."""

    def test_billing_meters_ssot_present(self):
        cfg = _pricing_json()
        assert "billing_meters" in cfg, "pricing.json must define a billing_meters object"
        bm = cfg["billing_meters"]
        assert bm.get("compute") == "trace_step_usage", (
            f"billing_meters.compute={bm.get('compute')} ≠ trace_step_usage"
        )
        assert bm.get("_default") == "proof_usage", (
            f"billing_meters._default={bm.get('_default')} ≠ proof_usage"
        )

    def test_compute_routes_to_trace_step_usage(self):
        """compute plan must use trace_step_usage meter (raw steps, not cents)."""
        assert sync_usage.BILLING_METERS.get("compute") == "trace_step_usage", (
            "sync_usage.BILLING_METERS['compute'] must be 'trace_step_usage'"
        )

    def test_compute_meter_event_for_plan(self):
        """meter_event_for_plan returns (trace_step_usage, raw_steps) for compute."""
        trace_len = 500_000
        meter_name, value = sync_usage.meter_event_for_plan("compute", trace_len)
        assert meter_name == "trace_step_usage", (
            f"compute meter_name={meter_name!r} ≠ 'trace_step_usage'"
        )
        assert value == str(trace_len), (
            f"compute meter value={value!r} ≠ str(trace_len)={str(trace_len)!r}"
        )

    def test_non_compute_meter_event_for_plan(self):
        """meter_event_for_plan returns (proof_usage, cents) for non-compute plans."""
        for plan in ("free", "developer", "pro", "scale", "team"):
            trace_len = 50_000  # 50K steps → tier 2 → 50 cents base
            meter_name, value = sync_usage.meter_event_for_plan(plan, trace_len)
            assert meter_name == sync_usage.METER_EVENT_NAME, (
                f"plan={plan}: meter_name={meter_name!r} ≠ METER_EVENT_NAME"
            )
            # value must be a stringified integer (discounted cents)
            assert value.isdigit() or (value.startswith("-") and value[1:].isdigit()), (
                f"plan={plan}: meter value={value!r} is not an integer string"
            )

    def test_billing_meters_matches_ssot(self):
        """sync_usage.BILLING_METERS keys must all appear in pricing.json billing_meters."""
        cfg = _pricing_json()
        ssot = cfg["billing_meters"]
        for plan, meter in sync_usage.BILLING_METERS.items():
            assert ssot.get(plan) == meter, (
                f"sync_usage.BILLING_METERS[{plan!r}]={meter!r} ≠ "
                f"pricing.json billing_meters[{plan!r}]={ssot.get(plan)!r}"
            )
