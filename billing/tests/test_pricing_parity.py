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
