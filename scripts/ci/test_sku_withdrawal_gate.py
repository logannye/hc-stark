"""Tests for the SKU withdrawal gate.

The defect this gate exists to prevent is specific and was live: the Guard
withdrawal reached human-readable HTML and nothing else, so `offers.jsonld`
went on telling Google that a $499/mo product was temporarily out of stock.
These tests exercise both directions of the disagreement, because the one
that actually happened (copy withdrawn, data not) is the one a copy-only
check cannot see.
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys
from typing import Any

import pytest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import sku_withdrawal_gate as gate  # noqa: E402


@pytest.fixture
def live() -> dict[str, Any]:
    """The real repository state, as the gate sees it."""
    return {
        "withdrawal": gate.load(gate.WITHDRAWAL),
        "pricing": gate.load(gate.SITE / "pricing.json"),
        "commerce": gate.load(gate.SITE / "commerce.json"),
        "offers": gate.load(gate.SITE / "offers.jsonld"),
        "copy_texts": {
            name: (gate.SITE / name).read_text(encoding="utf-8")
            for name in gate.COPY_SURFACES
        },
    }


def test_repository_state_passes(live: dict[str, Any]) -> None:
    assert gate.check(**live) == []


def test_the_fixture_actually_describes_a_withdrawn_sku(live: dict[str, Any]) -> None:
    """Guards against every assertion below holding vacuously."""
    assert gate.sku_withdrawn(live["withdrawal"]) is True
    assert gate.guard_offer_availabilities(live["offers"]) == [
        gate.DISCONTINUED,
        gate.DISCONTINUED,
    ]


def test_out_of_stock_is_rejected_for_a_withdrawn_sku(live: dict[str, Any]) -> None:
    """The exact defect: OutOfStock means 'coming back'."""
    live["offers"] = copy.deepcopy(live["offers"])
    for item in live["offers"]["itemListElement"]:
        if "Guard" in item.get("name", ""):
            item["availability"] = gate.OUT_OF_STOCK

    failures = gate.check(**live)

    assert any("OutOfStock" in failure for failure in failures), failures


def test_blocked_until_gates_pass_is_rejected(live: dict[str, Any]) -> None:
    """It promises the block lifts. For a withdrawn SKU that is false."""
    live["pricing"] = copy.deepcopy(live["pricing"])
    for product in live["pricing"]["products"]:
        if product["id"] == "guard":
            product["availability"] = "blocked_until_all_launch_gates_pass"

    failures = gate.check(**live)

    assert any("blocked_until_all_launch_gates_pass" in f for f in failures), failures


def test_stale_sales_state_is_rejected(live: dict[str, Any]) -> None:
    live["pricing"] = copy.deepcopy(live["pricing"])
    live["pricing"]["sales_state"] = "closed"

    failures = gate.check(**live)

    assert any("sales_state" in failure for failure in failures), failures


def test_a_withdrawn_sku_can_never_be_purchasable(live: dict[str, Any]) -> None:
    live["commerce"] = copy.deepcopy(live["commerce"])
    live["commerce"]["checkout_enabled"] = True

    failures = gate.check(**live)

    assert any("checkout_enabled" in failure for failure in failures), failures


def test_copy_must_carry_the_withdrawal(live: dict[str, Any]) -> None:
    """Data-says-withdrawn-but-copy-does-not misleads a buyer."""
    live["copy_texts"] = dict(live["copy_texts"])
    live["copy_texts"]["pricing.html"] = "<html>Buy Guard today</html>"

    failures = gate.check(**live)

    assert any("pricing.html" in failure for failure in failures), failures


def test_copy_only_withdrawal_is_rejected(live: dict[str, Any]) -> None:
    """The direction that actually happened, and that a substring check misses.

    Copy announces a withdrawal; no withdrawal is recorded; every machine
    surface therefore still advertises a purchasable product. Under the old
    copy-only assertion this state was GREEN.
    """
    live["withdrawal"] = {"withdrawn": False}

    failures = gate.check(**live)

    assert any("only in copy" in failure for failure in failures), failures


def test_discontinued_without_a_recorded_withdrawal_is_rejected(
    live: dict[str, Any],
) -> None:
    live["withdrawal"] = {"withdrawn": False}
    live["copy_texts"] = {name: "" for name in gate.COPY_SURFACES}

    failures = gate.check(**live)

    assert any("without a recorded withdrawal" in failure for failure in failures), failures


def test_price_history_is_retained_not_deleted() -> None:
    """Withdrawal ends new sales; it does not cancel prior commitments.

    The $499/$4990 figures are the evidence of what was promised to anyone
    who subscribed under the price lock, so they must survive as a record
    even though no surface may present them as a current offer.
    """
    pricing = gate.load(gate.SITE / "pricing.json")
    policy = pricing["price_policy"]
    assert policy["monthly_usd"] == 499
    assert policy["annual_usd"] == 4990
    assert policy["price_lock"] == "general_availability_plus_six_months"
    assert policy["existing_subscribers_grandfathered"] is True


def test_withdrawal_record_documents_surviving_obligations() -> None:
    record = gate.load(gate.WITHDRAWAL)
    obligations = record["surviving_obligations"]
    assert obligations["existing_subscribers_grandfathered"] is True
    assert obligations["activated_release_continues_offline"] is True
    assert record["successor"]["available"] is False


def test_a_malformed_record_does_not_silently_withdraw_a_live_sku(tmp_path) -> None:
    """Failing open in the safe direction: parse failure means NOT withdrawn."""
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert gate.sku_withdrawn({"withdrawn": False}) is False
    with pytest.raises(json.JSONDecodeError):
        gate.load(broken)
