import os
import pathlib
import subprocess
import sys

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "billing"))

import create_checkout


def test_legacy_checkout_rejects_restricted_live_key(monkeypatch):
    monkeypatch.setattr(create_checkout.stripe, "api_key", "rk_live_restricted")
    monkeypatch.setattr(create_checkout, "PRICE_ID", "price_legacy")
    monkeypatch.setenv("TINYZKP_ALLOW_LEGACY_TEST_CHECKOUT", "1")
    with pytest.raises(SystemExit, match="disabled"):
        create_checkout.main()


def test_legacy_checkout_test_mode_requires_explicit_gate(monkeypatch):
    monkeypatch.setattr(create_checkout.stripe, "api_key", "sk_test_fake")
    monkeypatch.setattr(create_checkout, "PRICE_ID", "price_legacy")
    monkeypatch.delenv("TINYZKP_ALLOW_LEGACY_TEST_CHECKOUT", raising=False)
    with pytest.raises(SystemExit, match="requires"):
        create_checkout.main()


def test_legacy_v2_catalog_script_stops_before_network_without_gate():
    env = os.environ.copy()
    env["STRIPE_SECRET_KEY"] = "sk_test_fake"
    env.pop("TINYZKP_ALLOW_LEGACY_RESEARCH_CATALOG", None)
    completed = subprocess.run(
        ["bash", "billing/setup_stripe_v2_pricing.sh"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 64
    assert "disabled during backend recovery" in completed.stderr
