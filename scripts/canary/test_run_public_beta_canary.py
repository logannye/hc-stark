import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).with_name("run_public_beta_canary.py")
SPEC = importlib.util.spec_from_file_location("run_public_beta_canary", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_state_is_exact_sha_and_driver_bound():
    state = MODULE.new_state("a" * 40, "b" * 64, 1_700_000_000)
    assert state["release_sha"] == "a" * 40
    assert state["driver_sha256"] == "b" * 64
    assert state["status"] == "running"
    assert state["hourly_verified_proofs"] == []


def test_event_validation_is_fail_closed():
    assert MODULE.validate_event(
        "proof", {"workload": "fibonacci", "official_verification": True}, "fibonacci"
    )["official_verification"]
    with pytest.raises(RuntimeError, match="officially verify"):
        MODULE.validate_event(
            "proof", {"workload": "fibonacci", "official_verification": False}, "fibonacci"
        )
    with pytest.raises(RuntimeError, match="full reservation"):
        MODULE.validate_event("cancel", {"full_reservation_released": False})
    with pytest.raises(RuntimeError, match="billing canary"):
        MODULE.validate_event(
            "billing",
            {"kind": "subscription", "synthetic": True, "refunded": True},
            "subscription",
        )


def test_driver_identity_rejects_symlinks(tmp_path):
    driver = tmp_path / "driver"
    driver.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    driver.chmod(0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(driver)
    with pytest.raises(ValueError, match="symlink"):
        MODULE.driver_identity(alias)
