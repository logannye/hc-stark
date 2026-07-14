import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).with_name("build_canary_attestation.py")
SPEC = importlib.util.spec_from_file_location("build_canary_attestation", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_live_topup_contract_requires_real_paid_tax_addressed_object():
    valid = {
        "status": "passed",
        "kind": "topup",
        "livemode": True,
        "synthetic": True,
        "payment_status": "paid",
        "catalog_namespace": "tinyzkp_public_beta_v1",
        "automatic_tax": True,
        "billing_address_collected": True,
        "amount_minor": 2500,
    }
    MODULE.validate_stripe(valid, "topup")
    valid["livemode"] = False
    with pytest.raises(ValueError, match="livemode"):
        MODULE.validate_stripe(valid, "topup")


def test_ledger_contract_requires_one_full_reversal_and_zero_net():
    valid = {
        "status": "passed",
        "kind": "subscription",
        "grant_count": 1,
        "reversal_count": 1,
        "granted_millicredits": 49_000,
        "reversed_millicredits": 49_000,
        "net_millicredits": 0,
        "semantic_duplicate_outcomes": 0,
        "synthetic": True,
        "excluded_from_revenue": True,
    }
    MODULE.validate_ledger(valid, "subscription")
    valid["semantic_duplicate_outcomes"] = 1
    with pytest.raises(ValueError, match="semantic_duplicate_outcomes"):
        MODULE.validate_ledger(valid, "subscription")


def test_final_audit_sources_require_clean_invariants_and_scratch():
    MODULE.validate_watchdog({"status": "passed", "violations": []}, None)
    MODULE.validate_authorization(
        {
            "status": "passed",
            "cross_tenant_bundle_denied": True,
            "successful_unauthorized_accesses": 0,
        },
        None,
    )
    MODULE.validate_scratch(
        {
            "status": "passed",
            "leaked_scratch_directories": 0,
            "unexpected_scratch_entries": 0,
        },
        None,
    )
    with pytest.raises(ValueError, match="leaked_scratch_directories"):
        MODULE.validate_scratch(
            {
                "status": "passed",
                "leaked_scratch_directories": 1,
                "unexpected_scratch_entries": 0,
            },
            None,
        )
