import copy
import json

import evaluation_revenue_launch_baseline_check as check


def manifest():
    return json.loads(check.MANIFEST.read_text(encoding="utf-8"))


def test_committed_revenue_launch_baseline_is_valid():
    assert check.validate(manifest()) == []


def test_baseline_rejects_enabled_customer_or_backend_surfaces():
    payload = copy.deepcopy(manifest())
    payload["release_contract"]["hosted_proving_enabled"] = True
    payload["release_contract"]["customer_email_enabled"] = True
    failures = check.validate(payload)
    assert "revenue launch containment flags are incomplete or unsafe" in failures


def test_baseline_rejects_dependency_drift_or_unknown_input():
    payload = copy.deepcopy(manifest())
    payload["dependency_locks"]["Cargo.lock"] = "0" * 64
    payload["deployment_inputs"].append("/tmp/unreviewed-secret")
    failures = check.validate(payload)
    assert "revenue launch dependency lock changed: Cargo.lock" in failures
    assert (
        "revenue launch deployment input inventory is incomplete or unknown"
        in failures
    )


def test_baseline_rejects_commercial_contract_change():
    payload = copy.deepcopy(manifest())
    payload["commercial_contract"]["price_usd"] = 25_000
    assert (
        "revenue launch commercial contract is incomplete or changed"
        in check.validate(payload)
    )
