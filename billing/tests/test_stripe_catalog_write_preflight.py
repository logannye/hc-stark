import importlib.util
import subprocess
import sys
from pathlib import Path


BILLING_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = BILLING_DIR / "stripe_catalog_write_preflight.py"
sys.path.insert(0, str(BILLING_DIR))
spec = importlib.util.spec_from_file_location("stripe_catalog_write_preflight", MODULE_PATH)
preflight = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = preflight
spec.loader.exec_module(preflight)


def completed(stderr="", stdout="", returncode=1):
    return subprocess.CompletedProcess(("stripe",), returncode, stdout=stdout, stderr=stderr)


def test_full_scope_builds_product_price_and_meter_probes():
    probes = preflight.build_probes(
        stripe_bin="/opt/homebrew/bin/stripe",
        live=True,
        scope="full",
        stripe_project_name="tinyzkp-prod",
    )

    names = [probe.name for probe in probes]
    assert names == ["products create", "prices create", "billing meters create"]
    assert all("--live" in probe.command for probe in probes)
    assert all("--project-name" in probe.command for probe in probes)
    assert all("tinyzkp-prod" in probe.command for probe in probes)
    assert any("prod_00000000000000" in probe.command for probe in probes)


def test_pilot_scope_skips_meter_probe():
    probes = preflight.build_probes(stripe_bin="stripe", live=False, scope="pilot")

    assert [probe.name for probe in probes] == ["products create", "prices create"]
    assert all("--live" not in probe.command for probe in probes)


def test_permission_error_fails_and_redacts_ids():
    def runner(*args, **kwargs):
        return completed("The provided key 'rk_live_secret' does not have the required permissions on account 'acct_1234567890'.")

    result = preflight.run_probe(preflight.Probe("products create", ("stripe",)), runner=runner)

    assert result.status == "FAIL"
    assert "required permissions" in result.detail
    assert "rk_live_secret" not in result.detail
    assert "acct_1234567890" not in result.detail


def test_validation_error_passes_without_creating_resource():
    def runner(*args, **kwargs):
        return completed("Request req_1234567890: Missing required param: name.")

    result = preflight.run_probe(preflight.Probe("products create", ("stripe",)), runner=runner)

    assert result.status == "PASS"
    assert "validation" in result.detail
    assert "req_1234567890" not in result.detail


def test_json_error_payload_with_zero_exit_is_classified():
    def runner(*args, **kwargs):
        return completed(
            stdout='{"error":{"message":"No such product: prod_00000000000000","type":"invalid_request_error","request_id":"req_1234567890"}}',
            returncode=0,
        )

    result = preflight.run_probe(preflight.Probe("prices create", ("stripe",)), runner=runner)

    assert result.status == "PASS"
    assert "validation" in result.detail


def test_unexpected_success_fails_closed():
    def runner(*args, **kwargs):
        return completed(stdout='{"id":"prod_created"}', returncode=0)

    result = preflight.run_probe(preflight.Probe("products create", ("stripe",)), runner=runner)

    assert result.status == "FAIL"
    assert "unexpectedly succeeded" in result.detail


def test_cli_main_stops_on_account_context_failure(monkeypatch, capsys):
    def fake_account_check(**_kwargs):
        return preflight.stripe_account_context_check.AccountCheckResult(
            "FAIL",
            "account context",
            "configured Stripe CLI display_name 'Galen Health' does not match expected 'LN Holdings'",
        )

    def unexpected_preflight(**_kwargs):
        raise AssertionError("write probes should not run with the wrong Stripe profile")

    monkeypatch.setattr(preflight.stripe_account_context_check, "run_check", fake_account_check)
    monkeypatch.setattr(preflight, "run_preflight", unexpected_preflight)

    assert preflight.main(["--stripe-bin", "/opt/homebrew/bin/stripe", "--scope", "pilot"]) == 1
    output = capsys.readouterr().out
    assert "Galen Health" in output
    assert "LN Holdings" in output
