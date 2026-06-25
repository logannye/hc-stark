import importlib.util
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "monitoring" / "stripe_checkout_canary.py"
spec = importlib.util.spec_from_file_location("stripe_checkout_canary", MODULE_PATH)
canary = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = canary
spec.loader.exec_module(canary)


class FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def test_checkout_canary_tags_monitoring_sessions_and_hides_checkout_urls():
    seen = []

    def opener(request, timeout):
        seen.append((request.full_url, json.loads(request.data.decode("utf-8")) if request.data else None, timeout))
        if request.full_url.endswith("/api/create-pilot-checkout") and request.data is None:
            return FakeResponse(200, {"available": True})
        return FakeResponse(200, {"url": "https://checkout.stripe.com/c/pay/cs_live_secret#fidkdWxOYHwn"})

    results = canary.run_canaries(
        site_url="https://tinyzkp.com",
        timeout=7,
        include_subscription=True,
        include_pilot=True,
        opener=opener,
        now=1_782_403_200,
    )

    assert [result.status for result in results] == ["PASS", "PASS"]
    payloads = [payload for _url, payload, _timeout in seen if payload]
    assert all(payload["source"] == "api_health_audit" for payload in payloads)
    assert all(payload["medium"] == "monitoring" for payload in payloads)
    assert "checkout.stripe.com/c/pay" not in json.dumps([result.detail for result in results])


def test_checkout_canary_reports_failure_without_pii_or_stripe_ids():
    def opener(_request, timeout):
        return FakeResponse(502, {"error": "failed for buyer@example.com and cs_live_secret"})

    results = canary.run_canaries(
        site_url="https://tinyzkp.com",
        timeout=7,
        include_subscription=True,
        include_pilot=False,
        opener=opener,
    )

    assert results[0].status == "FAIL"
    assert "buyer@example.com" not in results[0].detail
    assert "cs_live_secret" not in results[0].detail
    assert "[redacted-email]" in results[0].detail
    assert "[redacted-id]" in results[0].detail


def test_checkout_canary_rejects_test_mode_urls_by_default():
    def opener(_request, timeout):
        return FakeResponse(200, {"url": "https://checkout.stripe.com/c/pay/cs_test_secret#fidkdWxOYHwn"})

    results = canary.run_canaries(
        site_url="https://tinyzkp.com",
        timeout=7,
        include_subscription=True,
        include_pilot=False,
        opener=opener,
    )

    assert results[0].status == "FAIL"

    allowed = canary.run_canaries(
        site_url="https://tinyzkp.com",
        timeout=7,
        include_subscription=True,
        include_pilot=False,
        opener=opener,
        require_live=False,
    )
    assert allowed[0].status == "PASS"


def test_checkout_canary_can_verify_local_cli_visibility(monkeypatch):
    def opener(_request, timeout):
        return FakeResponse(200, {"url": "https://checkout.stripe.com/c/pay/cs_live_secret#fidkdWxOYHwn"})

    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"id": "cs_live_secret"}), stderr="")

    monkeypatch.setattr(canary.subprocess, "run", fake_run)

    results = canary.run_canaries(
        site_url="https://tinyzkp.com",
        timeout=7,
        include_subscription=True,
        include_pilot=False,
        verify_stripe_cli=True,
        stripe_bin="/opt/homebrew/bin/stripe",
        stripe_project_name="tinyzkp-prod",
        opener=opener,
    )

    assert [result.status for result in results] == ["PASS", "PASS"]
    assert calls[0][0][:4] == ["/opt/homebrew/bin/stripe", "checkout", "sessions", "retrieve"]
    assert calls[0][0][4] == "cs_live_secret"
    assert "--live" in calls[0][0]
    assert "--project-name" in calls[0][0]
    assert "tinyzkp-prod" in calls[0][0]


def test_checkout_canary_cli_visibility_warning_is_sanitized(monkeypatch):
    def fake_run(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="cannot read buyer@example.com cs_live_secret acct_live_secret",
        )

    monkeypatch.setattr(canary.subprocess, "run", fake_run)

    result = canary._verify_cli_can_read_session("cs_live_secret", stripe_bin="stripe", timeout=7)

    assert result.status == "WARN"
    assert "buyer@example.com" not in result.detail
    assert "cs_live_secret" not in result.detail
    assert "acct_live_secret" not in result.detail
    assert "[redacted-email]" in result.detail
    assert "[redacted-id]" in result.detail
