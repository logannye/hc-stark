import importlib.util
import json
import subprocess
import sys
from pathlib import Path


BILLING_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = BILLING_DIR / "stripe_checkout_monitor.py"
sys.path.insert(0, str(BILLING_DIR))
spec = importlib.util.spec_from_file_location("stripe_checkout_monitor", MODULE_PATH)
monitor = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = monitor
spec.loader.exec_module(monitor)


def _session(
    *,
    session_id="cs_live_secret",
    email="buyer@example.com",
    status="complete",
    payment_status="paid",
    amount_total=500_000,
    plan="production_pilot",
    source="pricing_commercial",
    medium="site",
    platform="website",
    intent="paid_pilot_checkout",
    created=1_782_403_200,
    mode="payment",
):
    return {
        "id": session_id,
        "customer": "cus_live_secret",
        "customer_email": email,
        "customer_details": {"email": email},
        "payment_intent": "pi_live_secret",
        "url": f"https://checkout.stripe.com/c/pay/{session_id}",
        "status": status,
        "payment_status": payment_status,
        "amount_total": amount_total,
        "currency": "usd",
        "mode": mode,
        "created": created,
        "metadata": {
            "plan": plan,
            "source": source,
            "medium": medium,
            "platform": platform,
            "intent": intent,
            "workflow": "sensitive customer workflow",
        },
    }


def test_summarize_sessions_counts_paid_pilot_revenue_without_pii():
    summary = monitor.summarize_sessions(
        [
            _session(),
            _session(
                session_id="cs_live_open",
                email="open@example.com",
                status="open",
                payment_status="unpaid",
                amount_total=7_900,
                plan="pro",
                source="open@example.com",
                medium="mcp_directory",
                platform="smithery",
                intent="paid_signup",
                created=1_782_400_000,
                mode="subscription",
            ),
        ],
        mode="live",
        lookback_hours=168,
    )

    assert summary.sessions == 2
    assert summary.paid == 1
    assert summary.unpaid == 1
    assert summary.open == 1
    assert summary.complete == 1
    assert summary.production_pilot_starts == 1
    assert summary.production_pilot_paid == 1
    assert summary.amount_total_by_currency == {"usd": 507_900}
    assert summary.paid_amount_by_currency == {"usd": 500_000}

    markdown = monitor.report_markdown(summary)
    payload = json.dumps(monitor.summary_to_dict(summary))
    combined = markdown + payload

    assert "production_pilot" in markdown
    assert "$5000.00" in markdown
    assert "buyer@example.com" not in combined
    assert "open@example.com" not in combined
    assert "[redacted-email]" in combined
    assert "cs_live_secret" not in combined
    assert "cus_live_secret" not in combined
    assert "pi_live_secret" not in combined
    assert "checkout.stripe.com" not in combined
    assert "sensitive customer workflow" not in combined


def test_summarize_sessions_excludes_monitoring_canaries_by_default():
    canary = _session(
        session_id="cs_live_canary",
        email="audit+pilot@example.com",
        status="complete",
        payment_status="paid",
        amount_total=500_000,
        plan="production_pilot",
        source="api_health_audit",
        medium="monitoring",
        platform="direct",
        intent="paid_pilot_checkout_canary",
    )

    summary = monitor.summarize_sessions([canary], mode="live", lookback_hours=168)

    assert summary.sessions == 0
    assert summary.paid == 0
    assert summary.production_pilot_starts == 0
    assert summary.production_pilot_paid == 0
    assert summary.amount_total_by_currency == {}
    assert summary.paid_amount_by_currency == {}
    assert summary.excluded_monitoring_sessions == 1
    assert "Monitoring canary sessions excluded: 1" in monitor.report_markdown(summary)

    included = monitor.summarize_sessions(
        [canary],
        mode="live",
        lookback_hours=168,
        include_monitoring=True,
    )
    assert included.sessions == 1
    assert included.paid == 1
    assert included.production_pilot_paid == 1
    assert included.excluded_monitoring_sessions == 0


def test_cli_loader_paginates_with_stripe_cli_and_redacts_errors():
    calls = []
    payloads = [
        {
            "has_more": True,
            "data": [_session(session_id="cs_page_1", email="first@example.com")],
        },
        {
            "has_more": False,
            "data": [_session(session_id="cs_page_2", email="second@example.com")],
        },
    ]

    def fake_runner(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(payloads.pop(0)), stderr="")

    sessions = monitor.load_sessions_from_stripe_cli(
        stripe_bin="/opt/homebrew/bin/stripe",
        live=True,
        limit=1,
        max_pages=2,
        lookback_hours=24,
        stripe_project_name="tinyzkp-prod",
        runner=fake_runner,
    )

    assert len(sessions) == 2
    assert calls[0][:4] == ["/opt/homebrew/bin/stripe", "checkout", "sessions", "list"]
    assert "--live" in calls[0]
    assert "--project-name" in calls[0]
    assert "tinyzkp-prod" in calls[0]
    assert calls[1][-2:] == ["--starting-after", "cs_page_1"]

    def failing_runner(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="permission denied for buyer@example.com, acct_live_secret, and cs_live_secret",
        )

    try:
        monitor.load_sessions_from_stripe_cli(runner=failing_runner)
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected Stripe CLI failure")

    assert "buyer@example.com" not in message
    assert "acct_live_secret" not in message
    assert "cs_live_secret" not in message
    assert "[redacted-email]" in message
    assert "[redacted-id]" in message


def test_collect_checkout_summary_fails_before_loading_sessions_when_profile_mismatches(monkeypatch):
    def fake_check(**_kwargs):
        return monitor.stripe_account_context_check.AccountCheckResult(
            "FAIL",
            "account context",
            "configured Stripe CLI display_name 'Galen Health' does not match expected 'TinyZKP'",
        )

    def unexpected_loader(**_kwargs):
        raise AssertionError("checkout sessions should not be loaded with the wrong Stripe profile")

    monkeypatch.setattr(monitor.stripe_account_context_check, "run_check", fake_check)
    monkeypatch.setattr(monitor, "load_sessions_from_stripe_cli", unexpected_loader)

    try:
        monitor.collect_checkout_summary(stripe_bin="/opt/homebrew/bin/stripe")
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected account-context failure")

    assert "Galen Health" in message
    assert "TinyZKP" in message


def test_collect_checkout_summary_can_skip_account_check_for_fixture_runs(monkeypatch):
    def fake_check(**_kwargs):
        raise AssertionError("account check should be skipped")

    monkeypatch.setattr(monitor.stripe_account_context_check, "run_check", fake_check)
    monkeypatch.setattr(monitor, "load_sessions_from_stripe_cli", lambda **_kwargs: [_session()])

    summary = monitor.collect_checkout_summary(skip_account_check=True)

    assert summary.sessions == 1
    assert summary.production_pilot_paid == 1


def test_redact_accepts_exception_objects():
    message = monitor.redact(RuntimeError("buyer@example.com failed on acct_live_secret and cs_live_secret"))

    assert "buyer@example.com" not in message
    assert "acct_live_secret" not in message
    assert "cs_live_secret" not in message
    assert "[redacted-email]" in message
    assert "[redacted-id]" in message
