"""Tests for abandoned Stripe Checkout recovery emails."""

import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import checkout_recovery
import tenant_store


NOW_MS = 1_782_403_200_000


def test_customer_emails_default_to_dry_run(monkeypatch):
    monkeypatch.delenv("TINYZKP_CUSTOMER_EMAILS_ENABLED", raising=False)

    assert checkout_recovery.customer_emails_enabled() is False
    assert checkout_recovery.effective_dry_run(False) is True


def test_customer_emails_require_explicit_enable(monkeypatch):
    monkeypatch.setenv("TINYZKP_CUSTOMER_EMAILS_ENABLED", "1")

    assert checkout_recovery.customer_emails_enabled() is True
    assert checkout_recovery.effective_dry_run(False) is False
    assert checkout_recovery.effective_dry_run(True) is True


def _tenant_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "tenant_store.sqlite")
    real_open = tenant_store.open_db
    monkeypatch.setattr(tenant_store, "open_db", lambda path=None: real_open(db_path))
    return db_path


def _session(session_id="cs_recover", email="buyer@example.com", plan="developer", created=None, url=None, mode="subscription", metadata=None):
    session_metadata = {
        "plan": plan,
        "source": "smithery_mcp",
        "platform": "smithery",
        "workflow": "agent_receipts",
    }
    if metadata:
        session_metadata.update(metadata)
    return {
        "id": session_id,
        "mode": mode,
        "customer_email": email,
        "created": created if created is not None else NOW_MS // 1000 - 6 * 3600,
        "metadata": session_metadata,
        "url": f"https://checkout.stripe.com/c/pay/{session_id}" if url is None else url,
    }


def _pilot_session(session_id="cs_pilot_recover", email="buyer@example.com", url=None):
    return _session(
        session_id=session_id,
        email=email,
        plan="production_pilot",
        mode="payment",
        url=url,
        metadata={
            "package": "production_pilot",
            "source": "pricing_commercial",
            "platform": "website",
            "pilot_workflow": "customer audit receipt",
        },
    )


def test_recovery_sends_and_marks_session_once(tmp_path, monkeypatch):
    db_path = _tenant_db(tmp_path, monkeypatch)
    sent = []

    def fake_send(to_email, subject, body):
        sent.append((to_email, subject, body))
        return True

    first = checkout_recovery.run(
        dry_run=False,
        current_ms=NOW_MS,
        list_sessions_fn=lambda _gte, _lte: [_session()],
        send_email_fn=fake_send,
    )
    second = checkout_recovery.run(
        dry_run=False,
        current_ms=NOW_MS,
        list_sessions_fn=lambda _gte, _lte: [_session()],
        send_email_fn=fake_send,
    )

    assert first == {"sent": 1, "skipped": 0, "failed": 0}
    assert second == {"sent": 0, "skipped": 1, "failed": 0}
    assert len(sent) == 1
    assert sent[0][0] == "buyer@example.com"
    assert sent[0][1] == "TinyZKP: finish setting up proof receipts"
    assert "https://checkout.stripe.com/c/pay/cs_recover" in sent[0][2]
    assert "Spend caps" in sent[0][2]

    conn = tenant_store.open_db(db_path)
    try:
        assert tenant_store.is_checkout_recovery_sent(conn, "cs_recover")
    finally:
        conn.close()


def test_recovery_skips_email_with_existing_tenant(tmp_path, monkeypatch):
    db_path = _tenant_db(tmp_path, monkeypatch)
    conn = tenant_store.open_db(db_path)
    try:
        tenant_store.create_tenant(conn, "t_existing", "buyer@example.com", "tzk_existing", plan="developer")
    finally:
        conn.close()
    sent = []

    result = checkout_recovery.run(
        dry_run=False,
        current_ms=NOW_MS,
        list_sessions_fn=lambda _gte, _lte: [_session()],
        send_email_fn=lambda to_email, subject, body: sent.append((to_email, subject, body)) or True,
    )

    assert result == {"sent": 0, "skipped": 1, "failed": 0}
    assert sent == []


def test_pilot_recovery_sends_even_when_buyer_has_existing_tenant(tmp_path, monkeypatch):
    db_path = _tenant_db(tmp_path, monkeypatch)
    conn = tenant_store.open_db(db_path)
    try:
        tenant_store.create_tenant(conn, "t_existing", "buyer@example.com", "tzk_existing", plan="free")
    finally:
        conn.close()
    sent = []

    result = checkout_recovery.run(
        dry_run=False,
        current_ms=NOW_MS,
        list_sessions_fn=lambda _gte, _lte: [_pilot_session()],
        send_email_fn=lambda to_email, subject, body: sent.append((to_email, subject, body)) or True,
    )

    assert result == {"sent": 1, "skipped": 0, "failed": 0}
    assert sent[0][0] == "buyer@example.com"
    assert sent[0][1] == "TinyZKP: finish your production pilot checkout"
    assert "Finish the $5,000 pilot checkout" in sent[0][2]
    assert "creditable toward an annual, platform, or reserved-capacity agreement" in sent[0][2]


def test_recovery_cooldown_suppresses_repeated_email_to_same_address(tmp_path, monkeypatch):
    db_path = _tenant_db(tmp_path, monkeypatch)
    conn = tenant_store.open_db(db_path)
    try:
        tenant_store.mark_checkout_recovery_sent(
            conn,
            "cs_previous",
            "buyer@example.com",
            "developer",
            NOW_MS - 24 * 60 * 60 * 1000,
        )
    finally:
        conn.close()

    result = checkout_recovery.run(
        dry_run=False,
        current_ms=NOW_MS,
        list_sessions_fn=lambda _gte, _lte: [_session(session_id="cs_new")],
        send_email_fn=lambda _email, _subject, _body: True,
    )

    assert result == {"sent": 0, "skipped": 1, "failed": 0}


def test_recovery_dry_run_does_not_mark_session(tmp_path, monkeypatch, capsys):
    db_path = _tenant_db(tmp_path, monkeypatch)

    result = checkout_recovery.run(
        dry_run=True,
        current_ms=NOW_MS,
        list_sessions_fn=lambda _gte, _lte: [_session(session_id="cs_dry", url="")],
    )

    output = capsys.readouterr().out
    assert result == {"sent": 1, "skipped": 0, "failed": 0}
    assert '"action": "would_send"' in output
    assert "buyer@example.com" not in output
    assert "cs_dry" not in output
    assert "recipient_ref" in output
    assert "session_ref" in output
    conn = tenant_store.open_db(db_path)
    try:
        assert not tenant_store.is_checkout_recovery_sent(conn, "cs_dry")
    finally:
        conn.close()


def test_recovery_uses_fallback_signup_url_when_session_url_missing():
    recovery = checkout_recovery.recovery_from_session(_session(session_id="cs_missing_url", plan="pro", url=""))

    assert recovery is not None
    body = checkout_recovery.recovery_body(recovery)
    assert "https://tinyzkp.com/signup?source=checkout_recovery&medium=email&plan=pro" in body
    assert "previous_source=smithery_mcp" in body


def test_pilot_recovery_uses_fallback_pilot_url_when_session_url_missing():
    recovery = checkout_recovery.recovery_from_session(_pilot_session(session_id="cs_pilot_missing_url", url=""))

    assert recovery is not None
    assert recovery.plan == "production_pilot"
    body = checkout_recovery.recovery_body(recovery)
    assert "https://tinyzkp.com/pilot?source=checkout_recovery&medium=email&intent=paid_pilot_checkout" in body
    assert "previous_source=pricing_commercial" in body
    assert "workflow=customer%20audit%20receipt" in body


def test_recovery_skips_unlabeled_one_time_payment_session(tmp_path, monkeypatch):
    _tenant_db(tmp_path, monkeypatch)

    result = checkout_recovery.run(
        dry_run=False,
        current_ms=NOW_MS,
        list_sessions_fn=lambda _gte, _lte: [
            _session(session_id="cs_unlabeled_payment", plan="developer", mode="payment")
        ],
        send_email_fn=lambda _email, _subject, _body: True,
    )

    assert result == {"sent": 0, "skipped": 1, "failed": 0}


def test_recovery_logs_do_not_print_email_or_stripe_session_id(tmp_path, monkeypatch, capsys):
    _tenant_db(tmp_path, monkeypatch)

    result = checkout_recovery.run(
        dry_run=False,
        current_ms=NOW_MS,
        max_emails=0,
        list_sessions_fn=lambda _gte, _lte: [_session(session_id="cs_sensitive_session", email="buyer@example.com")],
        send_email_fn=lambda _email, _subject, _body: True,
    )

    output = capsys.readouterr().out
    assert result == {"sent": 0, "skipped": 1, "failed": 0}
    assert "buyer@example.com" not in output
    assert "cs_sensitive_session" not in output
    assert "recipient_ref" in output
    assert "session_ref" in output

def test_checkout_recovery_email_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(checkout_recovery, "SMTP_HOST", "smtp.example.test")
    monkeypatch.setattr(checkout_recovery, "OUTBOUND_EMAIL_ENABLED", False)

    class MustNotConnect:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("SMTP must not be used while outbound email is disabled")

    monkeypatch.setattr(checkout_recovery.smtplib, "SMTP", MustNotConnect)
    assert checkout_recovery.send_email("buyer@example.com", "Subject", "Body") is False
