"""Tests for lifecycle activation and upgrade nudges."""

import os
import sqlite3
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lifecycle_nudges
import tenant_store


NOW_MS = 1_782_403_200_000


def test_customer_emails_default_to_dry_run(monkeypatch):
    monkeypatch.delenv("TINYZKP_CUSTOMER_EMAILS_ENABLED", raising=False)

    assert lifecycle_nudges.customer_emails_enabled() is False
    assert lifecycle_nudges.effective_dry_run(False) is True


def test_customer_emails_require_explicit_enable(monkeypatch):
    monkeypatch.setenv("TINYZKP_CUSTOMER_EMAILS_ENABLED", "1")

    assert lifecycle_nudges.customer_emails_enabled() is True
    assert lifecycle_nudges.effective_dry_run(False) is False
    assert lifecycle_nudges.effective_dry_run(True) is True


def _tenant_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "tenant_store.sqlite")
    real_open = tenant_store.open_db
    monkeypatch.setattr(tenant_store, "open_db", lambda path=None: real_open(db_path))
    return db_path


def _create_tenant(db_path, tenant_id="t_life", plan="free", created_at_ms=None):
    conn = tenant_store.open_db(db_path)
    tenant_store.create_tenant(conn, tenant_id, f"{tenant_id}@example.com", "tzk_lifecycle", plan=plan)
    if created_at_ms is not None:
        conn.execute(
            "UPDATE tenants SET created_at_ms = ?, updated_at_ms = ? WHERE tenant_id = ?",
            (created_at_ms, created_at_ms, tenant_id),
        )
        conn.commit()
    conn.close()


def _usage_db(tmp_path, rows):
    path = str(tmp_path / "usage.sqlite")
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE usage_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          tenant_id TEXT NOT NULL,
          job_id TEXT NOT NULL UNIQUE,
          trace_length INTEGER NOT NULL,
          completed_at_ms INTEGER NOT NULL,
          billed INTEGER NOT NULL DEFAULT 0
        )"""
    )
    for index, (tenant_id, completed_at_ms) in enumerate(rows):
        conn.execute(
            "INSERT INTO usage_log (tenant_id, job_id, trace_length, completed_at_ms) VALUES (?, ?, ?, ?)",
            (tenant_id, f"job_{index}", 5000, completed_at_ms),
        )
    conn.commit()
    conn.close()
    return path


def test_zero_proof_dry_run_does_not_mark_sent(tmp_path, monkeypatch, capsys):
    db_path = _tenant_db(tmp_path, monkeypatch)
    _create_tenant(
        db_path,
        tenant_id="t_zero",
        created_at_ms=NOW_MS - lifecycle_nudges.ZERO_PROOF_DELAY_MS - 1,
    )
    usage_path = _usage_db(tmp_path, [])

    result = lifecycle_nudges.run(dry_run=True, usage_db_path=usage_path, current_ms=NOW_MS)

    output = capsys.readouterr().out
    assert result == {"sent": 1, "skipped": 0, "failed": 0}
    assert '"action": "would_send"' in output
    assert '"kind": "zero_proof_24h"' in output

    conn = tenant_store.open_db(db_path)
    try:
        assert not tenant_store.is_lifecycle_email_sent(conn, "t_zero", lifecycle_nudges.KIND_ZERO_PROOF)
    finally:
        conn.close()


def test_lifecycle_dry_run_logs_recipient_ref_not_email(tmp_path, monkeypatch, capsys):
    db_path = _tenant_db(tmp_path, monkeypatch)
    _create_tenant(
        db_path,
        tenant_id="t_private",
        created_at_ms=NOW_MS - lifecycle_nudges.ZERO_PROOF_DELAY_MS - 1,
    )
    usage_path = _usage_db(tmp_path, [])

    result = lifecycle_nudges.run(dry_run=True, usage_db_path=usage_path, current_ms=NOW_MS)

    output = capsys.readouterr().out
    assert result == {"sent": 1, "skipped": 0, "failed": 0}
    assert '"recipient_ref": "email_' in output
    assert '"email":' not in output
    assert "t_private@example.com" not in output


def test_lifecycle_send_failure_warning_redacts_email(monkeypatch, capsys):
    monkeypatch.setattr(lifecycle_nudges, "SMTP_HOST", "smtp.example.test")
    monkeypatch.setattr(lifecycle_nudges, "OUTBOUND_EMAIL_ENABLED", True)

    class ExplodingSMTP:
        def __init__(self, host, port):
            raise RuntimeError("could not send to buyer@example.com with cs_live_sensitive123")

    monkeypatch.setattr(lifecycle_nudges.smtplib, "SMTP", ExplodingSMTP)

    assert lifecycle_nudges.send_email("buyer@example.com", "Subject", "Body") is False

    error = capsys.readouterr().err
    assert "buyer@example.com" not in error
    assert "cs_live_sensitive123" not in error
    assert "recipient_ref=email_" in error
    assert "[redacted-email]" in error
    assert "[redacted-id]" in error


def test_lifecycle_email_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(lifecycle_nudges, "SMTP_HOST", "smtp.example.test")
    monkeypatch.setattr(lifecycle_nudges, "OUTBOUND_EMAIL_ENABLED", False)

    class MustNotConnect:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("SMTP must not be used while outbound email is disabled")

    monkeypatch.setattr(lifecycle_nudges.smtplib, "SMTP", MustNotConnect)
    assert lifecycle_nudges.send_email("buyer@example.com", "Subject", "Body") is False


def test_sent_lifecycle_nudges_are_marked_and_not_repeated(tmp_path, monkeypatch):
    db_path = _tenant_db(tmp_path, monkeypatch)
    _create_tenant(
        db_path,
        tenant_id="t_active",
        plan="free",
        created_at_ms=NOW_MS - lifecycle_nudges.ZERO_PROOF_DELAY_MS - 1,
    )
    usage_path = _usage_db(tmp_path, [("t_active", NOW_MS) for _ in range(80)])
    sent = []

    def fake_send(to_email, subject, body):
        sent.append((to_email, subject, body))
        return True

    first = lifecycle_nudges.run(
        dry_run=False,
        usage_db_path=usage_path,
        current_ms=NOW_MS,
        send_email_fn=fake_send,
    )
    second = lifecycle_nudges.run(
        dry_run=False,
        usage_db_path=usage_path,
        current_ms=NOW_MS,
        send_email_fn=fake_send,
    )

    assert first == {"sent": 2, "skipped": 0, "failed": 0}
    assert second == {"sent": 0, "skipped": 2, "failed": 0}
    assert len(sent) == 2
    subjects = {item[1] for item in sent}
    assert "TinyZKP: share and verify your first receipt" in subjects
    assert "TinyZKP: your free receipt quota is close to the limit" in subjects

    conn = tenant_store.open_db(db_path)
    try:
        assert tenant_store.is_lifecycle_email_sent(conn, "t_active", lifecycle_nudges.KIND_FIRST_PROOF)
        assert tenant_store.is_lifecycle_email_sent(conn, "t_active", lifecycle_nudges.KIND_FREE_QUOTA)
    finally:
        conn.close()


def test_idle_winback_sends_once_after_existing_account_goes_idle(tmp_path, monkeypatch):
    db_path = _tenant_db(tmp_path, monkeypatch)
    _create_tenant(
        db_path,
        tenant_id="t_idle",
        plan="developer",
        created_at_ms=NOW_MS - lifecycle_nudges.IDLE_WINBACK_DELAY_MS - 1000,
    )
    usage_path = _usage_db(
        tmp_path,
        [("t_idle", NOW_MS - lifecycle_nudges.IDLE_WINBACK_DELAY_MS - 1000)],
    )
    conn = tenant_store.open_db(db_path)
    try:
        tenant_store.mark_lifecycle_email_sent(conn, "t_idle", lifecycle_nudges.KIND_FIRST_PROOF, NOW_MS - 1000)
    finally:
        conn.close()
    sent = []

    def fake_send(to_email, subject, body):
        sent.append((to_email, subject, body))
        return True

    first = lifecycle_nudges.run(
        dry_run=False,
        usage_db_path=usage_path,
        current_ms=NOW_MS,
        send_email_fn=fake_send,
    )
    second = lifecycle_nudges.run(
        dry_run=False,
        usage_db_path=usage_path,
        current_ms=NOW_MS,
        send_email_fn=fake_send,
    )

    assert first == {"sent": 1, "skipped": 1, "failed": 0}
    assert second == {"sent": 0, "skipped": 2, "failed": 0}
    assert len(sent) == 1
    assert sent[0][1] == "TinyZKP: restart the proof receipt workflow"
    assert "https://tinyzkp.com/pilot?source=lifecycle_email" in sent[0][2]

    conn = tenant_store.open_db(db_path)
    try:
        assert tenant_store.is_lifecycle_email_sent(conn, "t_idle", lifecycle_nudges.KIND_IDLE_WINBACK)
    finally:
        conn.close()


def test_recent_proof_activity_does_not_trigger_idle_winback(tmp_path, monkeypatch):
    db_path = _tenant_db(tmp_path, monkeypatch)
    _create_tenant(
        db_path,
        tenant_id="t_recent_activity",
        plan="developer",
        created_at_ms=NOW_MS - lifecycle_nudges.IDLE_WINBACK_DELAY_MS - 1000,
    )
    usage_path = _usage_db(tmp_path, [("t_recent_activity", NOW_MS - 1000)])
    sent = []

    def fake_send(to_email, subject, body):
        sent.append((to_email, subject, body))
        return True

    result = lifecycle_nudges.run(
        dry_run=False,
        usage_db_path=usage_path,
        current_ms=NOW_MS,
        send_email_fn=fake_send,
    )

    assert result == {"sent": 1, "skipped": 0, "failed": 0}
    assert [item[1] for item in sent] == ["TinyZKP: share and verify your first receipt"]


def test_inactive_or_recent_tenants_are_not_eligible(tmp_path, monkeypatch):
    db_path = _tenant_db(tmp_path, monkeypatch)
    _create_tenant(db_path, tenant_id="t_recent", created_at_ms=NOW_MS - 1000)
    conn = tenant_store.open_db(db_path)
    try:
        tenant = dict(tenant_store.get_tenant(conn, "t_recent"))
        assert lifecycle_nudges.nudge_for_tenant(tenant, 0, 0, NOW_MS) == []

        tenant["status"] = "suspended"
        tenant["created_at_ms"] = NOW_MS - lifecycle_nudges.ZERO_PROOF_DELAY_MS - 1
        assert lifecycle_nudges.nudge_for_tenant(tenant, 0, 0, NOW_MS) == []
    finally:
        conn.close()
