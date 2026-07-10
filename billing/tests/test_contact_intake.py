"""Tests for structured contact-form intake."""

import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_fake")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test_fake")

import provision_tenant


SECRET = "test-internal-secret-contact"
HEADERS = {"X-Internal-Secret": SECRET, "Content-Type": "application/json"}


class _ImmediateThread:
    def __init__(self, target, daemon=False):
        self.target = target
        self.daemon = daemon

    def start(self):
        self.target()


def test_contact_qualification_sanitizer_keeps_only_known_fields():
    out = provision_tenant._sanitize_contact_qualification({
        "stack": "  Plonky3 0.6.1  ",
        "current_memory": "OOM at 16 GiB",
        "api_key": "tzk_should_not_survive",
        "message": "also ignored",
        "budget_owner": "Engineering",
        "workload": "x" * 200,
    })

    assert out["stack"] == "Plonky3 0.6.1"
    assert out["current_memory"] == "OOM at 16 GiB"
    assert out["budget_owner"] == "Engineering"
    assert len(out["workload"]) == 160
    assert "api_key" not in out
    assert "message" not in out


def test_contact_format_includes_project_fit():
    body = provision_tenant._format_contact_qualification({
        "workload": "Poseidon2 AIR",
        "logical_rows": "1048576",
        "verifier_target": "Unmodified Plonky3 verifier",
    })

    assert "Project fit:" in body
    assert "Workload: Poseidon2 AIR" in body
    assert "Rows / work units: 1048576" in body
    assert "Verifier target: Unmodified Plonky3 verifier" in body


def test_send_contact_route_persists_sanitized_qualification(monkeypatch):
    captured = {}

    def fake_create(*, name, email, category, message, qualification):
        captured.update({
            "name": name,
            "email": email,
            "category": category,
            "message": message,
            "qualification": qualification or {},
        })
        return "eval_test123"

    monkeypatch.setattr(provision_tenant, "INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(provision_tenant.evaluation_store, "create_application", fake_create)

    provision_tenant.app.config["TESTING"] = True
    with provision_tenant.app.test_client() as client:
        resp = client.post(
            "/send-contact",
            headers=HEADERS,
            json={
                "name": "Buyer",
                "email": "Buyer@Example.com",
                "category": "General Inquiry",
                "message": "We have a long trace use case.",
                "qualification": {
                    "workload": "Long Plonky3 trace",
                    "logical_rows": "1048576",
                    "current_memory": "OOM at 16 GiB",
                    "api_key": "tzk_never_forward",
                },
            },
        )

    assert resp.status_code == 201
    assert resp.get_json()["application_id"] == "eval_test123"
    assert "hc-cli benchmark plonky3" in resp.get_json()["benchmark_command"]
    assert captured["email"] == "buyer@example.com"
    assert captured["category"] == "General Inquiry"
    assert captured["qualification"]["workload"] == "Long Plonky3 trace"
    assert captured["qualification"]["logical_rows"] == "1048576"
    assert "api_key" not in captured["qualification"]


def test_send_contact_rejects_oversized_message(monkeypatch):
    monkeypatch.setattr(provision_tenant, "INTERNAL_SECRET", SECRET)
    provision_tenant.app.config["TESTING"] = True
    with provision_tenant.app.test_client() as client:
        resp = client.post(
            "/send-contact",
            headers=HEADERS,
            json={
                "name": "Buyer",
                "email": "buyer@example.com",
                "category": "Enterprise",
                "message": "x" * 5001,
            },
        )

    assert resp.status_code == 400


def test_design_partner_intake_sends_no_email(monkeypatch):
    outbound_calls = []
    monkeypatch.setattr(provision_tenant, "INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(
        provision_tenant.evaluation_store,
        "create_application",
        lambda **kwargs: "eval_no_email",
    )
    monkeypatch.setattr(
        provision_tenant,
        "_send_contact_email",
        lambda *args, **kwargs: outbound_calls.append("forward"),
    )
    monkeypatch.setattr(
        provision_tenant,
        "_send_evaluation_ack",
        lambda *args, **kwargs: outbound_calls.append("ack"),
    )

    provision_tenant.app.config["TESTING"] = True
    with provision_tenant.app.test_client() as client:
        resp = client.post(
            "/send-contact",
            headers=HEADERS,
            json={
                "name": "Proving Lead",
                "email": "lead@example.com",
                "category": "Design Partner",
                "message": "Public deterministic workload",
                "qualification": {
                    "company": "Example",
                    "stack": "Plonky3 0.6.1",
                    "logical_rows": "1048576",
                    "current_memory": "OOM at 16 GiB",
                    "target_ram": "2 GiB",
                    "contact_method": "signal",
                    "contact_handle": "+15555550123",
                    "consent": "twelve_month_retention",
                },
            },
        )

    assert resp.status_code == 201
    assert resp.get_json()["application_id"] == "eval_no_email"
    assert outbound_calls == []


def test_all_provisioning_email_paths_fail_closed_in_recovery(monkeypatch):
    monkeypatch.setattr(provision_tenant, "OUTBOUND_EMAIL_ENABLED", False)
    monkeypatch.setattr(provision_tenant, "MAINTENANCE_MODE", True)
    monkeypatch.setattr(provision_tenant, "SMTP_HOST", "smtp.example.test")

    class MustNotConnect:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("SMTP must not be used during backend recovery")

    monkeypatch.setattr(provision_tenant.smtplib, "SMTP", MustNotConnect)

    assert provision_tenant._send_welcome_email("buyer@example.com", "t_test", "tzk_test") is False
    assert provision_tenant._send_magic_link_email("buyer@example.com", "https://example.test") is False
    assert provision_tenant._send_contact_email("Buyer", "buyer@example.com", "Design Partner", "Message") is False
    assert provision_tenant._send_evaluation_ack("Buyer", "buyer@example.com") is False


def test_design_partner_intake_accepts_no_email_with_no_email_contact(monkeypatch):
    captured = {}
    monkeypatch.setattr(provision_tenant, "INTERNAL_SECRET", SECRET)

    def fake_create(**kwargs):
        captured.update(kwargs)
        return "eval_no_email_address"

    monkeypatch.setattr(provision_tenant.evaluation_store, "create_application", fake_create)
    provision_tenant.app.config["TESTING"] = True
    with provision_tenant.app.test_client() as client:
        resp = client.post(
            "/send-contact",
            headers=HEADERS,
            json={
                "name": "Proving Lead",
                "email": "",
                "category": "Design Partner",
                "message": "Public deterministic workload",
                "qualification": {
                    "company": "Example",
                    "contact_method": "github",
                    "contact_handle": "https://github.com/example",
                    "consent": "twelve_month_retention",
                },
            },
        )

    assert resp.status_code == 201
    assert captured["email"] == ""
    assert captured["qualification"]["contact_method"] == "github"


def test_design_partner_intake_requires_supported_no_email_contact(monkeypatch):
    monkeypatch.setattr(provision_tenant, "INTERNAL_SECRET", SECRET)
    provision_tenant.app.config["TESTING"] = True
    with provision_tenant.app.test_client() as client:
        resp = client.post(
            "/send-contact",
            headers=HEADERS,
            json={
                "name": "Proving Lead",
                "email": "lead@example.com",
                "category": "Design Partner",
                "message": "Public deterministic workload",
                "qualification": {
                    "contact_method": "email",
                    "contact_handle": "lead@example.com",
                    "consent": "twelve_month_retention",
                },
            },
        )

    assert resp.status_code == 400
    assert "no-email contact" in resp.get_json()["error"]


def test_signed_legacy_checkout_is_ignored_in_maintenance(monkeypatch):
    event = {
        "id": "evt_stale_checkout",
        "type": "checkout.session.completed",
        "data": {"object": {"id": "cs_stale"}},
    }
    monkeypatch.setattr(
        provision_tenant.stripe.Webhook,
        "construct_event",
        lambda payload, signature, secret: event,
    )
    monkeypatch.setattr(provision_tenant, "MAINTENANCE_MODE", True)

    def fail_if_called(_event):
        raise AssertionError("legacy checkout handler must remain disabled")

    monkeypatch.setattr(provision_tenant, "_handle_checkout_completed", fail_if_called)

    provision_tenant.app.config["TESTING"] = True
    with provision_tenant.app.test_client() as client:
        response = client.post(
            "/webhook",
            data="{}",
            headers={"Stripe-Signature": "test"},
        )

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "checkout disabled during backend recovery"
