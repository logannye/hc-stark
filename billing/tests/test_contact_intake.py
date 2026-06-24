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
        "use_case": "  Long accumulator trace  ",
        "trace_length": "100M+ steps",
        "api_key": "tzk_should_not_survive",
        "message": "also ignored",
        "budget_owner": "Engineering",
        "latency_requirement": "x" * 200,
    })

    assert out["use_case"] == "Long accumulator trace"
    assert out["trace_length"] == "100M+ steps"
    assert out["budget_owner"] == "Engineering"
    assert len(out["latency_requirement"]) == 160
    assert "api_key" not in out
    assert "message" not in out


def test_contact_format_includes_project_fit():
    body = provision_tenant._format_contact_qualification({
        "use_case": "Audit-log checkpoints",
        "proof_frequency": "Daily checkpoints",
        "verification_environment": "AI agent / MCP",
    })

    assert "Project fit:" in body
    assert "Use case: Audit-log checkpoints" in body
    assert "Proof frequency: Daily checkpoints" in body
    assert "Verification: AI agent / MCP" in body


def test_send_contact_route_forwards_sanitized_qualification(monkeypatch):
    captured = {}

    def fake_send(name, email, category, message, qualification=None):
        captured.update({
            "name": name,
            "email": email,
            "category": category,
            "message": message,
            "qualification": qualification or {},
        })
        return True

    monkeypatch.setattr(provision_tenant, "INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(provision_tenant, "_send_contact_email", fake_send)
    monkeypatch.setattr(provision_tenant.threading, "Thread", _ImmediateThread)

    provision_tenant.app.config["TESTING"] = True
    with provision_tenant.app.test_client() as client:
        resp = client.post(
            "/send-contact",
            headers=HEADERS,
            json={
                "name": "Buyer",
                "email": "Buyer@Example.com",
                "category": "Compute Inquiry",
                "message": "We have a long trace use case.",
                "qualification": {
                    "use_case": "Long accumulator trace",
                    "trace_length": "100M+ steps",
                    "proof_frequency": "Hourly checkpoints",
                    "api_key": "tzk_never_forward",
                },
            },
        )

    assert resp.status_code == 200
    assert captured["email"] == "buyer@example.com"
    assert captured["category"] == "Compute Inquiry"
    assert captured["qualification"]["use_case"] == "Long accumulator trace"
    assert captured["qualification"]["trace_length"] == "100M+ steps"
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
