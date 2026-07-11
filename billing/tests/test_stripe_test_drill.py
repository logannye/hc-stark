import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import stripe_test_drill as drill


def _invoice(status: str) -> dict:
    return {
        "id": "in_test_drill",
        "customer": "cus_test_drill",
        "status": status,
        "collection_method": "send_invoice",
        "auto_advance": False,
        "livemode": False,
        "total": drill.AMOUNT_CENTS if status != "draft" else 0,
        "hosted_invoice_url": "https://invoice.stripe.com/i/test_drill",
        "metadata": {
            "tinyzkp_test_drill": "true",
            "tinyzkp_test_drill_id": "drill-001",
            "tinyzkp_release_sha": "a" * 40,
        },
    }


class FakeInvoices:
    def __init__(self):
        self.calls = []
        self.status = "draft"

    def create(self, params, options):
        self.calls.append(("create", params, options))
        return _invoice("draft")

    def finalize_invoice(self, invoice_id, params, options):
        self.calls.append(("finalize", invoice_id, params, options))
        self.status = "open"
        return _invoice("open")

    def retrieve(self, invoice_id):
        self.calls.append(("retrieve", invoice_id))
        return _invoice(self.status)

    def void_invoice(self, invoice_id, params, options):
        self.calls.append(("void", invoice_id, params, options))
        self.status = "void"
        return _invoice("void")

    def delete(self, invoice_id):
        self.calls.append(("delete", invoice_id))
        self.status = "deleted"
        return {"id": invoice_id, "deleted": True, "livemode": False}


class FakeItems:
    def __init__(self):
        self.calls = []

    def create(self, params, options):
        self.calls.append((params, options))
        return {
            "id": "ii_test_drill",
            "invoice": "in_test_drill",
            "amount": drill.AMOUNT_CENTS,
            "livemode": False,
        }


def client():
    invoices = FakeInvoices()
    items = FakeItems()
    account = {
        "id": "acct_tinyzkp_test",
        "settings": {"dashboard": {"display_name": "TinyZKP Test"}},
    }
    return SimpleNamespace(
        v1=SimpleNamespace(
            accounts=SimpleNamespace(retrieve_current=lambda: account),
            customers=SimpleNamespace(
                retrieve=lambda customer_id: {
                    "id": customer_id,
                    "livemode": False,
                    "deleted": False,
                }
            ),
            invoices=invoices,
            invoice_items=items,
        )
    )


def test_drill_is_exact_test_mode_and_voids_without_send(monkeypatch):
    monkeypatch.setattr(drill.importlib.metadata, "version", lambda package: "15.3.0")
    fake = client()
    evidence = drill.run_drill(
        fake,
        account_id="acct_tinyzkp_test",
        display_name="TinyZKP Test",
        customer_id="cus_test_drill",
        drill_id="drill-001",
        release_sha="a" * 40,
    )
    assert evidence["amount_cents"] == 1_250_000
    assert evidence["livemode"] is False
    assert evidence["send_api_invoked"] is False
    assert evidence["checkout_created"] is False
    assert evidence["cleanup_complete"] is True
    call_names = [call[0] for call in fake.v1.invoices.calls]
    assert call_names == ["create", "finalize", "retrieve", "void"]
    assert not hasattr(fake.v1.invoices, "send_invoice")
    invoice_params = fake.v1.invoices.calls[0][1]
    assert invoice_params["auto_advance"] is False
    assert invoice_params["collection_method"] == "send_invoice"
    item_params = fake.v1.invoice_items.calls[0][0]
    assert item_params["invoice"] == "in_test_drill"
    assert item_params["amount"] == 1_250_000


def test_failure_cleans_up_draft_invoice(monkeypatch):
    fake = client()
    fake.v1.invoice_items.create = lambda *args, **kwargs: (_ for _ in ()).throw(
        RuntimeError("injected")
    )
    with pytest.raises(RuntimeError, match="injected"):
        drill.run_drill(
            fake,
            account_id="acct_tinyzkp_test",
            display_name="TinyZKP Test",
            customer_id="cus_test_drill",
            drill_id="drill-001",
            release_sha="a" * 40,
        )
    assert fake.v1.invoices.calls[-2:] == [
        ("retrieve", "in_test_drill"),
        ("delete", "in_test_drill"),
    ]


def test_evidence_round_trip_requires_owner_only(tmp_path):
    payload = {
        "schema_version": drill.SCHEMA_VERSION,
        "status": "passed",
        "stripe_api_version": drill.STRIPE_API_VERSION,
        "stripe_sdk_version": "15.3.0",
        "stripe_account_id": "acct_tinyzkp_test",
        "stripe_display_name": "TinyZKP Test",
        "stripe_customer_id": "cus_test_drill",
        "stripe_invoice_id": "in_test_drill",
        "drill_id": "drill-001",
        "amount_cents": drill.AMOUNT_CENTS,
        "currency": "usd",
        "collection_method": "send_invoice",
        "days_until_due": 15,
        "auto_advance": False,
        "livemode": False,
        "hosted_invoice_url_sha256": "b" * 64,
        "created_status": "draft",
        "finalized_status": "open",
        "retrieved_status": "open",
        "voided_status": "void",
        "send_api_invoked": False,
        "checkout_created": False,
        "cleanup_complete": True,
        "started_at": "2026-07-10T12:00:00Z",
        "completed_at": "2026-07-10T12:01:00Z",
        "release_sha": "a" * 40,
        "operation_digest": "c" * 64,
    }
    output = tmp_path / "private" / "evidence.json"
    output.parent.mkdir(mode=0o700)
    drill.atomic_write_owner_only(output, payload)
    assert output.stat().st_mode & 0o777 == 0o600
    assert drill.load_evidence(output) == payload
    output.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        drill.load_evidence(output)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("livemode", True),
        ("amount_cents", 1),
        ("send_api_invoked", True),
        ("checkout_created", True),
        ("cleanup_complete", False),
        ("voided_status", "open"),
        ("stripe_api_version", "old"),
    ],
)
def test_evidence_rejects_unsafe_or_incomplete_claims(field, value):
    base = {
        "schema_version": drill.SCHEMA_VERSION,
        "status": "passed",
        "stripe_api_version": drill.STRIPE_API_VERSION,
        "stripe_sdk_version": "15.3.0",
        "stripe_account_id": "acct_tinyzkp_test",
        "stripe_display_name": "TinyZKP Test",
        "stripe_customer_id": "cus_test_drill",
        "stripe_invoice_id": "in_test_drill",
        "drill_id": "drill-001",
        "amount_cents": drill.AMOUNT_CENTS,
        "currency": "usd",
        "collection_method": "send_invoice",
        "days_until_due": 15,
        "auto_advance": False,
        "livemode": False,
        "hosted_invoice_url_sha256": "b" * 64,
        "created_status": "draft",
        "finalized_status": "open",
        "retrieved_status": "open",
        "voided_status": "void",
        "send_api_invoked": False,
        "checkout_created": False,
        "cleanup_complete": True,
        "started_at": "2026-07-10T12:00:00Z",
        "completed_at": "2026-07-10T12:01:00Z",
        "release_sha": "a" * 40,
        "operation_digest": "c" * 64,
    }
    base[field] = value
    with pytest.raises(ValueError):
        drill.validate_evidence(base)


def test_cli_rejects_live_key_before_client_creation(tmp_path):
    script = Path(drill.__file__)
    result = subprocess.run(
        [
            "python3",
            str(script),
            "run",
            "--account-id",
            "acct_live",
            "--display-name",
            "TinyZKP",
            "--customer-id",
            "cus_live",
            "--drill-id",
            "drill-001",
            "--release-sha",
            "a" * 40,
            "--output",
            str(tmp_path / "evidence.json"),
            "--apply",
        ],
        env={
            **os.environ,
            drill.WRITE_GATE_ENV: "1",
            "STRIPE_SECRET_KEY": "sk_live_forbidden",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "rejects live keys" in result.stderr


def test_duplicate_json_keys_fail_closed(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text('{"status":"passed","status":"failed"}')
    path.chmod(0o600)
    with pytest.raises(ValueError, match="duplicate JSON key"):
        drill.load_evidence(path)
