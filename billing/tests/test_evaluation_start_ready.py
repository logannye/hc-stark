from types import SimpleNamespace

import pytest

import contract_billing as billing
import evaluation_start_ready as readiness


def evidence():
    return billing.ContractEvidenceV1(
        schema_version=1,
        agreement_id="eval-001",
        offer_id="founding_evaluation",
        stripe_customer_id="cus_test",
        agreement_sha256="a" * 64,
        scope_sha256="b" * 64,
        signed_at="2026-07-09T12:00:00Z",
        delivery_acceptance_sha256=None,
        delivery_accepted_at=None,
    )


def request():
    return billing.BillingRequest(
        action="evaluation-deposit",
        offer_id="founding_evaluation",
        customer_id="cus_test",
        agreement_id="eval-001",
        days_until_due=15,
        evidence=evidence(),
    )


def paid_invoice(req, plan_sha256):
    return {
        "id": "in_deposit",
        "customer": "cus_test",
        "status": "paid",
        "currency": "usd",
        "amount_paid": 1_250_000,
        "amount_remaining": 0,
        "collection_method": "send_invoice",
        "metadata": {
            "tinyzkp_offer_id": "founding_evaluation",
            "tinyzkp_agreement_id": "eval-001",
            "tinyzkp_milestone": "deposit",
            "tinyzkp_plan_sha256": plan_sha256,
            "tinyzkp_contract_evidence_sha256": req.evidence.digest(),
            "tinyzkp_scope_sha256": "b" * 64,
        },
    }


def test_exact_paid_deposit_is_ready():
    req = request()
    offer = req.validate(billing.load_offers())
    plan_sha256 = billing.plan(req, offer)["plan_sha256"]
    readiness.validate_paid_deposit_invoice(
        paid_invoice(req, plan_sha256),
        invoice_id="in_deposit",
        request=req,
        offer=offer,
        plan_sha256=plan_sha256,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "open"),
        ("amount_paid", 1),
        ("customer", "cus_other"),
        ("collection_method", "charge_automatically"),
    ],
)
def test_unpaid_or_mismatched_deposit_blocks_start(field, value):
    req = request()
    offer = req.validate(billing.load_offers())
    plan_sha256 = billing.plan(req, offer)["plan_sha256"]
    invoice = paid_invoice(req, plan_sha256)
    invoice[field] = value
    with pytest.raises(ValueError, match="exact paid"):
        readiness.validate_paid_deposit_invoice(
            invoice,
            invoice_id="in_deposit",
            request=req,
            offer=offer,
            plan_sha256=plan_sha256,
        )


def test_report_contains_no_customer_contact_data():
    req = request()
    offer = req.validate(billing.load_offers())
    plan_sha256 = billing.plan(req, offer)["plan_sha256"]
    invoice = paid_invoice(req, plan_sha256)
    acceptance = {
        "workload": {"manifest_sha256": "d" * 64, "revision": "abc", "logical_rows": 1024},
        "baseline": {"host_id": "fixed-host"},
        "candidate": {"max_resident_bytes": 1024, "max_scratch_bytes": 2048},
    }
    report = readiness.readiness_report(
        account={"id": "acct_tinyzkp"},
        invoice=invoice,
        request=req,
        offer=offer,
        acceptance=acceptance,
        plan_sha256=plan_sha256,
    )
    assert report["ready"] is True
    assert "email" not in report
    assert report["workload_manifest_sha256"] == "d" * 64
