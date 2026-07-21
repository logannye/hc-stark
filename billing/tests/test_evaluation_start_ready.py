import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import contract_billing as billing
import evaluation_start_ready as readiness


LEGACY_OFFERS_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "legacy-commercial-offers-v3.json"
)
billing.OFFERS_PATH = LEGACY_OFFERS_PATH


def acceptance_matrix():
    return {
        "schema_version": "tinyzkp-evaluation-acceptance-v1",
        "agreement_id": "eval-001",
        "offer_id": "founding_evaluation",
        "workload": {
            "name": "Poseidon2 AIR",
            "repository": "https://github.com/example/workload",
            "revision": "abc123",
            "manifest_sha256": "d" * 64,
            "input_generator": "generate-public-input",
            "logical_rows": 1_048_576,
            "plonky3_version": "0.6.1",
            "verifier_target": "unmodified-p3-uni-stark-0.6.1",
        },
        "baseline": {
            "command": "run-baseline",
            "host_id": "fixed-host",
            "peak_rss_bytes": None,
            "wall_time_seconds": None,
            "oom_evidence": "OOM under target cgroup",
        },
        "candidate": {
            "command": "run-bounded",
            "max_resident_bytes": 2_147_483_648,
            "max_scratch_bytes": 200_000_000_000,
            "scratch_medium": "local-nvme",
        },
        "acceptance": {
            "official_verifier_must_accept": True,
            "target_peak_rss_bytes": 2_147_483_648,
            "minimum_ram_reduction_ratio": 1.5,
            "maximum_wall_time_ratio": 3,
            "performance_target_is_guaranteed": False,
        },
        "data_boundary": {
            "public_or_non_sensitive_generator_only": True,
            "witness_transfer_allowed": False,
            "credentials_transfer_allowed": False,
            "customer_data_transfer_allowed": False,
        },
        "delivery": {
            "raw_report_required": True,
            "reproduction_commands_required": True,
            "known_limitations_required": True,
            "written_acceptance_required_before_delivery_invoice": True,
        },
    }


def evidence():
    return billing.ContractEvidenceV2(
        schema_version=2,
        agreement_id="eval-001",
        offer_id="founding_evaluation",
        stripe_customer_id="cus_test",
        agreement_sha256="a" * 64,
        scope_sha256="b" * 64,
        agreement_gate_sha256="1" * 64,
        qualification_sha256="2" * 64,
        partner_preflight_sha256="3" * 64,
        stripe_test_drill_sha256="4" * 64,
        delivery_manifest_sha256=None,
        signed_at="2026-07-09T12:00:00Z",
        delivery_acceptance_sha256=None,
        delivery_accepted_at=None,
        deposit_invoice_id=None,
        deposit_plan_sha256=None,
        negotiated_annual_amount_cents=None,
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


def annual_request():
    contract = billing.ContractEvidenceV2(
        schema_version=2,
        agreement_id="annual-001",
        offer_id="tinyzkp_fleet_oem",
        stripe_customer_id="cus_test",
        agreement_sha256="a" * 64,
        scope_sha256="b" * 64,
        agreement_gate_sha256=None,
        qualification_sha256=None,
        partner_preflight_sha256=None,
        stripe_test_drill_sha256=None,
        delivery_manifest_sha256=None,
        signed_at="2026-07-09T12:00:00Z",
        delivery_acceptance_sha256=None,
        delivery_accepted_at=None,
        deposit_invoice_id=None,
        deposit_plan_sha256=None,
        negotiated_annual_amount_cents=15_000_000,
    )
    return billing.BillingRequest(
        action="annual-contract",
        offer_id="tinyzkp_fleet_oem",
        customer_id="cus_test",
        agreement_id="annual-001",
        days_until_due=15,
        evidence=contract,
        stripe_price_id="price_fleet_150k",
        stripe_product_id="prod_fleet",
    )


def release_binding():
    return billing.ReleaseBindingV1(
        authorization_sha256="1" * 64,
        authorization_bundle_sha256="2" * 64,
        release_sha="3" * 40,
        source_tree_sha256="4" * 64,
        verified_at="2026-07-10T12:00:00Z",
    )


def paid_annual_objects(req, plan_sha256, binding):
    metadata = billing.contract_metadata(
        req,
        "annual",
        plan_sha256,
        binding,
    )
    subscription = {
        "id": "sub_annual",
        "customer": "cus_test",
        "status": "active",
        "collection_method": "send_invoice",
        "latest_invoice": "in_annual",
        "items": {
            "data": [{"price": {"id": "price_fleet_150k"}, "quantity": 1}]
        },
        "metadata": metadata,
    }
    invoice = {
        "id": "in_annual",
        "customer": "cus_test",
        "subscription": "sub_annual",
        "status": "paid",
        "currency": "usd",
        "total": 15_000_000,
        "amount_paid": 15_000_000,
        "amount_remaining": 0,
        "collection_method": "send_invoice",
        "billing_reason": "subscription_create",
    }
    return subscription, invoice


def paid_invoice(req, plan_sha256):
    return {
        "id": "in_deposit",
        "customer": "cus_test",
        "status": "paid",
        "currency": "usd",
        "amount_paid": 1_250_000,
        "amount_remaining": 0,
        "collection_method": "send_invoice",
        "auto_advance": False,
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


def test_evaluation_readiness_rejects_scope_swap_after_initial_verification(
    tmp_path, monkeypatch
):
    agreement = tmp_path / "agreement.pdf"
    scope = tmp_path / "acceptance.json"
    contract = tmp_path / "contract.json"
    agreement.write_bytes(b"signed agreement")
    original_scope = acceptance_matrix()
    scope.write_text(json.dumps(original_scope), encoding="utf-8")
    agreement.chmod(0o600)
    scope.chmod(0o600)
    bound = billing.ContractEvidenceV2(
        **{
            **billing.asdict(evidence()),
            "agreement_sha256": hashlib.sha256(agreement.read_bytes()).hexdigest(),
            "scope_sha256": hashlib.sha256(scope.read_bytes()).hexdigest(),
        }
    )
    contract.write_text(json.dumps(billing.asdict(bound)), encoding="utf-8")
    contract.chmod(0o600)
    monkeypatch.setattr(
        readiness,
        "parse_args",
        lambda argv=None: SimpleNamespace(
            offer_id=bound.offer_id,
            customer_id=bound.stripe_customer_id,
            agreement_id=bound.agreement_id,
            deposit_invoice_id="in_deposit",
            annual_subscription_id=None,
            annual_invoice_id=None,
            stripe_price_id=None,
            stripe_product_id=None,
            days_until_due=15,
            contract_evidence=contract,
            agreement_document=agreement,
            scope_document=scope,
            expected_account_id="acct_expected",
            expected_display_name="TinyZKP",
        ),
    )
    def verify_then_swap(*args, **kwargs):
        billing.validate_acceptance_matrix(
            scope,
            bound,
            expected_sha256=bound.scope_sha256,
        )
        changed = acceptance_matrix()
        changed["workload"]["logical_rows"] *= 1024
        scope.write_text(json.dumps(changed), encoding="utf-8")
        scope.chmod(0o600)

    monkeypatch.setattr(billing, "verify_contract_documents", verify_then_swap)
    monkeypatch.setattr(
        billing,
        "create_stripe_client",
        lambda key: (_ for _ in ()).throw(
            AssertionError("Stripe must not be reached after a scope swap")
        ),
    )
    with pytest.raises(ValueError, match="scope document does not match"):
        readiness.main([])


def test_annual_entitlement_requires_fully_paid_initial_invoice():
    req = annual_request()
    offer = req.validate(billing.load_offers())
    binding = release_binding()
    plan_sha256 = billing.plan(req, offer, binding)["plan_sha256"]
    subscription, invoice = paid_annual_objects(req, plan_sha256, binding)
    readiness.validate_paid_annual_entitlement(
        subscription,
        invoice,
        subscription_id="sub_annual",
        invoice_id="in_annual",
        request=req,
        offer=offer,
        plan_sha256=plan_sha256,
        release_binding=binding,
    )
    invoice["status"] = "open"
    invoice["amount_paid"] = 0
    invoice["amount_remaining"] = 15_000_000
    with pytest.raises(ValueError, match="fully paid initial invoice"):
        readiness.validate_paid_annual_entitlement(
            subscription,
            invoice,
            subscription_id="sub_annual",
            invoice_id="in_annual",
            request=req,
            offer=offer,
            plan_sha256=plan_sha256,
            release_binding=binding,
        )


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("quantity", 2),
        ("total", 1),
        ("amount_remaining", None),
    ],
)
def test_annual_entitlement_rejects_nonexact_price_or_invoice(mutation, value):
    req = annual_request()
    offer = req.validate(billing.load_offers())
    binding = release_binding()
    plan_sha256 = billing.plan(req, offer, binding)["plan_sha256"]
    subscription, invoice = paid_annual_objects(req, plan_sha256, binding)
    if mutation == "quantity":
        subscription["items"]["data"][0]["quantity"] = value
    else:
        invoice[mutation] = value
    with pytest.raises(ValueError, match="fully paid initial invoice"):
        readiness.validate_paid_annual_entitlement(
            subscription,
            invoice,
            subscription_id="sub_annual",
            invoice_id="in_annual",
            request=req,
            offer=offer,
            plan_sha256=plan_sha256,
            release_binding=binding,
        )


def test_annual_entitlement_report_is_machine_bound_and_contains_no_contact_data():
    req = annual_request()
    offer = req.validate(billing.load_offers())
    binding = release_binding()
    plan_sha256 = billing.plan(req, offer, binding)["plan_sha256"]
    subscription, invoice = paid_annual_objects(req, plan_sha256, binding)
    report = readiness.annual_entitlement_report(
        account={"id": "acct_tinyzkp"},
        subscription=subscription,
        invoice=invoice,
        request=req,
        plan_sha256=plan_sha256,
        release_binding=binding,
    )
    assert report["ready"] is True
    assert report["readiness_kind"] == "annual_entitlement"
    assert report["negotiated_annual_amount_cents"] == 15_000_000
    assert report["backend_release_authorization_sha256"] == "1" * 64
    assert "email" not in report
