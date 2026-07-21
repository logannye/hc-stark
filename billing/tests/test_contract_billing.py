import pytest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import contract_billing as billing


LEGACY_OFFERS_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "legacy-commercial-offers-v3.json"
)
billing.OFFERS_PATH = LEGACY_OFFERS_PATH


def test_active_guard_catalog_disables_legacy_contract_creation(monkeypatch):
    monkeypatch.setattr(billing, "OFFERS_PATH", billing.ROOT / "site" / "pricing.json")
    with pytest.raises(ValueError, match="unavailable for the active Guard catalog"):
        billing.load_offers()


def evidence(
    action="evaluation-deposit",
    offer_id="founding_evaluation",
    customer_id="cus_test",
    agreement_id="eval-001",
    **overrides,
):
    values = {
        "schema_version": 2,
        "agreement_id": agreement_id,
        "offer_id": offer_id,
        "stripe_customer_id": customer_id,
        "agreement_sha256": "a" * 64,
        "scope_sha256": "b" * 64,
        "agreement_gate_sha256": "1" * 64
        if action.startswith("evaluation-")
        else None,
        "qualification_sha256": "2" * 64
        if action.startswith("evaluation-")
        else None,
        "partner_preflight_sha256": "3" * 64
        if action.startswith("evaluation-")
        else None,
        "stripe_test_drill_sha256": "4" * 64
        if action.startswith("evaluation-")
        else None,
        "delivery_manifest_sha256": "5" * 64
        if action == "evaluation-delivery"
        else None,
        "signed_at": "2026-07-09T12:00:00Z",
        "delivery_acceptance_sha256": "c" * 64
        if action == "evaluation-delivery"
        else None,
        "delivery_accepted_at": "2026-07-10T12:00:00Z"
        if action == "evaluation-delivery"
        else None,
        "deposit_invoice_id": "in_paid_deposit"
        if action == "evaluation-delivery"
        else None,
        "deposit_plan_sha256": "9" * 64
        if action == "evaluation-delivery"
        else None,
        "negotiated_annual_amount_cents": (
            6_000_000 if action == "annual-contract" else None
        ),
    }
    values.update(overrides)
    return billing.ContractEvidenceV2(**values)


def request(action="evaluation-deposit", offer_id="founding_evaluation", **overrides):
    customer_id = overrides.pop("customer_id", "cus_test")
    agreement_id = overrides.pop("agreement_id", "eval-001")
    contract_evidence = overrides.pop(
        "evidence",
        evidence(
            action=action,
            offer_id=offer_id,
            customer_id=customer_id,
            agreement_id=agreement_id,
        ),
    )
    values = {
        "action": action,
        "offer_id": offer_id,
        "customer_id": customer_id,
        "agreement_id": agreement_id,
        "days_until_due": 15,
        "evidence": contract_evidence,
        "stripe_price_id": None,
        "stripe_product_id": None,
    }
    values.update(overrides)
    return billing.BillingRequest(**values)


def acceptance_matrix(agreement_id="eval-001", offer_id="founding_evaluation"):
    return {
        "schema_version": "tinyzkp-evaluation-acceptance-v1",
        "agreement_id": agreement_id,
        "offer_id": offer_id,
        "workload": {
            "name": "Poseidon2 AIR",
            "repository": "https://github.com/example/workload",
            "revision": "abc123",
            "manifest_sha256": "d" * 64,
            "input_generator": "cargo run --release -- generate-public-input",
            "logical_rows": 1_048_576,
            "plonky3_version": "0.6.1",
            "verifier_target": "unmodified-p3-uni-stark-0.6.1",
        },
        "baseline": {
            "command": "cargo run --release -- baseline",
            "host_id": "fixed-host-8cpu-16g-nvme",
            "peak_rss_bytes": None,
            "wall_time_seconds": None,
            "oom_evidence": "OOM under 2 GiB cgroup",
        },
        "candidate": {
            "command": "hc-cli benchmark plonky3 --manifest workload.json --mode ceiling",
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


def release_authorization(**overrides):
    payload = {
        "schema_version": 1,
        "status": "ready",
        "release_sha": "a" * 40,
        "source_tree_sha256": "b" * 64,
        "backend_evidence_sha256": "c" * 64,
        "backend_release_ready_report_sha256": "d" * 64,
        "signed_release_manifest_sha256": "e" * 64,
        "signature_bundle_sha256": "f" * 64,
        "verified_at": "2026-07-10T12:00:00Z",
        "validator": "scripts/ci/backend_release_ready.py",
        "validator_exit_code": 0,
    }
    payload.update(overrides)
    return payload


def configure_release_authorization(tmp_path, monkeypatch, **overrides):
    authorization = tmp_path / "authorization.json"
    bundle = tmp_path / "authorization.sigstore.json"
    authorization.write_text(json.dumps(release_authorization(**overrides)))
    bundle.write_text(
        '{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}'
    )
    authorization.chmod(0o600)
    bundle.chmod(0o600)
    monkeypatch.setenv(billing.RELEASE_AUTHORIZATION_PATH_ENV, str(authorization))
    monkeypatch.setenv(
        billing.RELEASE_AUTHORIZATION_SHA_ENV,
        hashlib.sha256(authorization.read_bytes()).hexdigest(),
    )
    monkeypatch.setenv(
        billing.RELEASE_AUTHORIZATION_BUNDLE_PATH_ENV,
        str(bundle),
    )
    monkeypatch.setenv(
        billing.RELEASE_AUTHORIZATION_BUNDLE_SHA_ENV,
        hashlib.sha256(bundle.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        billing,
        "verify_release_authorization_signature",
        lambda authorization_bytes, bundle_bytes: None,
    )
    return authorization, bundle


def annual_request():
    return request(
        action="annual-contract",
        offer_id="tinyzkp_certified",
        stripe_price_id="price_certified",
        stripe_product_id="prod_certified",
    )


def test_evaluation_plan_is_half_and_never_checkout():
    offers = billing.load_offers()
    req = request()
    offer = req.validate(offers)
    summary = billing.plan(req, offer)
    assert summary["amount_cents"] == 1_250_000
    assert summary["collection_method"] == "send_invoice"
    assert summary["public_checkout"] is False
    assert len(summary["contract_evidence_sha256"]) == 64
    assert len(summary["plan_sha256"]) == 64
    changed = billing.plan(
        request(days_until_due=30), request(days_until_due=30).validate(offers)
    )
    assert changed["plan_sha256"] != summary["plan_sha256"]


def test_contract_billing_requires_verified_tinyzkp_sender_identity(monkeypatch):
    monkeypatch.delenv("TINYZKP_CONTRACT_SENDER_IDENTITY_CONFIRMED", raising=False)
    with pytest.raises(ValueError, match="sender identity"):
        billing.validate_sender_identity_gate()

    monkeypatch.setenv("TINYZKP_CONTRACT_SENDER_IDENTITY_CONFIRMED", "1")
    billing.validate_sender_identity_gate()

    account = {
        "business_profile": {
            "name": "TinyZKP",
            "support_email": "billing@tinyzkp.com",
            "support_url": "https://tinyzkp.com/contact",
        }
    }
    billing.validate_customer_facing_sender_identity(account)
    account["business_profile"]["support_email"] = "founder@unrelated.example"
    with pytest.raises(ValueError, match="must identify TinyZKP"):
        billing.validate_customer_facing_sender_identity(account)


def test_delivery_requires_acceptance_evidence():
    missing = evidence(
        action="evaluation-delivery",
        delivery_acceptance_sha256=None,
        delivery_accepted_at=None,
    )
    with pytest.raises(ValueError, match="delivery acceptance SHA-256"):
        request(action="evaluation-delivery", evidence=missing).validate(
            billing.load_offers()
        )


def test_contract_evidence_requires_owner_only_exact_schema(tmp_path):
    path = tmp_path / "contract.json"
    payload = {
        "schema_version": 2,
        "agreement_id": "eval-001",
        "offer_id": "founding_evaluation",
        "stripe_customer_id": "cus_test",
        "agreement_sha256": "a" * 64,
        "scope_sha256": "b" * 64,
        "agreement_gate_sha256": "1" * 64,
        "qualification_sha256": "2" * 64,
        "partner_preflight_sha256": "3" * 64,
        "stripe_test_drill_sha256": "4" * 64,
        "delivery_manifest_sha256": None,
        "signed_at": "2026-07-09T12:00:00Z",
        "delivery_acceptance_sha256": None,
        "delivery_accepted_at": None,
        "deposit_invoice_id": None,
        "deposit_plan_sha256": None,
        "negotiated_annual_amount_cents": None,
    }
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="owner-only"):
        billing.load_contract_evidence(path)
    path.chmod(0o600)
    loaded = billing.load_contract_evidence(path)
    assert loaded.digest() == evidence().digest()
    payload["unknown"] = True
    path.write_text(json.dumps(payload))
    path.chmod(0o600)
    with pytest.raises(ValueError, match="missing or unknown"):
        billing.load_contract_evidence(path)

    symlink = tmp_path / "linked.json"
    symlink.symlink_to(path)
    with pytest.raises(ValueError, match="non-symlink"):
        billing.load_contract_evidence(symlink)


def test_private_json_is_hashed_and_parsed_from_one_nofollow_descriptor(
    tmp_path, monkeypatch
):
    path = tmp_path / "private.json"
    path.write_text('{"status":"ready"}')
    path.chmod(0o600)
    opened = []
    real_open = billing.os.open

    def tracked_open(raw, flags, *args):
        opened.append((raw, flags))
        return real_open(raw, flags, *args)

    monkeypatch.setattr(billing.os, "open", tracked_open)
    monkeypatch.setattr(
        billing.Path,
        "read_text",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("private JSON must not be reopened through Path.read_text")
        ),
    )
    payload, digest = billing.load_private_json_document_with_digest(
        path, "private document"
    )
    assert payload == {"status": "ready"}
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(opened) == 1
    assert opened[0][1] & getattr(billing.os, "O_NOFOLLOW", 0) == getattr(
        billing.os, "O_NOFOLLOW", 0
    )


def test_contract_evidence_template_has_exact_schema():
    template = json.loads(
        (billing.ROOT / "commercial" / "contract-evidence.template.json").read_text()
    )
    assert set(template) == billing.CONTRACT_EVIDENCE_KEYS
    annual = json.loads(
        (
            billing.ROOT
            / "commercial"
            / "annual-contract-evidence.template.json"
        ).read_text()
    )
    assert set(annual) == billing.CONTRACT_EVIDENCE_KEYS
    assert annual["schema_version"] == 2
    assert all(
        annual[field] is None
        for field in (
            "agreement_gate_sha256",
            "qualification_sha256",
            "partner_preflight_sha256",
            "stripe_test_drill_sha256",
            "delivery_manifest_sha256",
        )
    )


def test_annual_order_template_has_exact_schema():
    template = json.loads(
        (billing.ROOT / "commercial" / "annual-order.template.json").read_text()
    )
    assert set(template) == billing.ANNUAL_ORDER_KEYS


def test_contract_evidence_binding_and_canonical_time_fail_closed():
    wrong = evidence(agreement_id="other")
    with pytest.raises(ValueError, match="does not bind"):
        request(evidence=wrong).validate(billing.load_offers())
    offset = evidence(signed_at="2026-07-09T05:00:00-07:00")
    with pytest.raises(ValueError, match="canonical UTC"):
        request(evidence=offset).validate(billing.load_offers())
    wrong_type = evidence(schema_version=True)
    with pytest.raises(ValueError, match="schema_version"):
        request(evidence=wrong_type).validate(billing.load_offers())
    future = evidence(signed_at="2099-01-01T00:00:00Z")
    with pytest.raises(ValueError, match="future"):
        request(evidence=future).validate(billing.load_offers())
    backwards = evidence(
        action="evaluation-delivery",
        signed_at="2026-07-10T12:00:00Z",
        delivery_accepted_at="2026-07-09T12:00:00Z",
    )
    with pytest.raises(ValueError, match="cannot precede"):
        request(action="evaluation-delivery", evidence=backwards).validate(
            billing.load_offers()
        )
    with pytest.raises(ValueError, match="valid only for an annual contract"):
        request(evidence=evidence(negotiated_annual_amount_cents=1)).validate(
            billing.load_offers()
        )


def test_contract_documents_are_owner_only_and_hash_bound(tmp_path):
    agreement = tmp_path / "signed-agreement.pdf"
    scope = tmp_path / "acceptance.json"
    agreement.write_bytes(b"signed agreement")
    scope.write_text(json.dumps(acceptance_matrix()))
    agreement.chmod(0o600)
    scope.chmod(0o600)
    bound = evidence(
        agreement_sha256=hashlib.sha256(agreement.read_bytes()).hexdigest(),
        scope_sha256=hashlib.sha256(scope.read_bytes()).hexdigest(),
    )
    with pytest.raises(ValueError, match="missing required commercial evidence"):
        billing.verify_contract_documents(
            bound,
            "evaluation-deposit",
            agreement_document=agreement,
            scope_document=scope,
            delivery_acceptance_document=None,
        )
    scope.write_bytes(b"changed scope")
    with pytest.raises(ValueError, match="scope document does not match"):
        billing.validate_acceptance_matrix(
            scope,
            bound,
            expected_sha256=bound.scope_sha256,
        )
    scope.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        billing.private_document_sha256(scope, "scope document")


def test_evaluation_contract_requires_exact_qualification_preflight_gate_and_test_drill(
    tmp_path, monkeypatch
):
    def write_private(name, payload):
        path = tmp_path / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o600)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    agreement = tmp_path / "signed-agreement.pdf"
    scope = tmp_path / "acceptance.json"
    agreement.write_bytes(b"signed agreement")
    scope.write_text(json.dumps(acceptance_matrix()), encoding="utf-8")
    agreement.chmod(0o600)
    scope.chmod(0o600)
    qualification_payload = {
        "application_id": "eval_001",
        "reviewed_at": "2020-01-01T12:00:00Z",
    }
    qualification, qualification_sha = write_private(
        "qualification.json", qualification_payload
    )
    preflight_payload = {
        "application_id": "eval_001",
        "checked_at": "2020-01-01T13:00:00Z",
        "bound_inputs": {"qualification_evidence_sha256": qualification_sha},
    }
    preflight, preflight_sha = write_private("preflight.json", preflight_payload)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    signed_at = (now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    reviewed_at = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    gate_payload = {
        "schema_version": billing.agreement_gate.GATE_SCHEMA,
        "status": "approved",
        "agreement_id": "eval-001",
        "offer_id": "founding_evaluation",
        "form_id": "tinyzkp-evaluation-msa-sow",
        "form_version": "1.0.0",
        "form_profile_sha256": "6" * 64,
        "approved_template_sha256": "7" * 64,
        "counsel_approval_sha256": "8" * 64,
        "agreement_source_sha256": "9" * 64,
        "signed_agreement_sha256": hashlib.sha256(agreement.read_bytes()).hexdigest(),
        "scope_sha256": hashlib.sha256(scope.read_bytes()).hexdigest(),
        "qualification_sha256": qualification_sha,
        "partner_preflight_sha256": preflight_sha,
        "required_terms": {
            field: True for field in billing.agreement_gate.REQUIRED_TERMS
        },
        "placeholders_absent": True,
        "material_deviations_reviewed": True,
        "approved_for_execution": True,
        "execution_reviewed_by": "Outside Counsel",
        "execution_reviewed_at": reviewed_at,
    }
    gate, gate_sha = write_private("agreement-gate.json", gate_payload)
    drill_payload = {
        "schema_version": billing.stripe_test_drill.SCHEMA_VERSION,
        "status": "passed",
        "stripe_api_version": billing.STRIPE_API_VERSION,
        "stripe_sdk_version": "15.3.0",
        "stripe_account_id": "acct_expected",
        "stripe_display_name": "TinyZKP Test",
        "stripe_customer_id": "cus_test_drill",
        "stripe_invoice_id": "in_test_drill",
        "drill_id": "drill-001",
        "amount_cents": billing.stripe_test_drill.AMOUNT_CENTS,
        "currency": "usd",
        "collection_method": "send_invoice",
        "days_until_due": 15,
        "auto_advance": False,
        "livemode": False,
        "hosted_invoice_url_sha256": "a" * 64,
        "created_status": "draft",
        "finalized_status": "open",
        "retrieved_status": "open",
        "voided_status": "void",
        "send_api_invoked": False,
        "checkout_created": False,
        "cleanup_complete": True,
        "started_at": (now - timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completed_at": reviewed_at,
        "release_sha": "b" * 40,
        "operation_digest": "c" * 64,
    }
    drill, drill_sha = write_private("stripe-test-drill.json", drill_payload)
    bound = evidence(
        agreement_sha256=gate_payload["signed_agreement_sha256"],
        scope_sha256=gate_payload["scope_sha256"],
        agreement_gate_sha256=gate_sha,
        qualification_sha256=qualification_sha,
        partner_preflight_sha256=preflight_sha,
        stripe_test_drill_sha256=drill_sha,
        signed_at=signed_at,
    )
    monkeypatch.setattr(
        billing.agreement_gate.evaluation_qualification,
        "validate_evidence",
        lambda payload, compatibility: payload,
    )
    monkeypatch.setattr(
        billing.agreement_gate.partner_preflight,
        "validate_evidence",
        lambda payload, compatibility: payload,
        raising=False,
    )
    billing.verify_contract_documents(
        bound,
        "evaluation-deposit",
        agreement_document=agreement,
        scope_document=scope,
        agreement_gate_document=gate,
        qualification_document=qualification,
        partner_preflight_document=preflight,
        stripe_test_drill_document=drill,
        expected_stripe_account_id="acct_expected",
        expected_stripe_display_name="TinyZKP Test",
        delivery_acceptance_document=None,
    )
    qualification.write_text('{"application_id":"eval_tampered"}', encoding="utf-8")
    qualification.chmod(0o600)
    with pytest.raises(ValueError, match="qualification does not match"):
        billing.verify_contract_documents(
            bound,
            "evaluation-deposit",
            agreement_document=agreement,
            scope_document=scope,
            agreement_gate_document=gate,
            qualification_document=qualification,
            partner_preflight_document=preflight,
            stripe_test_drill_document=drill,
            expected_stripe_account_id="acct_expected",
            expected_stripe_display_name="TinyZKP Test",
            delivery_acceptance_document=None,
        )


def test_acceptance_matrix_must_be_complete_and_semantically_safe(tmp_path):
    scope = tmp_path / "acceptance.json"
    incomplete = acceptance_matrix()
    incomplete["candidate"]["max_scratch_bytes"] = None
    scope.write_text(json.dumps(incomplete))
    scope.chmod(0o600)
    with pytest.raises(ValueError, match="max_scratch_bytes"):
        billing.validate_acceptance_matrix(scope, evidence())

    unsafe = acceptance_matrix()
    unsafe["data_boundary"]["witness_transfer_allowed"] = True
    scope.write_text(json.dumps(unsafe))
    scope.chmod(0o600)
    with pytest.raises(ValueError, match="data boundary"):
        billing.validate_acceptance_matrix(scope, evidence())

    placeholder = acceptance_matrix()
    placeholder["baseline"]["host_id"] = "REPLACE_ME"
    scope.write_text(json.dumps(placeholder))
    scope.chmod(0o600)
    with pytest.raises(ValueError, match="must be completed"):
        billing.validate_acceptance_matrix(scope, evidence())


def test_stripe_client_is_version_pinned_and_retry_safe(monkeypatch):
    captured = {}

    def fake_client(api_key, **kwargs):
        captured.update(api_key=api_key, **kwargs)
        return "client"

    monkeypatch.setattr(billing.stripe, "StripeClient", fake_client)
    assert billing.create_stripe_client("sk_test_placeholder") == "client"
    assert captured == {
        "api_key": "sk_test_placeholder",
        "stripe_version": "2026-02-25.clover",
        "max_network_retries": 2,
    }


def test_annual_contract_requires_matching_annual_price():
    req = request(
        action="annual-contract",
        offer_id="tinyzkp_certified",
        stripe_price_id="price_certified",
        stripe_product_id="prod_certified",
    )
    offer = req.validate(billing.load_offers())
    billing.validate_annual_price(
        {
            "id": "price_certified",
            "active": True,
            "currency": "usd",
            "unit_amount": 6_000_000,
            "recurring": {"interval": "year", "interval_count": 1},
            "lookup_key": "tinyzkp_certified_annual_contract_v1",
            "metadata": {
                "tinyzkp_offer_id": "tinyzkp_certified",
                "tinyzkp_contract_price": "true",
            },
            "product": {
                "id": "prod_certified",
                "active": True,
                "name": "TinyZKP Certified",
                "metadata": {
                    "tinyzkp_offer_id": "tinyzkp_certified",
                    "tinyzkp_contract_product": "true",
                },
            },
        },
        offer,
        expected_price_id="price_certified",
        expected_product_id="prod_certified",
        expected_amount_cents=6_000_000,
    )
    with pytest.raises(ValueError, match="amount/currency"):
        billing.validate_annual_price(
            {
                "id": "price_certified",
                "active": True,
                "currency": "usd",
                "unit_amount": 1,
                "recurring": {"interval": "year", "interval_count": 1},
                "product": {"id": "prod_certified"},
            },
            offer,
            expected_price_id="price_certified",
            expected_product_id="prod_certified",
            expected_amount_cents=6_000_000,
        )
    wrong_product = {
        "id": "price_certified",
        "active": True,
        "currency": "usd",
        "unit_amount": 6_000_000,
        "recurring": {"interval": "year", "interval_count": 1},
        "product": {"id": "prod_unrelated"},
    }
    with pytest.raises(ValueError, match="identity mismatch"):
        billing.validate_annual_price(
            wrong_product,
            offer,
            expected_price_id="price_certified",
            expected_product_id="prod_certified",
            expected_amount_cents=6_000_000,
        )


def test_fleet_negotiated_amount_is_signed_floor_checked_and_price_exact():
    negotiated = 15_000_000
    req = request(
        action="annual-contract",
        offer_id="tinyzkp_fleet_oem",
        evidence=evidence(
            action="annual-contract",
            offer_id="tinyzkp_fleet_oem",
            negotiated_annual_amount_cents=negotiated,
        ),
        stripe_price_id="price_fleet_150k",
        stripe_product_id="prod_fleet",
    )
    offer = req.validate(billing.load_offers())
    binding = billing.ReleaseBindingV1(
        authorization_sha256="1" * 64,
        authorization_bundle_sha256="2" * 64,
        release_sha="3" * 40,
        source_tree_sha256="4" * 64,
        verified_at="2026-07-10T12:00:00Z",
    )
    summary = billing.plan(req, offer, binding)
    assert summary["amount_cents"] == negotiated
    assert summary["negotiated_annual_amount_cents"] == negotiated
    assert (
        billing.contract_metadata(req, "annual", summary["plan_sha256"], binding)[
            "tinyzkp_negotiated_annual_amount_cents"
        ]
        == str(negotiated)
    )
    billing.validate_annual_price(
        {
            "id": "price_fleet_150k",
            "active": True,
            "currency": "usd",
            "unit_amount": negotiated,
            "recurring": {"interval": "year", "interval_count": 1},
            "lookup_key": "tinyzkp_fleet_oem_annual_contract_v1",
            "metadata": {
                "tinyzkp_offer_id": "tinyzkp_fleet_oem",
                "tinyzkp_contract_price": "true",
            },
            "product": {
                "id": "prod_fleet",
                "active": True,
                "name": "TinyZKP Fleet / OEM",
                "metadata": {
                    "tinyzkp_offer_id": "tinyzkp_fleet_oem",
                    "tinyzkp_contract_product": "true",
                },
            },
        },
        offer,
        expected_price_id="price_fleet_150k",
        expected_product_id="prod_fleet",
        expected_amount_cents=negotiated,
    )

    below_floor = request(
        action="annual-contract",
        offer_id="tinyzkp_fleet_oem",
        evidence=evidence(
            action="annual-contract",
            offer_id="tinyzkp_fleet_oem",
            negotiated_annual_amount_cents=12_499_999,
        ),
        stripe_price_id="price_fleet_low",
        stripe_product_id="prod_fleet",
    )
    with pytest.raises(ValueError, match="advertised minimum"):
        below_floor.validate(billing.load_offers())


def test_annual_amount_must_match_typed_countersigned_order(tmp_path):
    agreement = tmp_path / "countersigned-agreement.pdf"
    agreement.write_bytes(b"countersigned annual agreement")
    agreement.chmod(0o600)
    req = request(
        action="annual-contract",
        offer_id="tinyzkp_fleet_oem",
        evidence=evidence(
            action="annual-contract",
            offer_id="tinyzkp_fleet_oem",
            agreement_sha256=hashlib.sha256(agreement.read_bytes()).hexdigest(),
            negotiated_annual_amount_cents=15_000_000,
        ),
        stripe_price_id="price_fleet_150k",
        stripe_product_id="prod_fleet",
    )
    order = {
        "schema_version": "tinyzkp-annual-order-v1",
        "agreement_id": req.agreement_id,
        "offer_id": req.offer_id,
        "stripe_customer_id": req.customer_id,
        "signed_agreement_sha256": req.evidence.agreement_sha256,
        "negotiated_annual_amount_cents": 15_000_000,
        "currency": "usd",
        "billing_interval": "year",
        "stripe_price_id": req.stripe_price_id,
        "stripe_product_id": req.stripe_product_id,
        "customer_countersigned_at": "2026-07-09T11:00:00Z",
        "tinyzkp_countersigned_at": req.evidence.signed_at,
    }
    scope = tmp_path / "annual-order.json"
    scope.write_text(json.dumps(order), encoding="utf-8")
    scope.chmod(0o600)
    bound = billing.ContractEvidenceV2(
        **{
            **billing.asdict(req.evidence),
            "scope_sha256": hashlib.sha256(scope.read_bytes()).hexdigest(),
        }
    )
    billing.verify_contract_documents(
        bound,
        "annual-contract",
        agreement_document=agreement,
        scope_document=scope,
        delivery_acceptance_document=None,
        stripe_price_id=req.stripe_price_id,
        stripe_product_id=req.stripe_product_id,
    )
    order["negotiated_annual_amount_cents"] = 15_000_001
    scope.write_text(json.dumps(order), encoding="utf-8")
    scope.chmod(0o600)
    changed = billing.ContractEvidenceV2(
        **{
            **billing.asdict(bound),
            "scope_sha256": hashlib.sha256(scope.read_bytes()).hexdigest(),
        }
    )
    with pytest.raises(ValueError, match="exact contract, amount, and Stripe price"):
        billing.verify_contract_documents(
            changed,
            "annual-contract",
            agreement_document=agreement,
            scope_document=scope,
            delivery_acceptance_document=None,
            stripe_price_id=req.stripe_price_id,
            stripe_product_id=req.stripe_product_id,
        )


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_acceptance_matrix_rejects_noncanonical_nonfinite_numbers(tmp_path, constant):
    scope = tmp_path / "acceptance.json"
    raw = json.dumps(acceptance_matrix()).replace("1.5", constant, 1)
    scope.write_text(raw, encoding="utf-8")
    scope.chmod(0o600)
    bound = evidence(scope_sha256=hashlib.sha256(scope.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="noncanonical JSON number"):
        billing.validate_acceptance_matrix(
            scope,
            bound,
            expected_sha256=bound.scope_sha256,
        )


@pytest.mark.parametrize("spelling", ("1.500", "1e0", "-0"))
def test_acceptance_matrix_rejects_noncanonical_finite_number_spellings(
    tmp_path, spelling
):
    scope = tmp_path / "acceptance.json"
    raw = json.dumps(acceptance_matrix()).replace("1.5", spelling, 1)
    scope.write_text(raw, encoding="utf-8")
    scope.chmod(0o600)
    bound = evidence(scope_sha256=hashlib.sha256(scope.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="noncanonical JSON number"):
        billing.validate_acceptance_matrix(
            scope,
            bound,
            expected_sha256=bound.scope_sha256,
        )


@pytest.mark.parametrize(
    "field_path",
    (("baseline", "peak_rss_bytes"), ("acceptance", "target_peak_rss_bytes")),
)
def test_acceptance_matrix_rejects_boolean_integer_fields(tmp_path, field_path):
    scope = tmp_path / "acceptance.json"
    payload = acceptance_matrix()
    payload[field_path[0]][field_path[1]] = True
    scope.write_text(json.dumps(payload), encoding="utf-8")
    scope.chmod(0o600)
    with pytest.raises(ValueError, match="must be (null or )?positive"):
        billing.validate_acceptance_matrix(scope, evidence())

def test_annual_contract_requires_hash_bound_signed_release_authorization(
    tmp_path, monkeypatch
):
    annual = annual_request()
    monkeypatch.delenv(billing.RELEASE_AUTHORIZATION_PATH_ENV, raising=False)
    monkeypatch.delenv(billing.RELEASE_AUTHORIZATION_SHA_ENV, raising=False)
    monkeypatch.delenv(billing.RELEASE_AUTHORIZATION_BUNDLE_PATH_ENV, raising=False)
    monkeypatch.delenv(billing.RELEASE_AUTHORIZATION_BUNDLE_SHA_ENV, raising=False)
    with pytest.raises(
        ValueError, match="hash-bound signed backend release authorization"
    ):
        billing.validate_release_availability(annual)

    ready, _bundle = configure_release_authorization(tmp_path, monkeypatch)
    binding = billing.validate_release_availability(annual)
    assert binding == billing.ReleaseBindingV1(
        authorization_sha256=hashlib.sha256(ready.read_bytes()).hexdigest(),
        authorization_bundle_sha256=os.environ[
            billing.RELEASE_AUTHORIZATION_BUNDLE_SHA_ENV
        ],
        release_sha="a" * 40,
        source_tree_sha256="b" * 64,
        verified_at="2026-07-10T12:00:00Z",
    )

    weak = json.loads(ready.read_text())
    weak["status"] = "blocked"
    ready.write_text(json.dumps(weak))
    ready.chmod(0o600)
    monkeypatch.setenv(
        billing.RELEASE_AUTHORIZATION_SHA_ENV,
        hashlib.sha256(ready.read_bytes()).hexdigest(),
    )
    with pytest.raises(ValueError, match="not ready"):
        billing.validate_release_availability(annual)

    for field, value, message in (
        ("schema_version", True, "schema_version"),
        ("validator_exit_code", False, "not ready"),
    ):
        malformed = json.loads(json.dumps(weak))
        malformed["status"] = "ready"
        malformed["schema_version"] = 1
        malformed["validator_exit_code"] = 0
        malformed[field] = value
        ready.write_text(json.dumps(malformed))
        ready.chmod(0o600)
        monkeypatch.setenv(
            billing.RELEASE_AUTHORIZATION_SHA_ENV,
            hashlib.sha256(ready.read_bytes()).hexdigest(),
        )
        with pytest.raises(ValueError, match=message):
            billing.validate_release_availability(annual)


def test_annual_preview_validates_release_before_emitting_plan(tmp_path, monkeypatch):
    annual = annual_request()
    offer = annual.validate(billing.load_offers())
    for name in (
        billing.RELEASE_AUTHORIZATION_PATH_ENV,
        billing.RELEASE_AUTHORIZATION_SHA_ENV,
        billing.RELEASE_AUTHORIZATION_BUNDLE_PATH_ENV,
        billing.RELEASE_AUTHORIZATION_BUNDLE_SHA_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="signed backend release authorization"):
        billing.prepare_plan(annual, offer)

    configure_release_authorization(tmp_path, monkeypatch)
    summary, binding = billing.prepare_plan(annual, offer)
    assert binding is not None
    assert (
        summary["backend_release_authorization_sha256"] == binding.authorization_sha256
    )
    assert (
        summary["backend_release_authorization_bundle_sha256"]
        == binding.authorization_bundle_sha256
    )


def test_release_authorization_requires_valid_pinned_sigstore_bundle(
    tmp_path, monkeypatch
):
    annual = annual_request()
    _authorization, bundle = configure_release_authorization(tmp_path, monkeypatch)
    monkeypatch.setattr(
        billing,
        "verify_release_authorization_signature",
        lambda authorization_bytes, bundle_bytes: (_ for _ in ()).throw(
            ValueError("backend release authorization signature is invalid")
        ),
    )
    with pytest.raises(ValueError, match="signature is invalid"):
        billing.validate_release_availability(annual)

    monkeypatch.setattr(
        billing,
        "verify_release_authorization_signature",
        lambda authorization_bytes, bundle_bytes: None,
    )
    bundle.write_text("tampered")
    bundle.chmod(0o600)
    with pytest.raises(ValueError, match="bundle digest mismatch"):
        billing.validate_release_availability(annual)


def test_sigstore_verification_pins_release_workflow_identity(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(billing.shutil, "which", lambda name: "/trusted/bin/cosign")

    def run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, "Verified OK")

    monkeypatch.setattr(billing.subprocess, "run", run)
    billing.verify_release_authorization_signature(b"authorization", b"bundle")
    command = captured["command"]
    assert command[0] == "/trusted/bin/cosign"
    assert command[1:3] == ["verify-blob", "--bundle"]
    assert command[4:8] == [
        "--certificate-identity-regexp",
        billing.SIGSTORE_IDENTITY_REGEXP,
        "--certificate-oidc-issuer",
        billing.SIGSTORE_ISSUER,
    ]
    assert captured["kwargs"]["stdin"] == subprocess.DEVNULL


def test_evaluation_milestone_isolated_to_its_own_invoice(monkeypatch):
    calls = []
    invoices = SimpleNamespace(
        create=lambda params, options: (
            calls.append(("invoice", params, options)) or {"id": "in_eval"}
        ),
        finalize_invoice=lambda invoice_id, params, options: (
            calls.append(("finalize", invoice_id, params, options))
            or {"id": invoice_id, "status": "open"}
        ),
        send_invoice=lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("invoice email sending must remain disabled")
        ),
    )
    invoice_items = SimpleNamespace(
        create=lambda params, options: (
            calls.append(("item", params, options)) or {"id": "ii_eval"}
        )
    )
    client = SimpleNamespace(
        v1=SimpleNamespace(invoices=invoices, invoice_items=invoice_items)
    )
    req = request()
    offer = req.validate(billing.load_offers())
    plan_sha256 = billing.plan(req, offer)["plan_sha256"]
    created = billing.create_invoice(req, offer, client, plan_sha256)

    invoice_call = calls[0][1]
    item_call = calls[1][1]
    assert created["id"] == "in_eval"
    assert invoice_call["auto_advance"] is False
    assert "pending_invoice_items_behavior" not in invoice_call
    assert item_call["invoice"] == "in_eval"
    assert invoice_call["metadata"]["tinyzkp_agreement_sha256"] == "a" * 64
    assert invoice_call["metadata"]["tinyzkp_plan_sha256"] == plan_sha256
    assert calls[2][0:2] == ("finalize", "in_eval")
    assert calls[2][2]["auto_advance"] is False
    assert calls[2][3]["idempotency_key"].endswith("-finalize")


def test_hosted_invoice_url_is_strict_https_stripe_invoice_path():
    url = "https://invoice.stripe.com/i/in_contract?test=expected"
    assert billing.hosted_invoice_url({"hosted_invoice_url": url}) == url


@pytest.mark.parametrize(
    "url",
    (
        "http://invoice.stripe.com/i/in_contract",
        "https://example.invalid/i/in_contract",
        "https://user@invoice.stripe.com/i/in_contract",
        "https://user:password@invoice.stripe.com/i/in_contract",
        "https://invoice.stripe.com:443/i/in_contract",
        "https://invoice.stripe.com/",
        "https://invoice.stripe.com/i/",
        "https://invoice.stripe.com/not-an-invoice/in_contract",
        "https://invoice.stripe.com/i/in_contract#fragment",
        "https://invoice.stripe.com/i/in_contract#",
        "https://invoice.stripe.com/i/in_contract\n",
        " https://invoice.stripe.com/i/in_contract",
    ),
)
def test_hosted_invoice_url_rejects_untrusted_variants(url):
    with pytest.raises(ValueError, match="untrusted"):
        billing.hosted_invoice_url({"hosted_invoice_url": url})


def test_founding_offer_is_limited_to_two_unique_agreements(monkeypatch):
    plans = {
        agreement: billing.plan(
            request(agreement_id=agreement),
            request(agreement_id=agreement).validate(billing.load_offers()),
        )["plan_sha256"]
        for agreement in ("eval-001", "eval-002")
    }
    invoices = {
        "data": [
            {
                "id": f"in_{agreement}",
                "customer": "cus_test",
                "status": "paid",
                "currency": "usd",
                "collection_method": "send_invoice",
                "auto_advance": False,
                "total": 1_250_000,
                "metadata": {
                    "tinyzkp_offer_id": "founding_evaluation",
                    "tinyzkp_agreement_id": agreement,
                    "tinyzkp_milestone": "deposit",
                    "tinyzkp_plan_sha256": plans[agreement],
                    "tinyzkp_contract_evidence_sha256": request(
                        agreement_id=agreement
                    ).evidence.digest(),
                    "tinyzkp_scope_sha256": "b" * 64,
                    "tinyzkp_agreement_gate_sha256": "1" * 64,
                    "tinyzkp_qualification_sha256": "2" * 64,
                    "tinyzkp_partner_preflight_sha256": "3" * 64,
                    "tinyzkp_test_drill_sha256": "4" * 64,
                },
            }
            for agreement in ("eval-001", "eval-002")
        ]
    }
    client = SimpleNamespace(
        v1=SimpleNamespace(invoices=SimpleNamespace(list=lambda params: invoices))
    )

    existing = request(agreement_id="eval-001")
    billing.validate_evaluation_history(existing, client, plans["eval-001"])
    with pytest.raises(ValueError, match="slots are already allocated"):
        third = request(agreement_id="eval-003")
        third_plan = billing.plan(third, third.validate(billing.load_offers()))[
            "plan_sha256"
        ]
        billing.validate_evaluation_history(third, client, third_plan)


def test_delivery_requires_existing_paid_deposit():
    invoices = SimpleNamespace(
        list=lambda params: {
            "data": [
                {
                    "status": "open",
                    "metadata": {
                        "tinyzkp_offer_id": "standard_evaluation",
                        "tinyzkp_agreement_id": "eval-001",
                        "tinyzkp_milestone": "deposit",
                    },
                }
            ]
        }
    )
    client = SimpleNamespace(v1=SimpleNamespace(invoices=invoices))
    delivery = request(
        action="evaluation-delivery",
        offer_id="standard_evaluation",
    )
    with pytest.raises(ValueError, match="paid deposit invoice"):
        delivery_plan = billing.plan(
            delivery, delivery.validate(billing.load_offers())
        )["plan_sha256"]
        billing.validate_evaluation_history(delivery, client, delivery_plan)


def paid_deposit_for_delivery(req):
    return {
        "id": req.evidence.deposit_invoice_id,
        "customer": req.customer_id,
        "status": "paid",
        "currency": "usd",
        "total": 2_000_000
        if req.offer_id == "standard_evaluation"
        else 1_250_000,
        "amount_paid": 2_000_000
        if req.offer_id == "standard_evaluation"
        else 1_250_000,
        "amount_remaining": 0,
        "collection_method": "send_invoice",
        "auto_advance": False,
        "metadata": {
            "tinyzkp_offer_id": req.offer_id,
            "tinyzkp_agreement_id": req.agreement_id,
            "tinyzkp_milestone": "deposit",
            "tinyzkp_plan_sha256": req.evidence.deposit_plan_sha256,
            "tinyzkp_agreement_sha256": req.evidence.agreement_sha256,
            "tinyzkp_scope_sha256": req.evidence.scope_sha256,
            "tinyzkp_signed_at": req.evidence.signed_at,
            "tinyzkp_agreement_gate_sha256": req.evidence.agreement_gate_sha256,
            "tinyzkp_qualification_sha256": req.evidence.qualification_sha256,
            "tinyzkp_partner_preflight_sha256": req.evidence.partner_preflight_sha256,
            "tinyzkp_test_drill_sha256": req.evidence.stripe_test_drill_sha256,
        },
    }


@pytest.mark.parametrize(
    ("target", "field", "value"),
    [
        ("invoice", "id", "in_other"),
        ("invoice", "customer", "cus_other"),
        ("invoice", "total", 1),
        ("invoice", "amount_paid", 1),
        ("invoice", "amount_remaining", 1),
        ("invoice", "collection_method", "charge_automatically"),
        ("invoice", "auto_advance", True),
        ("metadata", "tinyzkp_plan_sha256", "f" * 64),
        ("metadata", "tinyzkp_scope_sha256", "e" * 64),
        ("metadata", "tinyzkp_agreement_sha256", "d" * 64),
        ("metadata", "tinyzkp_agreement_gate_sha256", "d" * 64),
        ("metadata", "tinyzkp_qualification_sha256", "d" * 64),
        ("metadata", "tinyzkp_partner_preflight_sha256", "d" * 64),
        ("metadata", "tinyzkp_test_drill_sha256", "d" * 64),
    ],
)
def test_delivery_deposit_is_exactly_object_plan_amount_and_document_bound(
    target, field, value
):
    req = request(action="evaluation-delivery")
    deposit = paid_deposit_for_delivery(req)
    plan_sha256 = billing.plan(req, req.validate(billing.load_offers()))[
        "plan_sha256"
    ]
    client = SimpleNamespace(
        v1=SimpleNamespace(
            invoices=SimpleNamespace(list=lambda params: {"data": [deposit]})
        )
    )
    billing.validate_evaluation_history(req, client, plan_sha256)
    if target == "metadata":
        deposit["metadata"][field] = value
    else:
        deposit[field] = value
    with pytest.raises(ValueError, match="exact (paid|fully paid) deposit"):
        billing.validate_evaluation_history(req, client, plan_sha256)


def test_delivery_evidence_requires_typed_deposit_object_and_plan_binding():
    for overrides in (
        {"deposit_invoice_id": None},
        {"deposit_invoice_id": "not-an-invoice"},
        {"deposit_plan_sha256": None},
        {"deposit_plan_sha256": "A" * 64},
    ):
        req = request(
            action="evaluation-delivery",
            evidence=evidence(action="evaluation-delivery", **overrides),
        )
        with pytest.raises(ValueError, match="exact paid deposit"):
            req.validate(billing.load_offers())


def test_existing_milestone_with_different_plan_is_rejected():
    req = request()
    invoices = SimpleNamespace(
        list=lambda params: {
            "data": [
                {
                    "status": "open",
                    "metadata": {
                        "tinyzkp_offer_id": req.offer_id,
                        "tinyzkp_agreement_id": req.agreement_id,
                        "tinyzkp_milestone": "deposit",
                        "tinyzkp_plan_sha256": "f" * 64,
                    },
                }
            ]
        }
    )
    client = SimpleNamespace(v1=SimpleNamespace(invoices=invoices))
    plan_sha256 = billing.plan(req, req.validate(billing.load_offers()))["plan_sha256"]
    with pytest.raises(ValueError, match="different plan"):
        billing.validate_evaluation_history(req, client, plan_sha256)


def test_existing_same_plan_invoice_is_reused_instead_of_recreated():
    req = request()
    plan_sha256 = billing.plan(req, req.validate(billing.load_offers()))[
        "plan_sha256"
    ]
    existing = {
        "id": "in_existing",
        "customer": req.customer_id,
        "status": "open",
        "currency": "usd",
        "collection_method": "send_invoice",
        "auto_advance": False,
        "total": 1_250_000,
        "metadata": {
            "tinyzkp_offer_id": req.offer_id,
            "tinyzkp_agreement_id": req.agreement_id,
            "tinyzkp_milestone": "deposit",
            "tinyzkp_plan_sha256": plan_sha256,
            "tinyzkp_contract_evidence_sha256": req.evidence.digest(),
            "tinyzkp_scope_sha256": req.evidence.scope_sha256,
            "tinyzkp_agreement_gate_sha256": req.evidence.agreement_gate_sha256,
            "tinyzkp_qualification_sha256": req.evidence.qualification_sha256,
            "tinyzkp_partner_preflight_sha256": req.evidence.partner_preflight_sha256,
            "tinyzkp_test_drill_sha256": req.evidence.stripe_test_drill_sha256,
        },
    }
    client = SimpleNamespace(
        v1=SimpleNamespace(
            invoices=SimpleNamespace(list=lambda params: {"data": [existing]})
        )
    )
    assert billing.validate_evaluation_history(req, client, plan_sha256) is existing
    existing["auto_advance"] = True
    with pytest.raises(ValueError, match="malformed or was edited"):
        billing.validate_evaluation_history(req, client, plan_sha256)
    existing["auto_advance"] = False
    existing["total"] = 1
    with pytest.raises(ValueError, match="malformed or was edited"):
        billing.validate_evaluation_history(req, client, plan_sha256)


def test_billing_ledger_reservation_is_atomic_and_requires_reconciliation(tmp_path):
    ledger = tmp_path / "contract-billing.sqlite"
    req = request()
    plan_sha256 = billing.plan(req, req.validate(billing.load_offers()))[
        "plan_sha256"
    ]
    first = billing.reserve_billing_operation(ledger, req, plan_sha256)
    second = billing.reserve_billing_operation(ledger, req, plan_sha256)
    assert first.newly_reserved is True
    assert first.stripe_object_id is None
    assert second.newly_reserved is False
    assert second.stripe_object_id is None

    billing.bind_billing_operation(ledger, first, "in_original")
    bound = billing.reserve_billing_operation(ledger, req, plan_sha256)
    assert bound.newly_reserved is False
    assert bound.stripe_object_id == "in_original"
    with pytest.raises(ValueError, match="different Stripe object"):
        billing.bind_billing_operation(ledger, bound, "in_duplicate")


def test_concurrent_billing_reservation_has_exactly_one_creator(tmp_path):
    ledger = tmp_path / "contract-billing.sqlite"
    req = request()
    plan_sha256 = billing.plan(req, req.validate(billing.load_offers()))[
        "plan_sha256"
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        reservations = list(
            pool.map(
                lambda _: billing.reserve_billing_operation(
                    ledger,
                    req,
                    plan_sha256,
                ),
                range(2),
            )
        )
    assert sorted(item.newly_reserved for item in reservations) == [False, True]
    assert {item.operation_key for item in reservations} == {
        billing.billing_operation_key(req)
    }


def test_billing_ledger_rejects_same_operation_with_different_plan(tmp_path):
    ledger = tmp_path / "contract-billing.sqlite"
    req = request()
    plan_sha256 = billing.plan(req, req.validate(billing.load_offers()))[
        "plan_sha256"
    ]
    billing.reserve_billing_operation(ledger, req, plan_sha256)
    with pytest.raises(ValueError, match="different contract plan"):
        billing.reserve_billing_operation(ledger, req, "f" * 64)


class ResumableInvoiceStripe:
    def __init__(self, req, plan_sha256, fail_after):
        self.req = req
        self.plan_sha256 = plan_sha256
        self.fail_after = fail_after
        self.failed = False
        self.invoice = None
        self.item = None
        self.invoice_create_count = 0
        self.item_create_count = 0
        self.finalize_count = 0
        self.v1 = SimpleNamespace(
            invoices=SimpleNamespace(
                list=self.list_invoices,
                create=self.create_invoice,
                retrieve=self.retrieve_invoice,
                finalize_invoice=self.finalize_invoice,
            ),
            invoice_items=SimpleNamespace(
                list=self.list_items,
                create=self.create_item,
            ),
        )

    def _maybe_fail(self, point):
        if self.fail_after == point and not self.failed:
            self.failed = True
            raise ConnectionError(f"injected failure after {point}")

    def list_invoices(self, params):
        return {"data": [] if self.invoice is None else [self.invoice]}

    def create_invoice(self, params, options):
        self.invoice_create_count += 1
        if self.invoice is None:
            self.invoice = {
                "id": "in_resumable",
                "customer": self.req.customer_id,
                "status": "draft",
                "currency": "usd",
                "collection_method": "send_invoice",
                "auto_advance": False,
                "total": 0,
                "metadata": dict(params["metadata"]),
            }
        self._maybe_fail("invoice_create")
        return self.invoice

    def retrieve_invoice(self, invoice_id):
        assert self.invoice is not None and invoice_id == self.invoice["id"]
        return self.invoice

    def list_items(self, params):
        return {"data": [] if self.item is None else [self.item]}

    def create_item(self, params, options):
        self.item_create_count += 1
        if self.item is None:
            self.item = {
                "id": "ii_resumable",
                "invoice": params["invoice"],
                "customer": params["customer"],
                "amount": params["amount"],
                "currency": params["currency"],
                "metadata": dict(params["metadata"]),
            }
        self._maybe_fail("item_create")
        return self.item

    def finalize_invoice(self, invoice_id, params, options):
        self.finalize_count += 1
        assert self.invoice is not None and invoice_id == self.invoice["id"]
        self.invoice["status"] = "open"
        self.invoice["total"] = self.item["amount"]
        self.invoice["auto_advance"] = False
        self.invoice["hosted_invoice_url"] = (
            "https://invoice.stripe.com/i/in_resumable"
        )
        self._maybe_fail("finalize")
        return self.invoice


@pytest.mark.parametrize(
    "fail_after",
    ("invoice_create", "item_create", "finalize"),
)
def test_evaluation_invoice_resumes_every_accepted_stripe_phase_without_duplicate(
    tmp_path, fail_after
):
    ledger = tmp_path / "contract-billing.sqlite"
    req = request()
    offer = req.validate(billing.load_offers())
    plan_sha256 = billing.plan(req, offer)["plan_sha256"]
    stripe_client = ResumableInvoiceStripe(req, plan_sha256, fail_after)
    first = billing.reserve_billing_operation(ledger, req, plan_sha256)
    with pytest.raises(ConnectionError, match="injected failure"):
        billing.resume_evaluation_invoice(
            req,
            offer,
            stripe_client,
            plan_sha256,
            ledger_path=ledger,
            reservation=first,
        )

    resumed = billing.reserve_billing_operation(ledger, req, plan_sha256)
    invoice = billing.resume_evaluation_invoice(
        req,
        offer,
        stripe_client,
        plan_sha256,
        ledger_path=ledger,
        reservation=resumed,
    )
    final = billing.reserve_billing_operation(ledger, req, plan_sha256)
    assert invoice["id"] == "in_resumable"
    assert invoice["status"] == "open"
    assert final.phase == "finalized"
    assert final.stripe_object_id == "in_resumable"
    assert stripe_client.invoice_create_count == 1
    assert stripe_client.item_create_count == 1
    assert stripe_client.finalize_count == 1


def bound_partial_invoice(tmp_path):
    ledger = tmp_path / "contract-billing.sqlite"
    req = request()
    offer = req.validate(billing.load_offers())
    plan_sha256 = billing.plan(req, offer)["plan_sha256"]
    stripe_client = ResumableInvoiceStripe(req, plan_sha256, None)
    first = billing.reserve_billing_operation(ledger, req, plan_sha256)
    stripe_client.create_invoice(
        {
            "customer": req.customer_id,
            "metadata": billing.contract_metadata(req, "deposit", plan_sha256),
        },
        {},
    )
    billing.advance_billing_operation(
        ledger,
        first,
        "in_resumable",
        "invoice_created",
    )
    return (
        ledger,
        req,
        offer,
        plan_sha256,
        stripe_client,
        billing.reserve_billing_operation(ledger, req, plan_sha256),
    )


def test_evaluation_resume_retrieves_ledger_bound_invoice_when_list_is_stale(
    tmp_path,
):
    (
        ledger,
        req,
        offer,
        plan_sha256,
        stripe_client,
        reservation,
    ) = bound_partial_invoice(tmp_path)
    stripe_client.v1.invoices.list = lambda _params: (_ for _ in ()).throw(
        AssertionError("a ledger-bound invoice must not rely on Stripe list results")
    )

    invoice = billing.resume_evaluation_invoice(
        req,
        offer,
        stripe_client,
        plan_sha256,
        ledger_path=ledger,
        reservation=reservation,
    )

    assert invoice["id"] == "in_resumable"
    assert invoice["status"] == "open"
    assert stripe_client.invoice_create_count == 1
    assert stripe_client.item_create_count == 1
    assert stripe_client.finalize_count == 1


@pytest.mark.parametrize("wrong_field", ("id", "customer"))
def test_evaluation_resume_rejects_wrong_ledger_bound_invoice_object(
    tmp_path,
    wrong_field,
):
    (
        ledger,
        req,
        offer,
        plan_sha256,
        stripe_client,
        reservation,
    ) = bound_partial_invoice(tmp_path)
    retrieved = dict(stripe_client.invoice)
    retrieved[wrong_field] = (
        "in_wrong" if wrong_field == "id" else "cus_wrong"
    )
    stripe_client.v1.invoices.retrieve = lambda _invoice_id: retrieved

    expected = (
        "wrong ledger-bound invoice"
        if wrong_field == "id"
        else "not exactly bound"
    )
    with pytest.raises(ValueError, match=expected):
        billing.resume_evaluation_invoice(
            req,
            offer,
            stripe_client,
            plan_sha256,
            ledger_path=ledger,
            reservation=reservation,
        )
    assert stripe_client.invoice_create_count == 1
    assert stripe_client.item_create_count == 0
    assert stripe_client.finalize_count == 0


def test_billing_ledger_requires_owner_only_directory(tmp_path):
    unsafe = tmp_path / "shared"
    unsafe.mkdir(mode=0o755)
    unsafe.chmod(0o755)
    req = request()
    plan_sha256 = billing.plan(req, req.validate(billing.load_offers()))[
        "plan_sha256"
    ]
    with pytest.raises(ValueError, match="parent must be owner-only"):
        billing.reserve_billing_operation(
            unsafe / "contract-billing.sqlite",
            req,
            plan_sha256,
        )


def test_annual_history_and_creation_are_plan_and_release_bound(tmp_path, monkeypatch):
    req = annual_request()
    offer = req.validate(billing.load_offers())
    configure_release_authorization(tmp_path, monkeypatch)
    release_binding = billing.validate_release_availability(req)
    assert release_binding is not None
    summary = billing.plan(req, offer, release_binding)
    plan_sha256 = summary["plan_sha256"]
    assert summary["backend_release_sha"] == "a" * 40
    assert summary["backend_source_tree_sha256"] == "b" * 64
    calls = []
    subscriptions = SimpleNamespace(
        list=lambda params: {
            "data": [
                {
                    "status": "active",
                    "metadata": {
                        "tinyzkp_offer_id": req.offer_id,
                        "tinyzkp_agreement_id": req.agreement_id,
                        "tinyzkp_plan_sha256": "f" * 64,
                    },
                }
            ]
        },
        create=lambda params, options: (
            calls.append((params, options)) or {"id": "sub_contract"}
        ),
    )
    prices = SimpleNamespace(
        retrieve=lambda price_id, params: {
            "id": "price_certified",
            "active": True,
            "currency": "usd",
            "unit_amount": 6_000_000,
            "recurring": {"interval": "year", "interval_count": 1},
            "lookup_key": "tinyzkp_certified_annual_contract_v1",
            "metadata": {
                "tinyzkp_offer_id": "tinyzkp_certified",
                "tinyzkp_contract_price": "true",
            },
            "product": {
                "id": "prod_certified",
                "active": True,
                "name": "TinyZKP Certified",
                "metadata": {
                    "tinyzkp_offer_id": "tinyzkp_certified",
                    "tinyzkp_contract_product": "true",
                },
            },
        }
    )
    client = SimpleNamespace(
        v1=SimpleNamespace(subscriptions=subscriptions, prices=prices)
    )
    with pytest.raises(ValueError, match="different plan"):
        billing.validate_annual_history(req, client, plan_sha256, release_binding)

    existing = {
        "id": "sub_existing",
        "customer": req.customer_id,
        "status": "active",
        "collection_method": "send_invoice",
        "items": {
            "data": [{"price": {"id": req.stripe_price_id}, "quantity": 1}]
        },
        "metadata": {
            "tinyzkp_offer_id": req.offer_id,
            "tinyzkp_agreement_id": req.agreement_id,
            "tinyzkp_plan_sha256": plan_sha256,
            "tinyzkp_milestone": "annual",
            "tinyzkp_contract_evidence_sha256": req.evidence.digest(),
            "tinyzkp_scope_sha256": req.evidence.scope_sha256,
            "tinyzkp_negotiated_annual_amount_cents": "6000000",
            "tinyzkp_backend_authorization_sha256": (
                release_binding.authorization_sha256
            ),
            "tinyzkp_backend_authorization_bundle_sha256": (
                release_binding.authorization_bundle_sha256
            ),
            "tinyzkp_backend_release_sha": release_binding.release_sha,
            "tinyzkp_backend_source_tree_sha256": (
                release_binding.source_tree_sha256
            ),
        },
    }
    subscriptions.list = lambda params: {"data": [existing]}
    assert (
        billing.validate_annual_history(
            req,
            client,
            plan_sha256,
            release_binding,
        )
        is existing
    )
    existing["items"]["data"][0]["quantity"] = 2
    with pytest.raises(ValueError, match="malformed or was edited"):
        billing.validate_annual_history(req, client, plan_sha256, release_binding)
    existing["items"]["data"][0]["quantity"] = 1
    existing["status"] = "past_due"
    with pytest.raises(ValueError, match="malformed or was edited"):
        billing.validate_annual_history(req, client, plan_sha256, release_binding)
    existing["status"] = "active"
    existing["metadata"]["tinyzkp_backend_release_sha"] = "0" * 40
    with pytest.raises(ValueError, match="malformed or was edited"):
        billing.validate_annual_history(req, client, plan_sha256, release_binding)
    existing["metadata"]["tinyzkp_backend_release_sha"] = (
        release_binding.release_sha
    )

    subscriptions.list = lambda params: {"data": []}
    billing.validate_annual_history(req, client, plan_sha256, release_binding)
    created = billing.create_annual_contract(
        req,
        offer,
        client,
        plan_sha256,
        release_binding,
    )
    assert created["id"] == "sub_contract"
    assert calls[0][0]["metadata"]["tinyzkp_plan_sha256"] == plan_sha256
    assert calls[0][0]["metadata"]["tinyzkp_backend_release_sha"] == "a" * 40
    assert (
        calls[0][0]["metadata"]["tinyzkp_backend_authorization_sha256"]
        == release_binding.authorization_sha256
    )
    assert plan_sha256[:24] in calls[0][1]["idempotency_key"]


def test_annual_plan_and_write_fail_if_release_binding_changes(tmp_path, monkeypatch):
    req = annual_request()
    offer = req.validate(billing.load_offers())
    authorization, _bundle = configure_release_authorization(tmp_path, monkeypatch)
    first = billing.validate_release_availability(req)
    assert first is not None
    first_plan = billing.plan(req, offer, first)

    authorization.write_text(json.dumps(release_authorization(release_sha="1" * 40)))
    authorization.chmod(0o600)
    monkeypatch.setenv(
        billing.RELEASE_AUTHORIZATION_SHA_ENV,
        hashlib.sha256(authorization.read_bytes()).hexdigest(),
    )
    second = billing.validate_release_availability(req)
    assert second is not None
    second_plan = billing.plan(req, offer, second)
    assert second_plan["plan_sha256"] != first_plan["plan_sha256"]

    subscriptions = SimpleNamespace(
        create=lambda params, options: (_ for _ in ()).throw(
            AssertionError("Stripe write must not occur after release swap")
        )
    )
    prices = SimpleNamespace(
        retrieve=lambda price_id, params: {
            "id": "price_certified",
            "active": True,
            "currency": "usd",
            "unit_amount": 6_000_000,
            "recurring": {"interval": "year", "interval_count": 1},
            "lookup_key": "tinyzkp_certified_annual_contract_v1",
            "metadata": {
                "tinyzkp_offer_id": "tinyzkp_certified",
                "tinyzkp_contract_price": "true",
            },
            "product": {
                "id": "prod_certified",
                "active": True,
                "name": "TinyZKP Certified",
                "metadata": {
                    "tinyzkp_offer_id": "tinyzkp_certified",
                    "tinyzkp_contract_product": "true",
                },
            },
        }
    )
    client = SimpleNamespace(
        v1=SimpleNamespace(subscriptions=subscriptions, prices=prices)
    )
    with pytest.raises(ValueError, match="changed after annual contract preview"):
        billing.create_annual_contract(
            req,
            offer,
            client,
            first_plan["plan_sha256"],
            first,
        )


def test_contract_customer_must_be_explicitly_bound():
    req = request()
    customer = {
        "id": "cus_test",
        "email": "billing@customer.example",
        "name": "Example Customer LLC",
        "address": {
            "line1": "1 Main Street",
            "city": "San Francisco",
            "postal_code": "94105",
            "country": "US",
        },
        "metadata": {
            "tinyzkp_contract_customer": "true",
            "tinyzkp_agreement_id": "eval-001",
            "tinyzkp_offer_id": "founding_evaluation",
        },
    }
    billing.validate_contract_customer(customer, req)
    customer["metadata"]["tinyzkp_agreement_id"] = "other"
    with pytest.raises(ValueError, match="contract-tagged"):
        billing.validate_contract_customer(customer, req)

    customer["metadata"]["tinyzkp_agreement_id"] = "eval-001"
    customer["address"]["postal_code"] = ""
    with pytest.raises(ValueError, match="contract-tagged"):
        billing.validate_contract_customer(customer, req)


def test_apply_requires_exact_read_only_plan_hash_before_stripe(tmp_path, monkeypatch):
    agreement = tmp_path / "signed-agreement.pdf"
    scope = tmp_path / "acceptance.json"
    agreement.write_bytes(b"signed agreement")
    scope.write_text(json.dumps(acceptance_matrix()))
    agreement.chmod(0o600)
    scope.chmod(0o600)
    bound = evidence(
        agreement_sha256=hashlib.sha256(agreement.read_bytes()).hexdigest(),
        scope_sha256=hashlib.sha256(scope.read_bytes()).hexdigest(),
    )
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps({**billing.asdict(bound)}))
    contract.chmod(0o600)
    monkeypatch.setattr(
        billing,
        "parse_args",
        lambda: SimpleNamespace(
            action="evaluation-deposit",
            offer_id="founding_evaluation",
            customer_id="cus_test",
            agreement_id="eval-001",
            days_until_due=15,
            stripe_price_id=None,
            stripe_product_id=None,
            contract_evidence=contract,
            agreement_document=agreement,
            scope_document=scope,
            delivery_acceptance_document=None,
            expected_plan_sha256="0" * 64,
            expected_account_id="acct_expected",
            expected_display_name="TinyZKP",
            apply=True,
        ),
    )
    monkeypatch.setattr(
        billing,
        "create_stripe_client",
        lambda key: (_ for _ in ()).throw(AssertionError("Stripe must not be reached")),
    )
    monkeypatch.setattr(billing, "verify_contract_documents", lambda *args, **kwargs: None)
    with pytest.raises(SystemExit, match="exact preview plan SHA-256"):
        billing.main()


def test_apply_reuses_exact_existing_invoice_without_second_stripe_create(
    tmp_path, monkeypatch, capsys
):
    agreement = tmp_path / "signed-agreement.pdf"
    scope = tmp_path / "acceptance.json"
    agreement.write_bytes(b"signed agreement")
    scope.write_text(json.dumps(acceptance_matrix()))
    agreement.chmod(0o600)
    scope.chmod(0o600)
    bound = evidence(
        agreement_sha256=hashlib.sha256(agreement.read_bytes()).hexdigest(),
        scope_sha256=hashlib.sha256(scope.read_bytes()).hexdigest(),
    )
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps(billing.asdict(bound)))
    contract.chmod(0o600)
    req = request(evidence=bound)
    plan_sha256 = billing.plan(req, req.validate(billing.load_offers()))[
        "plan_sha256"
    ]
    existing = {
        "id": "in_existing",
        "customer": "cus_test",
        "status": "open",
        "currency": "usd",
        "collection_method": "send_invoice",
        "auto_advance": False,
        "hosted_invoice_url": "https://invoice.stripe.com/i/in_existing",
        "total": 1_250_000,
        "metadata": billing.contract_metadata(req, "deposit", plan_sha256),
    }
    account = {
        "id": "acct_expected",
        "settings": {"dashboard": {"display_name": "TinyZKP"}},
        "business_profile": {
            "name": "TinyZKP",
            "support_email": "billing@tinyzkp.com",
            "support_url": "https://tinyzkp.com/contact",
        },
    }
    customer = {
        "id": "cus_test",
        "email": "billing@customer.example",
        "name": "Customer LLC",
        "address": {
            "line1": "1 Main Street",
            "city": "San Francisco",
            "postal_code": "94105",
            "country": "US",
        },
        "metadata": {
            "tinyzkp_contract_customer": "true",
            "tinyzkp_agreement_id": "eval-001",
            "tinyzkp_offer_id": "founding_evaluation",
        },
    }
    invoices = SimpleNamespace(
        list=lambda params: {"data": [existing]},
        retrieve=lambda invoice_id: existing,
        create=lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("same-plan apply must not create a second invoice")
        ),
    )
    client = SimpleNamespace(
        v1=SimpleNamespace(
            accounts=SimpleNamespace(retrieve_current=lambda: account),
            customers=SimpleNamespace(retrieve=lambda customer_id: customer),
            invoices=invoices,
        )
    )
    monkeypatch.setattr(
        billing,
        "parse_args",
        lambda: SimpleNamespace(
            action="evaluation-deposit",
            offer_id="founding_evaluation",
            customer_id="cus_test",
            agreement_id="eval-001",
            days_until_due=15,
            stripe_price_id=None,
            stripe_product_id=None,
            contract_evidence=contract,
            agreement_document=agreement,
            scope_document=scope,
            delivery_acceptance_document=None,
            expected_plan_sha256=plan_sha256,
            expected_account_id="acct_expected",
            expected_display_name="TinyZKP",
            apply=True,
        ),
    )
    monkeypatch.setattr(billing, "create_stripe_client", lambda key: client)
    monkeypatch.setattr(billing, "verify_contract_documents", lambda *args, **kwargs: None)
    monkeypatch.setenv("TINYZKP_ALLOW_CONTRACT_BILLING_WRITE", "1")
    monkeypatch.setenv("TINYZKP_CONTRACT_SENDER_IDENTITY_CONFIRMED", "1")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_placeholder")
    monkeypatch.setenv(
        "TINYZKP_CONTRACT_BILLING_LEDGER_PATH",
        str(tmp_path / "contract-billing.sqlite"),
    )
    billing.main()
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "existing"
    assert result["stripe_object_id"] == "in_existing"
    assert result["hosted_invoice_url"] == (
        "https://invoice.stripe.com/i/in_existing"
    )

    billing.main()
    retry = json.loads(capsys.readouterr().out)
    assert retry["mode"] == "existing"
    assert retry["stripe_object_id"] == "in_existing"

    existing["metadata"]["tinyzkp_offer_id"] = "edited"
    with pytest.raises(ValueError, match="malformed or was edited"):
        billing.main()
