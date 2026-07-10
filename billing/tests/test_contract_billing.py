import pytest
import hashlib
import json
from types import SimpleNamespace

import contract_billing as billing


def evidence(
    action="evaluation-deposit",
    offer_id="founding_evaluation",
    customer_id="cus_test",
    agreement_id="eval-001",
    **overrides,
):
    values = {
        "schema_version": 1,
        "agreement_id": agreement_id,
        "offer_id": offer_id,
        "stripe_customer_id": customer_id,
        "agreement_sha256": "a" * 64,
        "scope_sha256": "b" * 64,
        "signed_at": "2026-07-09T12:00:00Z",
        "delivery_acceptance_sha256": "c" * 64
        if action == "evaluation-delivery"
        else None,
        "delivery_accepted_at": "2026-07-10T12:00:00Z"
        if action == "evaluation-delivery"
        else None,
    }
    values.update(overrides)
    return billing.ContractEvidenceV1(**values)


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
    }
    values.update(overrides)
    return billing.BillingRequest(**values)


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
        "schema_version": 1,
        "agreement_id": "eval-001",
        "offer_id": "founding_evaluation",
        "stripe_customer_id": "cus_test",
        "agreement_sha256": "a" * 64,
        "scope_sha256": "b" * 64,
        "signed_at": "2026-07-09T12:00:00Z",
        "delivery_acceptance_sha256": None,
        "delivery_accepted_at": None,
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


def test_contract_evidence_template_has_exact_schema():
    template = json.loads(
        (billing.ROOT / "commercial" / "contract-evidence.template.json").read_text()
    )
    assert set(template) == billing.CONTRACT_EVIDENCE_KEYS


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


def test_contract_documents_are_owner_only_and_hash_bound(tmp_path):
    agreement = tmp_path / "signed-agreement.pdf"
    scope = tmp_path / "acceptance.json"
    agreement.write_bytes(b"signed agreement")
    scope.write_bytes(b"frozen scope")
    agreement.chmod(0o600)
    scope.chmod(0o600)
    bound = evidence(
        agreement_sha256=hashlib.sha256(agreement.read_bytes()).hexdigest(),
        scope_sha256=hashlib.sha256(scope.read_bytes()).hexdigest(),
    )
    billing.verify_contract_documents(
        bound,
        "evaluation-deposit",
        agreement_document=agreement,
        scope_document=scope,
        delivery_acceptance_document=None,
    )
    scope.write_bytes(b"changed scope")
    with pytest.raises(ValueError, match="scope document does not match"):
        billing.verify_contract_documents(
            bound,
            "evaluation-deposit",
            agreement_document=agreement,
            scope_document=scope,
            delivery_acceptance_document=None,
        )
    scope.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        billing.private_document_sha256(scope, "scope document")


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
    )
    offer = req.validate(billing.load_offers())
    billing.validate_annual_price(
        {
            "active": True,
            "currency": "usd",
            "unit_amount": 6_000_000,
            "recurring": {"interval": "year", "interval_count": 1},
        },
        offer,
    )
    with pytest.raises(ValueError, match="amount/currency"):
        billing.validate_annual_price(
            {
                "active": True,
                "currency": "usd",
                "unit_amount": 1,
                "recurring": {"interval": "year", "interval_count": 1},
            },
            offer,
        )


def test_annual_contract_is_blocked_while_backend_release_is_blocked(tmp_path, monkeypatch):
    annual = request(
        action="annual-contract",
        offer_id="tinyzkp_certified",
        stripe_price_id="price_certified",
    )
    with pytest.raises(ValueError, match="blocked until every backend-v1 release gate"):
        billing.validate_release_availability(annual)

    ready = tmp_path / "gates.json"
    ready.write_text(
        json.dumps(
            {
                "status": "ready",
                "gates": {"review": {"passed": True, "evidence": "report.pdf"}},
            }
        )
    )
    monkeypatch.setattr(billing, "RELEASE_GATES_PATH", ready)
    billing.validate_release_availability(annual)


def test_evaluation_milestone_isolated_to_its_own_invoice(monkeypatch):
    calls = []
    invoices = SimpleNamespace(
        create=lambda params, options: calls.append(("invoice", params, options))
        or {"id": "in_eval"},
        finalize_invoice=lambda invoice_id, params, options: calls.append(
            ("finalize", invoice_id, params, options)
        )
        or {"id": invoice_id, "status": "open"},
    )
    invoice_items = SimpleNamespace(
        create=lambda params, options: calls.append(("item", params, options))
        or {"id": "ii_eval"}
    )
    client = SimpleNamespace(v1=SimpleNamespace(invoices=invoices, invoice_items=invoice_items))
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
    assert calls[2][2]["auto_advance"] is True
    assert calls[2][3]["idempotency_key"].endswith("-finalize")


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
                "status": "paid",
                "metadata": {
                    "tinyzkp_offer_id": "founding_evaluation",
                    "tinyzkp_agreement_id": agreement,
                    "tinyzkp_milestone": "deposit",
                    "tinyzkp_plan_sha256": plans[agreement],
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
        third_plan = billing.plan(
            third, third.validate(billing.load_offers())
        )["plan_sha256"]
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


def test_annual_history_and_creation_are_plan_bound():
    req = request(
        action="annual-contract",
        offer_id="tinyzkp_certified",
        stripe_price_id="price_certified",
    )
    offer = req.validate(billing.load_offers())
    plan_sha256 = billing.plan(req, offer)["plan_sha256"]
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
        create=lambda params, options: calls.append((params, options))
        or {"id": "sub_contract"},
    )
    prices = SimpleNamespace(
        retrieve=lambda price_id: {
            "active": True,
            "currency": "usd",
            "unit_amount": 6_000_000,
            "recurring": {"interval": "year", "interval_count": 1},
        }
    )
    client = SimpleNamespace(v1=SimpleNamespace(subscriptions=subscriptions, prices=prices))
    with pytest.raises(ValueError, match="different plan"):
        billing.validate_annual_history(req, client, plan_sha256)

    subscriptions.list = lambda params: {"data": []}
    billing.validate_annual_history(req, client, plan_sha256)
    created = billing.create_annual_contract(req, offer, client, plan_sha256)
    assert created["id"] == "sub_contract"
    assert calls[0][0]["metadata"]["tinyzkp_plan_sha256"] == plan_sha256
    assert plan_sha256[:24] in calls[0][1]["idempotency_key"]


def test_contract_customer_must_be_explicitly_bound():
    req = request()
    customer = {
        "id": "cus_test",
        "email": "billing@customer.example",
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


def test_apply_requires_exact_read_only_plan_hash_before_stripe(tmp_path, monkeypatch):
    agreement = tmp_path / "signed-agreement.pdf"
    scope = tmp_path / "acceptance.json"
    agreement.write_bytes(b"signed agreement")
    scope.write_bytes(b"frozen scope")
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
    with pytest.raises(SystemExit, match="exact preview plan SHA-256"):
        billing.main()
