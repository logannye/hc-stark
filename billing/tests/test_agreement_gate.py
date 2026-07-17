import hashlib
import json

import pytest

import agreement_gate as gate


COMPLETE = """
TinyZKP evaluates exactly one pinned Plonky3 workload for two weeks with an
eight person-days cap for a $15,000 fixed fee. Extra work needs a written change order. Fees are a
50% deposit and remaining 50% only after written delivery acceptance. This is
not hosted proving, not a security certification, and not an SLA. TinyZKP does
not guarantee performance. Supply a non-sensitive deterministic input
generator and must not transfer witnesses, credentials, private keys, private
source code, customer data, regulated data, or production secrets. The MIT-licensed core remains open and a
customer-specific adapter has separately agreed ownership. Retention and
deletion follow the schedule. Provider signature. Customer signature.
"""


def write_private(path, raw):
    path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
    path.chmod(0o600)
    return path


@pytest.fixture(autouse=True)
def validated_commercial_evidence(monkeypatch):
    monkeypatch.setattr(
        gate.evidence_common,
        "compatibility_identity",
        lambda path: {"profile": "test"},
    )
    monkeypatch.setattr(
        gate.evaluation_qualification,
        "validate_evidence",
        lambda payload, compatibility: payload,
    )
    monkeypatch.setattr(
        gate.partner_preflight,
        "validate_evidence",
        lambda payload, compatibility: payload,
        raising=False,
    )


def fixture_files(tmp_path):
    approved = write_private(tmp_path / "approved.md", COMPLETE)
    approval = write_private(tmp_path / "approval.pdf", b"counsel approval")
    profile = {
        "schema_version": gate.PROFILE_SCHEMA,
        "status": "approved",
        "form_id": "tinyzkp-evaluation-msa-sow",
        "form_version": "1.0.0",
        "approved_template_sha256": hashlib.sha256(approved.read_bytes()).hexdigest(),
        "counsel_approval_sha256": hashlib.sha256(approval.read_bytes()).hexdigest(),
        "approved_by": "Outside Counsel",
        "approved_at": "2020-01-01T12:00:00Z",
        "approval_scope": "evaluation-msa-sow-for-execution",
    }
    profile_path = write_private(tmp_path / "profile.json", json.dumps(profile))
    qualification_payload = {
        "application_id": "eval_001",
        "reviewed_at": "2019-12-31T12:00:00Z",
    }
    qualification_raw = gate.evidence_common.canonical_bytes(qualification_payload)
    qualification_path = write_private(
        tmp_path / "qualification.json", qualification_raw
    )
    preflight_payload = {
        "application_id": "eval_001",
        "checked_at": "2019-12-31T13:00:00Z",
        "bound_inputs": {
            "qualification_evidence_sha256": hashlib.sha256(
                qualification_raw
            ).hexdigest()
        },
    }
    preflight_path = write_private(
        tmp_path / "partner.json",
        gate.evidence_common.canonical_bytes(preflight_payload),
    )
    return {
        "profile_path": profile_path,
        "approved_template_path": approved,
        "counsel_approval_path": approval,
        "agreement_source_path": write_private(tmp_path / "completed.md", COMPLETE),
        "signed_agreement_path": write_private(tmp_path / "signed.pdf", b"signed"),
        "scope_path": write_private(tmp_path / "scope.json", b"scope"),
        "qualification_path": qualification_path,
        "partner_preflight_path": preflight_path,
        "agreement_id": "eval-001",
        "offer_id": "founding_evaluation",
        "execution_reviewed_by": "Outside Counsel",
        "execution_reviewed_at": "2020-01-01T12:01:00Z",
        "material_deviations_reviewed": True,
    }


def test_build_gate_binds_every_document(tmp_path):
    payload = gate.build_gate(**fixture_files(tmp_path))
    assert gate.validate_gate(payload) == payload
    assert payload["approved_for_execution"] is True
    assert payload["required_terms"] == {key: True for key in gate.REQUIRED_TERMS}
    assert payload["signed_agreement_sha256"] == hashlib.sha256(b"signed").hexdigest()


@pytest.mark.parametrize(
    "marker",
    ("[COUNSEL: COMPLETE]", "REPLACE_ME", "TODO", "DO NOT SIGN", "DRAFT FOR COUNSEL"),
)
def test_source_rejects_unresolved_markers(marker):
    with pytest.raises(ValueError, match="unresolved marker"):
        gate.validate_agreement_source(
            (COMPLETE + marker).encode(),
            "founding_evaluation",
        )


def test_current_counsel_draft_is_deliberately_not_approvable():
    draft = (
        gate.Path(gate.__file__).resolve().parents[1]
        / "commercial"
        / "evaluation-sow.counsel-draft.md"
    )
    with pytest.raises(ValueError, match="unresolved marker"):
        gate.validate_agreement_source(draft.read_bytes(), "founding_evaluation")


def test_offer_specific_terms_come_from_pricing_source():
    with pytest.raises(ValueError, match="offer_duration"):
        gate.validate_agreement_source(
            COMPLETE.replace("two weeks", "three weeks").encode(),
            "founding_evaluation",
        )
    standard = (
        COMPLETE.replace("two weeks", "three weeks")
        .replace("eight person-days", "fifteen person-days")
        .replace("$15,000", "$40,000")
    )
    assert all(
        gate.validate_agreement_source(
            standard.encode(),
            "standard_evaluation",
        ).values()
    )


def test_build_rejects_template_or_approval_hash_mismatch(tmp_path):
    values = fixture_files(tmp_path)
    values["approved_template_path"].write_text("changed")
    values["approved_template_path"].chmod(0o600)
    with pytest.raises(ValueError, match="approved template"):
        gate.build_gate(**values)


def test_gate_rejects_false_attestations(tmp_path):
    payload = gate.build_gate(**fixture_files(tmp_path))
    payload["material_deviations_reviewed"] = False
    with pytest.raises(ValueError, match="material_deviations_reviewed"):
        gate.validate_gate(payload)


def test_owner_only_input_and_output(tmp_path):
    values = fixture_files(tmp_path)
    values["scope_path"].chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        gate.build_gate(**values)
    output_dir = tmp_path / "private"
    output_dir.mkdir(mode=0o700)
    output = output_dir / "gate.json"
    payload = {"status": "test"}
    gate.atomic_write(output, payload)
    assert output.stat().st_mode & 0o777 == 0o600


def test_duplicate_json_keys_fail_closed():
    with pytest.raises(ValueError, match="duplicate JSON key"):
        gate.decode_json(b'{"status":"approved","status":"draft"}', "profile")
