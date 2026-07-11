import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

import pytest


MODULE_PATH = Path(__file__).with_name("build_external_records.py")
SPEC = importlib.util.spec_from_file_location("build_external_records", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_reproduction_record_binds_every_expected_artifact(tmp_path):
    artifacts = {}
    for index, role in enumerate(MODULE.INDEPENDENT_RESOURCE_ROLES):
        path = tmp_path / f"{index}.json"
        path.write_text(json.dumps({"role": role}), encoding="utf-8")
        artifacts[role] = path
    record = MODULE.reproduction_record(
        release_sha="abc",
        reproducer="reviewer",
        organization="independent lab",
        completed_at="2026-01-01T00:00:00Z",
        artifacts=artifacts,
        signer_id="lab-signer",
    )
    assert set(record["artifact_sha256"]) == set(MODULE.INDEPENDENT_RESOURCE_ROLES)
    for role, path in artifacts.items():
        assert (
            record["artifact_sha256"][role]
            == hashlib.sha256(path.read_bytes()).hexdigest()
        )


def test_review_ledger_hashes_report_and_validates_findings(tmp_path):
    report = tmp_path / "review.pdf"
    report.write_bytes(b"review bytes")
    bundle = tmp_path / "review.zip"
    bundle.write_bytes(b"deterministic review bundle")
    findings = MODULE.validate_findings(
        [
            {
                "id": "LOW-1",
                "severity": "low",
                "status": "open",
                "reviewer_verified": False,
            }
        ]
    )
    ledger = MODULE.review_ledger(
        release_sha="abc",
        scope="implementation",
        reviewer="reviewer",
        completed_at="2026-01-01T00:00:00Z",
        bundle=bundle,
        review_manifest_sha256="a" * 64,
        source_tree_sha256="b" * 64,
        report=report,
        findings=findings,
        security_assessment=None,
        signer_id="review-signer",
    )
    assert (
        ledger["review_report_sha256"]
        == hashlib.sha256(report.read_bytes()).hexdigest()
    )
    assert (
        ledger["review_bundle_sha256"]
        == hashlib.sha256(bundle.read_bytes()).hexdigest()
    )
    assert ledger["review_manifest_sha256"] == "a" * 64
    assert ledger["source_tree_sha256"] == "b" * 64
    assert ledger["security_assessment"] is None


def test_review_record_builder_rejects_skew_and_binds_exact_bundle(
    tmp_path, monkeypatch
):
    release_sha = init_source_repo(tmp_path)
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    source_tree_sha256 = MODULE.source_tree_identity.source_tree_sha256(
        tmp_path, release_sha
    )
    manifest_bytes = json.dumps(
        {
            "schema_version": 2,
            "release_sha": release_sha,
            "source_tree_sha256": source_tree_sha256,
            "profile": MODULE.PROFILE,
            "plonky3_version": "0.6.1",
            "files": [],
        },
        sort_keys=True,
    ).encode()
    bundle = tmp_path / "review.zip"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("review-manifest.json", manifest_bytes)

    def verify_fixture(path, *, root, release_sha):
        with zipfile.ZipFile(path) as archive:
            payload = archive.read("review-manifest.json")
        return json.loads(payload), payload

    monkeypatch.setattr(MODULE.build_review_bundle, "verify_bundle", verify_fixture)
    report = tmp_path / "review.pdf"
    report.write_bytes(b"review")
    completed = tmp_path / "review-input.json"
    completed.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "record_type": "implementation_review",
                "completion_status": "completed",
                "release_sha": release_sha,
                "reviewer": "independent reviewer",
                "reviewer_independent": True,
                "completed_at": "2026-01-01T00:00:00Z",
                "signer_id": "review-signer",
                "artifact_paths": {
                    "review_bundle": str(bundle),
                    "review_report": str(report),
                },
                "findings": [],
                "security_assessment": None,
            }
        ),
        encoding="utf-8",
    )
    completed.chmod(0o600)
    output = tmp_path / "ledger.json"
    MODULE.capture_external_input(completed, output)
    ledger = json.loads(output.read_text(encoding="utf-8"))
    assert (
        ledger["review_bundle_sha256"]
        == hashlib.sha256(bundle.read_bytes()).hexdigest()
    )
    assert (
        ledger["review_manifest_sha256"] == hashlib.sha256(manifest_bytes).hexdigest()
    )
    assert ledger["source_tree_sha256"] == source_tree_sha256
    assert stat.S_IMODE(output.stat().st_mode) == 0o600

    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr(
            "review-manifest.json",
            manifest_bytes.replace(source_tree_sha256.encode(), b"f" * 64),
        )
    with pytest.raises(ValueError, match="incomplete or release-skewed"):
        MODULE.capture_external_input(completed, output)


def test_specialist_security_assessment_binds_exact_frozen_fri_profile():
    assessment = {
        "schema_version": 1,
        "profile_id": MODULE.PROFILE,
        "plonky3_version": "0.6.1",
        "fri_constructor": "FriParameters::new_benchmark",
        "log_blowup": 1,
        "log_final_poly_len": 0,
        "max_log_arity": 1,
        "num_queries": 100,
        "commit_proof_of_work_bits": 0,
        "query_proof_of_work_bits": 16,
        "conjectured_soundness_reviewed": True,
        "proven_soundness_reviewed": True,
        "duplicate_query_probability_reviewed": True,
        "challenger_capacity_reviewed": True,
        "minimum_security_bits": 96,
        "production_use_approved": True,
        "analysis_summary": "Independent assessment of the frozen profile.",
        "limitations": ["Security bound depends on the documented FRI assumptions."],
    }
    assert (
        MODULE.release_gate.validate_profile_security_assessment(
            assessment, require_production_approval=True
        )
        == []
    )
    assessment["query_proof_of_work_bits"] = 15
    assert MODULE.release_gate.validate_profile_security_assessment(
        assessment, require_production_approval=True
    ) == ["Plonky3 specialist profile-security assessment is missing or incomplete"]
    assessment["query_proof_of_work_bits"] = 16
    assessment["production_use_approved"] = False
    assert MODULE.release_gate.validate_profile_security_assessment(
        assessment, require_production_approval=True
    ) == ["Plonky3 specialist did not approve the frozen profile for production use"]


def test_partner_acceptance_hashes_only_artifacts_and_atomic_output_is_private(
    tmp_path,
):
    adapter = tmp_path / "adapter.json"
    resource = tmp_path / "resource.json"
    adapter.write_text("{}", encoding="utf-8")
    resource.write_text("{}", encoding="utf-8")
    record = MODULE.partner_acceptance(
        release_sha="abc",
        acceptance_id="acceptance-1",
        partner_id="opaque-partner",
        accepted_at="2026-01-01T00:00:00Z",
        adapter_result=adapter,
        resource_report=resource,
        signer_id="partner-signer",
    )
    assert record["witness_data_committed"] is False
    assert (
        record["adapter_result_sha256"]
        == hashlib.sha256(adapter.read_bytes()).hexdigest()
    )
    output = tmp_path / "record.json"
    MODULE.write_json_atomic(output, record)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


@pytest.mark.parametrize("kind", sorted(MODULE.TEMPLATE_FILES))
def test_tracked_external_templates_are_structurally_valid_but_fail_closed(kind):
    value = MODULE.template_input(kind)
    assert value["record_type"] == kind
    assert value["completion_status"] == "incomplete"
    assert MODULE.contains_placeholder(value)
    with pytest.raises(ValueError, match="remains incomplete"):
        MODULE.validate_external_input(value, require_complete=True)

    value["completion_status"] = "completed"
    with pytest.raises(ValueError, match="unresolved placeholder"):
        MODULE.validate_external_input(value, require_complete=True)


def test_raw_cli_flags_cannot_manufacture_external_claims():
    with pytest.raises(SystemExit):
        MODULE.parse_args(
            [
                "partner-acceptance",
                "--release-sha",
                "a" * 40,
                "--partner-id",
                "partner",
            ]
        )
    parsed = MODULE.parse_args(
        [
            "partner-acceptance",
            "--input",
            "completed.json",
            "--output",
            "claim.json",
        ]
    )
    assert parsed.expected_kind == "design_partner_acceptance"


def test_completed_external_input_must_be_owner_only(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    exposed = tmp_path / "completed.json"
    exposed.write_text("{}", encoding="utf-8")
    exposed.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        MODULE.load_external_input(exposed, require_complete=True)


def test_held_read_rejects_path_replacement_symlink_and_hardlink(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    source = tmp_path / "source.json"
    source.write_bytes(b'{"old":true}')
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(b'{"new":true}')
    real_read = MODULE.os.read
    replaced = False

    def replace_during_read(descriptor, size):
        nonlocal replaced
        if not replaced:
            replaced = True
            MODULE.os.replace(replacement, source)
        return real_read(descriptor, size)

    monkeypatch.setattr(MODULE.os, "read", replace_during_read)
    with pytest.raises(ValueError, match="changed during its held read"):
        MODULE.stable_file_bytes(source, require_private=False)
    assert replaced

    monkeypatch.setattr(MODULE.os, "read", real_read)
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(source)
    with pytest.raises(ValueError, match="symlink"):
        MODULE.stable_file_bytes(symlink, require_private=False)

    hardlink = tmp_path / "hardlink.json"
    MODULE.os.link(source, hardlink)
    with pytest.raises(ValueError, match="unsafe file identity"):
        MODULE.stable_file_bytes(source, require_private=False)


def test_template_cli_copies_owner_only_input_that_cannot_validate(
    tmp_path, monkeypatch
):
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    source_template = (
        MODULE.TEMPLATE_DIR / MODULE.TEMPLATE_FILES["implementation_review"]
    )
    (template_dir / source_template.name).write_bytes(source_template.read_bytes())
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "TEMPLATE_DIR", template_dir)
    output = tmp_path / "implementation-review.json"
    assert (
        MODULE.main(
            [
                "template",
                "--kind",
                "implementation_review",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert MODULE.main(["validate-input", "--input", str(output)]) == 2


def init_source_repo(path: Path) -> str:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    source = path / "source"
    source.write_text("reviewed source\n", encoding="utf-8")
    subprocess.run(["git", "add", "source"], cwd=path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=TinyZKP Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=path,
        check=True,
    )
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=path, text=True
    ).strip()


def test_completed_review_capture_is_canonical_private_and_still_requires_signature(
    tmp_path, monkeypatch
):
    release_sha = init_source_repo(tmp_path)
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    source_tree_sha256 = MODULE.source_tree_identity.source_tree_sha256(
        tmp_path, release_sha
    )
    manifest_bytes = json.dumps(
        {
            "schema_version": 2,
            "release_sha": release_sha,
            "source_tree_sha256": source_tree_sha256,
            "profile": MODULE.PROFILE,
            "plonky3_version": "0.6.1",
            "files": [],
        },
        sort_keys=True,
    ).encode()
    bundle = tmp_path / "review.zip"
    bundle.write_bytes(b"review bundle")
    report = tmp_path / "review.pdf"
    report.write_bytes(b"independent review")

    def verify_fixture(path, *, root, release_sha):
        assert path.read_bytes() == bundle.read_bytes()
        return json.loads(manifest_bytes), manifest_bytes

    monkeypatch.setattr(MODULE.build_review_bundle, "verify_bundle", verify_fixture)
    completed = tmp_path / "completed-review.json"
    completed.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "record_type": "implementation_review",
                "completion_status": "completed",
                "release_sha": release_sha,
                "reviewer": "Independent Reviewer",
                "reviewer_independent": True,
                "completed_at": "2026-07-10T12:00:00Z",
                "signer_id": "reviewer-signer",
                "artifact_paths": {
                    "review_bundle": str(bundle),
                    "review_report": str(report),
                },
                "findings": [],
                "security_assessment": None,
            }
        ),
        encoding="utf-8",
    )
    completed.chmod(0o600)
    claim = tmp_path / "review-ledger.json"
    record = MODULE.capture_external_input(
        completed, claim, expected_kind="implementation_review"
    )
    assert json.loads(claim.read_text(encoding="utf-8")) == record
    assert (
        record["review_bundle_sha256"]
        == hashlib.sha256(bundle.read_bytes()).hexdigest()
    )
    assert stat.S_IMODE(claim.stat().st_mode) == 0o600

    completed_value = json.loads(completed.read_text(encoding="utf-8"))
    completed_value["reviewer_independent"] = False
    completed.write_text(json.dumps(completed_value), encoding="utf-8")
    with pytest.raises(ValueError, match="did not attest independence"):
        MODULE.capture_external_input(completed, tmp_path / "not-independent.json")
    completed_value["reviewer_independent"] = True
    completed.write_text(json.dumps(completed_value), encoding="utf-8")

    signature = tmp_path / "review.sigstore.json"
    signature.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="signed external evidence failed validation"):
        MODULE.validate_signed_external_input(completed, claim, signature)

    claim.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match the completed external input"):
        MODULE.validate_signed_external_input(completed, claim, signature)


def test_partner_capture_validates_machine_artifacts_before_hashing(
    tmp_path, monkeypatch
):
    release_sha = init_source_repo(tmp_path)
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(
        MODULE.release_gate, "valid_resource_estimate", lambda value: True
    )
    monkeypatch.setattr(
        MODULE.release_gate, "valid_benchmark_report_envelope", lambda value: True
    )
    adapter = tmp_path / "adapter.json"
    adapter_value = {
        "schema_version": 1,
        "mode": "compare",
        "profile": MODULE.PROFILE,
        "plonky3_version": "0.6.1",
        "dependency_lock_sha256": (
            "bbd614a78a9ee8c531d7e6758708aa6d4929b60f99eac46dda941f6599c6a5e7"
        ),
        "release_sha": release_sha,
        "official_verification": True,
        "bounded_equals_conventional": True,
        "witness_data_included": False,
        "preflight_estimate": {},
        "proof_size_bytes": 1,
        "proof_blake3_hex": "a" * 64,
    }
    adapter.write_text(json.dumps(adapter_value), encoding="utf-8")
    report = tmp_path / "resource.json"
    report.write_text(
        json.dumps({"mode": "bounded", "release_sha": release_sha}),
        encoding="utf-8",
    )
    completed = tmp_path / "partner-input.json"
    completed.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "record_type": "design_partner_acceptance",
                "completion_status": "completed",
                "release_sha": release_sha,
                "acceptance_id": "acceptance-0123456789abcdef",
                "partner_id": "partner-fedcba9876543210",
                "accepted_at": "2026-07-10T12:00:00Z",
                "signer_id": "partner-signer",
                "official_verification": True,
                "bounded_equals_conventional": True,
                "witness_data_committed": False,
                "artifact_paths": {
                    "adapter_result": str(adapter),
                    "resource_report": str(report),
                },
            }
        ),
        encoding="utf-8",
    )
    completed.chmod(0o600)
    claim = tmp_path / "acceptance.json"
    record = MODULE.capture_external_input(
        completed, claim, expected_kind="design_partner_acceptance"
    )
    assert record["witness_data_committed"] is False
    assert (
        record["adapter_result_sha256"]
        == hashlib.sha256(adapter.read_bytes()).hexdigest()
    )

    completed_value = json.loads(completed.read_text(encoding="utf-8"))
    completed_value["partner_id"] = "Named Customer Incorporated"
    completed.write_text(json.dumps(completed_value), encoding="utf-8")
    with pytest.raises(ValueError, match="opaque partner"):
        MODULE.capture_external_input(completed, tmp_path / "named-partner.json")
    completed_value["partner_id"] = "partner-fedcba9876543210"
    completed.write_text(json.dumps(completed_value), encoding="utf-8")

    adapter_value["official_verification"] = False
    adapter.write_text(json.dumps(adapter_value), encoding="utf-8")
    with pytest.raises(ValueError, match="partner adapter result is incomplete"):
        MODULE.capture_external_input(completed, tmp_path / "invalid.json")


def test_completed_external_input_rejects_noncanonical_timestamp_before_capture():
    value = MODULE.template_input("implementation_review")
    value.update(
        completion_status="completed",
        release_sha="a" * 40,
        reviewer="reviewer",
        completed_at="2026-07-10T12:00:00+00:00",
        signer_id="signer",
        artifact_paths={"review_bundle": "missing", "review_report": "missing"},
    )
    with pytest.raises(ValueError, match="canonical RFC3339 UTC"):
        MODULE.completed_timestamp(value["completed_at"], "completion time")
