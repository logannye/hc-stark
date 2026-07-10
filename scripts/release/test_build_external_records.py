import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import zipfile


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
        assert record["artifact_sha256"][role] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_review_ledger_hashes_report_and_validates_findings(tmp_path):
    report = tmp_path / "review.pdf"
    report.write_bytes(b"review bytes")
    bundle = tmp_path / "review.zip"
    bundle.write_bytes(b"deterministic review bundle")
    findings = MODULE.validate_findings(
        [{"id": "LOW-1", "severity": "low", "status": "open", "reviewer_verified": False}]
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
        signer_id="review-signer",
    )
    assert ledger["review_report_sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()
    assert ledger["review_bundle_sha256"] == hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert ledger["review_manifest_sha256"] == "a" * 64
    assert ledger["source_tree_sha256"] == "b" * 64


def test_review_record_builder_rejects_skew_and_binds_exact_bundle(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    source = tmp_path / "source"
    source.write_text("reviewed source\n", encoding="utf-8")
    subprocess.run(["git", "add", "source"], cwd=tmp_path, check=True)
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
        cwd=tmp_path,
        check=True,
    )
    release_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True
    ).strip()
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
    findings = tmp_path / "findings.json"
    findings.write_text("[]", encoding="utf-8")
    output = tmp_path / "ledger.json"
    args = SimpleNamespace(
        release_sha=release_sha,
        scope="implementation",
        reviewer="independent reviewer",
        completed_at="2026-01-01T00:00:00Z",
        signer_id="review-signer",
        review_bundle=bundle,
        review_report=report,
        findings=findings,
        output=output,
    )
    MODULE.build_review(args)
    ledger = json.loads(output.read_text(encoding="utf-8"))
    assert ledger["review_bundle_sha256"] == hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert ledger["review_manifest_sha256"] == hashlib.sha256(manifest_bytes).hexdigest()
    assert ledger["source_tree_sha256"] == source_tree_sha256
    assert stat.S_IMODE(output.stat().st_mode) == 0o600

    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr(
            "review-manifest.json",
            manifest_bytes.replace(source_tree_sha256.encode(), b"f" * 64),
        )
    try:
        MODULE.build_review(args)
    except ValueError as error:
        assert "incomplete or release-skewed" in str(error)
    else:
        raise AssertionError("source-skewed review bundle was accepted")


def test_partner_acceptance_hashes_only_artifacts_and_atomic_output_is_private(tmp_path):
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
    assert record["adapter_result_sha256"] == hashlib.sha256(adapter.read_bytes()).hexdigest()
    output = tmp_path / "record.json"
    MODULE.write_json_atomic(output, record)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
