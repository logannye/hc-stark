import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys


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
    )
    assert set(record["artifact_sha256"]) == set(MODULE.INDEPENDENT_RESOURCE_ROLES)
    for role, path in artifacts.items():
        assert record["artifact_sha256"][role] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_review_ledger_hashes_report_and_validates_findings(tmp_path):
    report = tmp_path / "review.pdf"
    report.write_bytes(b"review bytes")
    findings = MODULE.validate_findings(
        [{"id": "LOW-1", "severity": "low", "status": "open", "reviewer_verified": False}]
    )
    ledger = MODULE.review_ledger(
        release_sha="abc",
        scope="implementation",
        reviewer="reviewer",
        completed_at="2026-01-01T00:00:00Z",
        report=report,
        findings=findings,
    )
    assert ledger["review_report_sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()


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
    )
    assert record["witness_data_committed"] is False
    assert record["adapter_result_sha256"] == hashlib.sha256(adapter.read_bytes()).hexdigest()
    output = tmp_path / "record.json"
    MODULE.write_json_atomic(output, record)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
