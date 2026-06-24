import pathlib
import subprocess

import launch_gate_audit as audit


def write(root: pathlib.Path, rel: str, text: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_check_evidence_reports_missing_file(tmp_path):
    failures = audit.check_evidence(tmp_path, audit.Evidence("missing.txt", ("marker",)))
    assert failures == ["missing missing.txt"]


def test_check_evidence_reports_missing_marker(tmp_path):
    write(tmp_path, "file.txt", "hello")
    failures = audit.check_evidence(tmp_path, audit.Evidence("file.txt", ("marker",)))
    assert failures == ["file.txt missing marker: marker"]


def test_check_evidence_passes_all_markers(tmp_path):
    write(tmp_path, "file.txt", "alpha beta gamma")
    assert audit.check_evidence(tmp_path, audit.Evidence("file.txt", ("alpha", "gamma"))) == []


def test_legacy_gate_skips_without_legacy_checkout(tmp_path):
    results = audit.audit_gates(tmp_path, None, require_legacy=False)
    legacy = next(result for result in results if result.name == "Legacy repo hygiene")
    assert legacy.status == "SKIP"


def test_legacy_gate_can_be_required(tmp_path):
    results = audit.audit_gates(tmp_path, None, require_legacy=True)
    legacy = next(result for result in results if result.name == "Legacy repo hygiene")
    assert legacy.status == "FAIL"


def test_legacy_proof_bin_tracking_detection(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    write(tmp_path, "proof.bin", "generated")
    subprocess.run(["git", "add", "proof.bin"], cwd=tmp_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    assert audit.legacy_proof_bin_tracked(tmp_path) is True


def test_deleted_legacy_proof_bin_is_allowed(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    write(tmp_path, "proof.bin", "generated")
    subprocess.run(["git", "add", "proof.bin"], cwd=tmp_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    (tmp_path / "proof.bin").unlink()
    assert audit.legacy_proof_bin_tracked(tmp_path) is False


def test_all_numbered_phases_are_part_of_roadmap_gate():
    roadmap_gate = audit.GATES[0]
    markers = roadmap_gate.required[0].markers
    for index in range(0, 11):
        assert f"## Phase {index}:" in markers
