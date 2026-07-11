import hashlib
import json
from pathlib import Path

import public_beta_gate


def fixture_root(tmp_path: Path) -> tuple[Path, dict]:
    required = ["clean_merged_ci", "official_verifier_equivalence"]
    release = tmp_path / "release"
    release.mkdir()
    (release / "release-channels-v1.json").write_text(
        json.dumps(
            {"channels": {"public_beta": {"required_gate_ids": required}}}
        ),
        encoding="utf-8",
    )
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("verified\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    evidence = {
        "schema_version": 1,
        "release_channel": "public_beta",
        "release_sha": "a" * 40,
        "gates": {
            gate: [{"path": "evidence.txt", "sha256": digest}] for gate in required
        },
    }
    return tmp_path, evidence


def test_complete_hash_bound_evidence_is_ready(tmp_path):
    root, evidence = fixture_root(tmp_path)
    path = root / "manifest.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    report = public_beta_gate.audit(path, root=root, expected_sha="a" * 40)
    assert report["status"] == "ready"
    assert not report["failures"]


def test_missing_gate_and_digest_mismatch_fail_closed(tmp_path):
    root, evidence = fixture_root(tmp_path)
    evidence["gates"].pop("official_verifier_equivalence")
    evidence["gates"]["clean_merged_ci"][0]["sha256"] = "0" * 64
    path = root / "manifest.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    report = public_beta_gate.audit(path, root=root, expected_sha="b" * 40)
    assert report["status"] == "blocked"
    assert any("gate set" in failure for failure in report["failures"])
    assert any("digest mismatch" in failure for failure in report["failures"])
    assert any("candidate" in failure for failure in report["failures"])
