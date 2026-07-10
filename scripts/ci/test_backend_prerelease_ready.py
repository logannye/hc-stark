import hashlib
import json
import subprocess

import backend_prerelease_ready as gate


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_candidate_rejects_blocked_config(tmp_path):
    evidence = tmp_path / "candidate.json"
    write_json(
        evidence,
        {
            "schema_version": 1,
            "status": "candidate",
            "release_sha": "abc",
            "gates": {},
        },
    )
    problems = gate.failures(
        {
            "schema_version": 2,
            "status": "blocked",
            "evidence_manifest": "candidate.json",
        },
        root=tmp_path,
    )
    assert "release gate config status must equal candidate" in problems


def test_candidate_evidence_manifest_cannot_escape_root(tmp_path):
    outside = tmp_path.parent / "outside-candidate.json"
    outside.write_text("{}", encoding="utf-8")
    for manifest in (str(outside), "../outside-candidate.json"):
        problems = gate.failures(
            {
                "schema_version": 2,
                "status": "candidate",
                "evidence_manifest": manifest,
            },
            root=tmp_path,
        )
        assert any("candidate evidence manifest is unavailable" in problem for problem in problems)
        assert any("unsafe" in problem for problem in problems)


def test_candidate_evidence_rejects_mutable_release_revision(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    source = tmp_path / "source"
    source.write_text("source\n", encoding="utf-8")
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
    digest = gate.source_tree_identity.source_tree_sha256(tmp_path, "HEAD")
    problems = gate.evidence_failures(
        {
            "schema_version": 1,
            "status": "candidate",
            "release_sha": "HEAD",
            "source_tree_sha256": digest,
            "gates": {},
        },
        root=tmp_path,
    )
    assert any("exact canonical Git commit" in problem for problem in problems)


def test_candidate_requires_every_unsigned_gate_and_forbids_signed_gate(tmp_path):
    report = tmp_path / "report.json"
    digest = write_json(report, {"status": "pass"})
    gates = {
        name: {
            "kind": kind,
            "metadata": {
                "exit_status": 0,
                "command": ["test"],
                "release_sha": "abc",
            },
            "artifacts": [{"path": "report.json", "sha256": digest}],
        }
        for name, kind in gate.final_gate.EXPECTED_KINDS.items()
        if name != "official_verifier_poseidon2"
    }
    evidence = tmp_path / "candidate.json"
    write_json(
        evidence,
        {
            "schema_version": 1,
            "status": "candidate",
            "release_sha": "abc",
            "gates": gates,
        },
    )
    problems = gate.failures(
        {
            "schema_version": 2,
            "status": "candidate",
            "evidence_manifest": "candidate.json",
        },
        root=tmp_path,
    )
    assert "candidate evidence gate is missing: official_verifier_poseidon2" in problems
    assert (
        "unexpected candidate evidence gate: signed_release_sbom_and_checksums"
        in problems
    )
