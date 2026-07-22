import hashlib
import json
from pathlib import Path

import assemble_backend_candidate as assembly
import build_backend_assembly_provenance as provenance
import pytest


RELEASE_SHA = "a" * 40


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_value(kind: str):
    policy = assembly.PROVENANCE_POLICY[kind]
    return {
        "schema_version": 1,
        "repository": "logannye/hc-stark",
        "workflow_path": policy["workflow_path"],
        "run_id": 100 if kind == "resource" else 200,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": RELEASE_SHA,
        "status": "completed",
        "conclusion": "success",
        "actor": "logannye",
        "triggering_actor": "logannye",
        "run_started_at": "2026-01-01T00:00:00Z",
        "artifact": {
            "id": 101 if kind == "resource" else 201,
            "name": policy["artifact_prefix"] + RELEASE_SHA,
            "created_at": "2026-01-01T00:01:00Z",
            "archive_sha256": ("b" if kind == "resource" else "c") * 64,
        },
    }


def candidate_fixture(root: Path):
    gates = {}
    plan = {(spec.gate, spec.role): spec for spec in assembly.artifact_plan()}
    for gate, roles in provenance.candidate.GATE_ROLES.items():
        artifacts = []
        for role in roles:
            spec = plan[(gate, role)]
            path = (
                root / spec.source
                if spec.destination is None
                else root
                / "release"
                / "evidence"
                / "backend-v1"
                / RELEASE_SHA
                / spec.destination
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(f"{spec.source_kind}/{spec.source}\n".encode())
            artifacts.append(
                {
                    "role": role,
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        gates[gate] = {
            "kind": provenance.candidate.final_gate.EXPECTED_KINDS[gate],
            "metadata": {},
            "artifacts": artifacts,
        }
    evidence = {
        "schema_version": 1,
        "status": "candidate",
        "release_sha": RELEASE_SHA,
        "source_tree_sha256": "d" * 64,
        "gates": gates,
    }
    evidence_path = root / "release" / "evidence" / "backend-v1-evidence.json"
    write_json(evidence_path, evidence)
    config = {
        "schema_version": 2,
        "release": "tinyzkp-plonky3-backend-v1",
        "status": "candidate",
        "evidence_manifest": "release/evidence/backend-v1-evidence.json",
        "policy": "fixture",
    }
    config_path = root / "release" / "backend-v1-gates.json"
    write_json(config_path, config)
    provenance_root = (
        root / "release" / "evidence" / "backend-v1" / RELEASE_SHA / "provenance"
    )
    resource = provenance_root / "resource-qualification-run-v1.json"
    recovery = provenance_root / "recovery-qualification-run-v1.json"
    write_json(resource, run_value("resource"))
    write_json(recovery, run_value("recovery"))
    artifact_digests = {
        (gate, artifact["role"]): artifact["sha256"]
        for gate, value in evidence["gates"].items()
        for artifact in value["artifacts"]
    }
    for kind in ("resource", "recovery"):
        entries = {}
        for spec in assembly.artifact_plan():
            if spec.source_kind == kind:
                entries[spec.source] = artifact_digests[(spec.gate, spec.role)]
        lines = []
        for name, digest in sorted(entries.items()):
            rendered = f"./{name}" if kind == "resource" else name
            lines.append(f"{digest}  {rendered}\n")
        (provenance_root / assembly.CHECKSUM_MANIFESTS[kind]).write_text(
            "".join(lines), encoding="ascii"
        )
    return config_path, resource, recovery, evidence


def build(root: Path, monkeypatch):
    config, resource, recovery, evidence = candidate_fixture(root)
    monkeypatch.setattr(
        provenance.candidate.prerelease,
        "candidate_content_failures",
        lambda value, *, root: [],
    )
    report = provenance.build_report(
        root=root,
        release_sha=RELEASE_SHA,
        candidate_config=config,
        resource_provenance=resource,
        recovery_provenance=recovery,
        workflow_run_id=300,
        workflow_run_attempt=2,
        actor="logannye",
        triggering_actor="logannye",
        issued_at="2026-01-01T00:02:00Z",
    )
    return report, evidence


def test_report_binds_candidate_artifacts_and_both_owner_runs(tmp_path, monkeypatch):
    report, evidence = build(tmp_path, monkeypatch)

    assert set(report) == {
        "schema_version",
        "kind",
        "release_sha",
        "issued_at",
        "assembly_workflow",
        "qualification_sources",
        "candidate",
    }
    assert report["release_sha"] == RELEASE_SHA
    assert report["assembly_workflow"] == {
        "repository": "logannye/hc-stark",
        "workflow_path": ".github/workflows/assemble-backend-evidence.yml",
        "workflow_ref": "refs/heads/main",
        "run_id": 300,
        "run_attempt": 2,
        "actor": "logannye",
        "triggering_actor": "logannye",
    }
    assert set(report["qualification_sources"]) == {"resource", "recovery"}
    for value in report["qualification_sources"].values():
        assert set(value["checksum_manifest"]) == {"path", "sha256"}
    expected_count = sum(len(gate["artifacts"]) for gate in evidence["gates"].values())
    assert len(report["candidate"]["artifact_bindings"]) == expected_count
    assert report["candidate"]["source_tree_sha256"] == "d" * 64


def test_report_rejects_artifact_digest_skew(tmp_path, monkeypatch):
    config, resource, recovery, evidence = candidate_fixture(tmp_path)
    first_gate = next(iter(evidence["gates"].values()))
    first_gate["artifacts"][0]["sha256"] = "f" * 64
    write_json(tmp_path / "release" / "evidence" / "backend-v1-evidence.json", evidence)
    monkeypatch.setattr(
        provenance.candidate.prerelease,
        "candidate_content_failures",
        lambda value, *, root: [],
    )
    with pytest.raises(ValueError, match="digest mismatch"):
        provenance.build_report(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            candidate_config=config,
            resource_provenance=resource,
            recovery_provenance=recovery,
            workflow_run_id=300,
            workflow_run_attempt=2,
            actor="logannye",
            triggering_actor="logannye",
            issued_at="2026-01-01T00:02:00Z",
        )


def test_report_rejects_non_owner_workflow(tmp_path, monkeypatch):
    config, resource, recovery, _ = candidate_fixture(tmp_path)
    monkeypatch.setattr(
        provenance.candidate.prerelease,
        "candidate_content_failures",
        lambda value, *, root: [],
    )
    with pytest.raises(ValueError, match="owner-dispatched"):
        provenance.build_report(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            candidate_config=config,
            resource_provenance=resource,
            recovery_provenance=recovery,
            workflow_run_id=300,
            workflow_run_attempt=2,
            actor="someone-else",
            triggering_actor="logannye",
            issued_at="2026-01-01T00:02:00Z",
        )


def test_report_rejects_checksum_manifest_skew(tmp_path, monkeypatch):
    config, resource, recovery, _ = candidate_fixture(tmp_path)
    checksum = resource.parent / assembly.CHECKSUM_MANIFESTS["resource"]
    value = checksum.read_text(encoding="ascii")
    checksum.write_text(value.replace(value[:64], "f" * 64, 1), encoding="ascii")
    monkeypatch.setattr(
        provenance.candidate.prerelease,
        "candidate_content_failures",
        lambda value, *, root: [],
    )
    with pytest.raises(ValueError, match="differs from candidate artifact bindings"):
        provenance.build_report(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            candidate_config=config,
            resource_provenance=resource,
            recovery_provenance=recovery,
            workflow_run_id=300,
            workflow_run_attempt=2,
            actor="logannye",
            triggering_actor="logannye",
            issued_at="2026-01-01T00:02:00Z",
        )
