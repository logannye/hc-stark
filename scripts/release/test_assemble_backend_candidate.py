import hashlib
import json
from pathlib import Path
import stat
import zipfile

import assemble_backend_candidate as assembly
import pytest


RELEASE_SHA = "a" * 40


def write_archive(path: Path, names: set[str], *, unsafe: str | None = None):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(names):
            archive.writestr(name, (name + "\n").encode())
        if unsafe is not None:
            archive.writestr(unsafe, b"unsafe\n")


def write_qualified_archive(
    path: Path,
    kind: str,
    names: set[str],
    *,
    corrupt: str | None = None,
    extra: str | None = None,
):
    payloads = {name: (name + "\n").encode() for name in names}
    manifest_lines = []
    for name in sorted(names):
        digest = hashlib.sha256(payloads[name]).hexdigest()
        if name == corrupt:
            digest = "0" * 64
        rendered = f"./{name}" if kind == "resource" else name
        manifest_lines.append(f"{digest}  {rendered}\n")
    manifest = assembly.CHECKSUM_MANIFESTS[kind]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(payloads.items()):
            archive.writestr(name, payload)
        archive.writestr(manifest, "".join(manifest_lines).encode())
        if extra is not None:
            archive.writestr(extra, b"unexpected\n")


def provenance(kind: str, archive: Path):
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
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        },
    }


def write_inputs(root: Path):
    plan = assembly.artifact_plan()
    local_root = root / "release" / "evidence" / "work" / "local"
    local_root.mkdir(parents=True)
    for source in {spec.source for spec in plan if spec.source_kind == "local"}:
        (local_root / source).write_bytes((source + "\n").encode())
    for source in {spec.source for spec in plan if spec.source_kind == "tracked"}:
        path = root / source
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")

    resource_archive = root / "resource.zip"
    recovery_archive = root / "recovery.zip"
    write_qualified_archive(
        resource_archive,
        "resource",
        {spec.source for spec in plan if spec.source_kind == "resource"},
    )
    write_qualified_archive(
        recovery_archive,
        "recovery",
        {spec.source for spec in plan if spec.source_kind == "recovery"},
    )
    resource_provenance = root / "resource-provenance.json"
    recovery_provenance = root / "recovery-provenance.json"
    resource_provenance.write_text(
        json.dumps(provenance("resource", resource_archive)), encoding="utf-8"
    )
    recovery_provenance.write_text(
        json.dumps(provenance("recovery", recovery_archive)), encoding="utf-8"
    )
    return {
        "plan": plan,
        "local_root": local_root,
        "resource_archive": resource_archive,
        "recovery_archive": recovery_archive,
        "resource_provenance": resource_provenance,
        "recovery_provenance": recovery_provenance,
    }


def assemble(root: Path, monkeypatch):
    inputs = write_inputs(root)
    validated = []

    def validate(source, *, root):
        validated.append((source, root))
        return {"status": "candidate"}

    monkeypatch.setattr(assembly.candidate, "construct_evidence", validate)
    output_root = root / "release" / "evidence" / "backend-v1" / RELEASE_SHA
    output_input = root / "release" / "evidence" / "work" / "candidate-input.json"
    result = assembly.assemble(
        root=root,
        release_sha=RELEASE_SHA,
        resource_archive=inputs["resource_archive"],
        recovery_archive=inputs["recovery_archive"],
        resource_provenance=inputs["resource_provenance"],
        recovery_provenance=inputs["recovery_provenance"],
        local_root=inputs["local_root"],
        output_root=output_root,
        output_input=output_input,
    )
    return result, inputs, output_root, output_input, validated


def test_plan_is_the_exact_closed_candidate_gate_inventory():
    plan = assembly.artifact_plan()
    observed = {(spec.gate, spec.role) for spec in plan}
    expected = {
        (gate, role)
        for gate, roles in assembly.candidate.GATE_ROLES.items()
        for role in roles
    }
    assert observed == expected
    assert len(observed) == len(plan)
    assert len([spec for spec in plan if spec.role.startswith("fuzz_log_")]) == 14
    assert len([spec for spec in plan if spec.role.startswith("crash_log_")]) == 22


def test_assembly_copies_exact_bytes_and_validates_before_emitting_input(
    tmp_path, monkeypatch
):
    result, inputs, output_root, output_input, validated = assemble(
        tmp_path, monkeypatch
    )

    assert validated == [(result, tmp_path.resolve())]
    assert json.loads(output_input.read_text()) == result
    assert stat.S_IMODE(output_input.stat().st_mode) == 0o600
    assert set(result["gates"]) == assembly.candidate.prerelease.EXPECTED_GATES
    for gate, roles in assembly.candidate.GATE_ROLES.items():
        assert [item["role"] for item in result["gates"][gate]["artifacts"]] == roles

    unique_destinations = {
        spec.destination for spec in inputs["plan"] if spec.destination is not None
    }
    for destination in unique_destinations:
        path = output_root / destination
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert (output_root / "provenance" / "resource-qualification-run-v1.json").is_file()
    assert (output_root / "provenance" / "recovery-qualification-run-v1.json").is_file()
    assert (output_root / "provenance" / "qualification-SHA256SUMS").is_file()
    assert (output_root / "provenance" / "recovery-SHA256SUMS").is_file()

    one = result["gates"]["one_million_row_resource_gate"]["artifacts"][0]
    ten = result["gates"]["ten_million_row_resource_gate"]["artifacts"][0]
    assert one["role"] == ten["role"] == "matrix_manifest"
    assert one["path"] == ten["path"]


def test_archive_rejects_path_traversal(tmp_path):
    archive_path = tmp_path / "unsafe.zip"
    write_archive(archive_path, {"expected.json"}, unsafe="../escape")
    with pytest.raises(ValueError, match="unsafe ZIP member"):
        with assembly.EvidenceArchive(
            archive_path, required={"expected.json"}, label="unsafe"
        ):
            pass


@pytest.mark.parametrize("oversized", [False, True])
def test_archive_rejects_empty_or_oversized_zip_before_parsing(tmp_path, oversized):
    archive_path = tmp_path / "bounded.zip"
    with archive_path.open("wb") as archive:
        if oversized:
            archive.truncate(assembly.MAX_ARCHIVE_BYTES + 1)
    with pytest.raises(ValueError, match="empty or oversized"):
        with assembly.EvidenceArchive(
            archive_path, required={"expected.json"}, label="bounded"
        ):
            pass


def test_assembly_rejects_provenance_that_does_not_hash_downloaded_archive(
    tmp_path, monkeypatch
):
    inputs = write_inputs(tmp_path)
    value = json.loads(inputs["resource_provenance"].read_text())
    value["artifact"]["archive_sha256"] = "f" * 64
    inputs["resource_provenance"].write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(
        assembly.candidate, "construct_evidence", lambda source, *, root: source
    )
    with pytest.raises(ValueError, match="provenance is incomplete"):
        assembly.assemble(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            resource_archive=inputs["resource_archive"],
            recovery_archive=inputs["recovery_archive"],
            resource_provenance=inputs["resource_provenance"],
            recovery_provenance=inputs["recovery_provenance"],
            local_root=inputs["local_root"],
            output_root=(
                tmp_path / "release" / "evidence" / "backend-v1" / RELEASE_SHA
            ),
            output_input=tmp_path / "release" / "evidence" / "work" / "input.json",
        )


def test_assembly_rejects_checksum_mismatch_before_copying_evidence(
    tmp_path, monkeypatch
):
    inputs = write_inputs(tmp_path)
    resource_files = assembly.archive_evidence_files("resource", inputs["plan"])
    write_qualified_archive(
        inputs["resource_archive"],
        "resource",
        resource_files,
        corrupt=next(iter(resource_files)),
    )
    inputs["resource_provenance"].write_text(
        json.dumps(provenance("resource", inputs["resource_archive"])),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        assembly.candidate, "construct_evidence", lambda source, *, root: source
    )
    output_root = tmp_path / "release" / "evidence" / "backend-v1" / RELEASE_SHA
    with pytest.raises(ValueError, match="checksum mismatch"):
        assembly.assemble(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            resource_archive=inputs["resource_archive"],
            recovery_archive=inputs["recovery_archive"],
            resource_provenance=inputs["resource_provenance"],
            recovery_provenance=inputs["recovery_provenance"],
            local_root=inputs["local_root"],
            output_root=output_root,
            output_input=tmp_path / "release" / "evidence" / "work" / "input.json",
        )
    assert not output_root.exists()


def test_manifest_extraction_rejects_unattested_extra_file(tmp_path):
    plan = assembly.artifact_plan()
    resource_files = assembly.archive_evidence_files("resource", plan)
    recovery_files = assembly.archive_evidence_files("recovery", plan)
    resource = tmp_path / "resource.zip"
    recovery = tmp_path / "recovery.zip"
    write_qualified_archive(
        resource, "resource", resource_files, extra="unattested-output.json"
    )
    write_qualified_archive(recovery, "recovery", recovery_files)
    with pytest.raises(ValueError, match="ZIP file inventory differs"):
        assembly.extract_checksum_manifests(
            resource_archive=resource,
            recovery_archive=recovery,
            resource_output=tmp_path / "qualification-SHA256SUMS",
            recovery_output=tmp_path / "recovery-SHA256SUMS",
        )


def test_assembly_refuses_noncanonical_output_root(tmp_path, monkeypatch):
    inputs = write_inputs(tmp_path)
    monkeypatch.setattr(
        assembly.candidate, "construct_evidence", lambda source, *, root: source
    )
    with pytest.raises(ValueError, match="canonical release path"):
        assembly.assemble(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            resource_archive=inputs["resource_archive"],
            recovery_archive=inputs["recovery_archive"],
            resource_provenance=inputs["resource_provenance"],
            recovery_provenance=inputs["recovery_provenance"],
            local_root=inputs["local_root"],
            output_root=tmp_path / "elsewhere",
            output_input=tmp_path / "release" / "evidence" / "work" / "input.json",
        )
