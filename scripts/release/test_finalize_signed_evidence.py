import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys


MODULE_PATH = Path(__file__).with_name("finalize_signed_evidence.py")
SPEC = importlib.util.spec_from_file_location("finalize_signed_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_checksum_manifest_rejects_symlink(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("{}", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(real)
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text(f"{sha256(real)}  linked.json\n", encoding="utf-8")
    try:
        module.verify_checksum_manifest(checksums, real)
    except ValueError as error:
        assert "contains a symlink" in str(error)
    else:
        raise AssertionError("symlinked checksum entry was accepted")


def test_bad_sigstore_verification_fails_closed(tmp_path):
    cosign = tmp_path / "cosign"
    cosign.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    cosign.chmod(cosign.stat().st_mode | stat.S_IXUSR)
    result = module.subprocess.run(
        [str(cosign), "verify-blob", "--bundle", "x", "y"],
        check=False,
    )
    assert result.returncode == 1


def test_checksum_manifest_requires_every_production_artifact(tmp_path):
    sbom = tmp_path / "tinyzkp-engine.spdx.json"
    sbom.write_text("{}", encoding="utf-8")
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text(f"{sha256(sbom)}  {sbom.name}\n", encoding="utf-8")
    try:
        module.verify_checksum_manifest(
            checksums, sbom, module.REQUIRED_CHECKSUM_ENTRIES
        )
    except ValueError as error:
        assert "release artifact inventory differs" in str(error)
    else:
        raise AssertionError("partial release checksum manifest was accepted")


def test_checksum_manifest_rejects_unexpected_public_artifact(tmp_path):
    names = set(module.REQUIRED_CHECKSUM_ENTRIES) | {"hc-server-linux-x86_64"}
    for name in names:
        (tmp_path / name).write_bytes(name.encode())
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text(
        "".join(
            f"{sha256(tmp_path / name)}  {name}\n" for name in sorted(names)
        ),
        encoding="utf-8",
    )
    try:
        module.verify_checksum_manifest(
            checksums,
            tmp_path / "tinyzkp-engine.spdx.json",
            module.REQUIRED_CHECKSUM_ENTRIES,
        )
    except ValueError as error:
        assert "unexpected hc-server-linux-x86_64" in str(error)
    else:
        raise AssertionError("unexpected server binary was accepted")


def test_spdx_sbom_requires_document_identity(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")
    try:
        module.verify_spdx_sbom(sbom)
    except ValueError as error:
        assert "SPDX document identity" in str(error)
    else:
        raise AssertionError("empty SPDX document was accepted")

    sbom.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "tinyzkp-engine",
                "documentNamespace": "https://tinyzkp.com/sbom/test",
            }
        ),
        encoding="utf-8",
    )
    module.verify_spdx_sbom(sbom)


def test_atomic_json_is_owner_only(tmp_path):
    output = tmp_path / "evidence.json"
    module.write_json_atomic(output, {"status": "ready"})
    assert json.loads(output.read_text(encoding="utf-8")) == {"status": "ready"}
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_finalization_binds_source_commit_without_requiring_sha_self_reference(
    tmp_path, monkeypatch
):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("pub fn value() -> u8 { 1 }\n")
    (tmp_path / "release" / "evidence").mkdir(parents=True)
    (tmp_path / "release" / "backend-v1-gates.json").write_text("{}\n")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
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
    source_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True
    ).strip()
    source_tree_sha256 = module.source_tree_identity.source_tree_sha256(
        tmp_path, source_sha
    )
    candidate = {
        "schema_version": 1,
        "status": "candidate",
        "release_sha": source_sha,
        "source_tree_sha256": source_tree_sha256,
        "gates": {},
    }
    candidate_path = tmp_path / "release" / "evidence" / "backend-v1-evidence.json"
    candidate_path.write_text(json.dumps(candidate))
    config_path = tmp_path / "release" / "backend-v1-gates.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "status": "candidate",
                "evidence_manifest": "release/evidence/backend-v1-evidence.json",
            }
        )
    )
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=TinyZKP Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "candidate evidence",
        ],
        cwd=tmp_path,
        check=True,
    )
    release_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True
    ).strip()

    sbom = tmp_path / "sbom.json"
    checksums = tmp_path / "SHA256SUMS"
    signature = tmp_path / "signature.json"
    identity_report = tmp_path / "engine-identity.json"
    runtime_smoke = tmp_path / "engine-runtime-smoke.json"
    sbom.write_text("{}")
    checksums.write_text("placeholder")
    signature.write_text("{}")
    identity_report.write_text("{}")
    runtime_smoke.write_text("{}")
    cosign = tmp_path / "cosign"
    cosign.write_text("#!/bin/sh\nexit 0\n")
    cosign.chmod(0o700)
    monkeypatch.setattr(module.prerelease, "failures", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "verify_spdx_sbom", lambda _path: None)
    monkeypatch.setattr(module, "verify_checksum_manifest", lambda *_args, **_kwargs: 9)
    monkeypatch.setattr(module.final_gate, "evidence_failures", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        module.final_gate, "validate_identity_evidence", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        module.final_gate,
        "validate_identity_checksum_binding",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        module.final_gate.evidence_runtime,
        "run_anchored_cosign",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "verified"),
    )

    evidence, _config = module.finalize(
        root=tmp_path,
        candidate_config_path=config_path,
        release_sha=release_sha,
        release_ref="backend-v0.1.0",
        sbom=sbom,
        checksums=checksums,
        signature=signature,
        identity_report=identity_report,
        runtime_smoke=runtime_smoke,
        output_evidence=tmp_path / "final-evidence.json",
        output_config=tmp_path / "final-config.json",
        cosign=str(cosign),
    )

    assert source_sha != release_sha
    assert evidence["source_release_sha"] == source_sha
    assert evidence["release_sha"] == release_sha
    signed = evidence["gates"][module.prerelease.SIGNED_GATE]["metadata"]
    assert signed["source_tree_sha256"] == source_tree_sha256
    assert signed["release_tree_sha256"] == source_tree_sha256
    assert signed["evidence_only_delta_verified"] is True
    assert signed["release_ref"] == "backend-v0.1.0"
    assert signed["signer_identity"] == module.sigstore_identity("backend-v0.1.0")
    assert signed["signer_workflow_sha"] == release_sha
    assert signed["signer_workflow_ref"] == "refs/tags/backend-v0.1.0"
    assert signed["signer_workflow_repository"] == "logannye/hc-stark"
    assert signed["signer_workflow_trigger"] == "workflow_dispatch"
    command = signed["verification_command"]
    assert command[command.index("--certificate-github-workflow-sha") + 1] == release_sha
    assert command[command.index("--certificate-github-workflow-ref") + 1] == (
        "refs/tags/backend-v0.1.0"
    )
    assert command[command.index("--certificate-github-workflow-repository") + 1] == (
        "logannye/hc-stark"
    )
    assert command[command.index("--certificate-github-workflow-trigger") + 1] == (
        "workflow_dispatch"
    )
    identity_gate = evidence["gates"][module.prerelease.IDENTITY_GATE]
    assert identity_gate["metadata"]["identities"] == {
        "engine_cli": release_sha,
        "engine_oci": release_sha,
    }
    assert identity_gate["metadata"]["cli_smoke"] is True
    assert identity_gate["metadata"]["oci_smoke"] is True
    assert {item["role"] for item in identity_gate["artifacts"]} == {
        "identity_report",
        "runtime_smoke",
    }
