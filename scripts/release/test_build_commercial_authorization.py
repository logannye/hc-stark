import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys


MODULE_PATH = Path(__file__).with_name("build_commercial_authorization.py")
SPEC = importlib.util.spec_from_file_location("build_commercial_authorization", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def artifact(path, role):
    return {
        "role": role,
        "path": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def release_fixture(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"spdxVersion":"SPDX-2.3"}\n')
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text("signed manifest\n")
    signature = tmp_path / "SHA256SUMS.sigstore.json"
    signature.write_text("signature bundle\n")
    evidence = tmp_path / "evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "ready",
                "release_sha": "a" * 40,
                "source_release_sha": "b" * 40,
                "source_tree_sha256": "c" * 64,
                "gates": {
                    "signed_release_sbom_and_checksums": {
                        "kind": "signed_release",
                        "metadata": {},
                        "artifacts": [
                            artifact(sbom, "sbom"),
                            artifact(checksums, "checksums"),
                            artifact(signature, "signature"),
                        ],
                    }
                },
            },
            sort_keys=True,
        )
        + "\n"
    )
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "status": "ready",
                "evidence_manifest": evidence.name,
            }
        )
        + "\n"
    )
    return config, evidence, sbom, checksums, signature


def permit_valid_release(monkeypatch):
    monkeypatch.setattr(MODULE.gate, "failures", lambda config, root: [])
    monkeypatch.setattr(MODULE.signed, "verify_spdx_sbom", lambda path: None)
    monkeypatch.setattr(
        MODULE.signed,
        "verify_checksum_manifest",
        lambda checksums, sbom, required: 9,
    )
    monkeypatch.setattr(
        MODULE.gate.evidence_runtime,
        "run_anchored_cosign",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "verified"),
    )


def test_builds_exact_owner_only_hash_bound_authorization(tmp_path, monkeypatch):
    config, evidence, _sbom, checksums, signature = release_fixture(tmp_path)
    permit_valid_release(monkeypatch)
    report_path = tmp_path / "report.json"
    authorization_path = tmp_path / "authorization.json"
    report, authorization, digest = MODULE.build(
        root=tmp_path,
        config_path=config,
        output_report=report_path,
        output_authorization=authorization_path,
        cosign="cosign",
        verified_at="2026-07-10T12:00:00Z",
    )
    assert set(authorization) == MODULE.AUTHORIZATION_KEYS
    assert authorization["release_sha"] == "a" * 40
    assert authorization["source_tree_sha256"] == "c" * 64
    assert authorization["backend_evidence_sha256"] == hashlib.sha256(
        evidence.read_bytes()
    ).hexdigest()
    assert authorization["backend_release_ready_report_sha256"] == hashlib.sha256(
        report_path.read_bytes()
    ).hexdigest()
    assert authorization["signed_release_manifest_sha256"] == hashlib.sha256(
        checksums.read_bytes()
    ).hexdigest()
    assert authorization["signature_bundle_sha256"] == hashlib.sha256(
        signature.read_bytes()
    ).hexdigest()
    assert report["signature_bundle"]["verified"] is True
    assert digest == hashlib.sha256(authorization_path.read_bytes()).hexdigest()
    assert stat.S_IMODE(report_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(authorization_path.stat().st_mode) == 0o600


def test_blocked_release_or_bad_signature_emits_nothing(tmp_path, monkeypatch):
    config, *_ = release_fixture(tmp_path)
    report_path = tmp_path / "report.json"
    authorization_path = tmp_path / "authorization.json"
    monkeypatch.setattr(MODULE.gate, "failures", lambda config, root: ["review missing"])
    try:
        MODULE.build(
            root=tmp_path,
            config_path=config,
            output_report=report_path,
            output_authorization=authorization_path,
            cosign="cosign",
        )
    except ValueError as error:
        assert "not ready" in str(error)
    else:
        raise AssertionError("blocked release produced a commercial authorization")
    assert not report_path.exists()
    assert not authorization_path.exists()

    permit_valid_release(monkeypatch)
    monkeypatch.setattr(
        MODULE.gate.evidence_runtime,
        "run_anchored_cosign",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, "invalid"),
    )
    try:
        MODULE.build(
            root=tmp_path,
            config_path=config,
            output_report=report_path,
            output_authorization=authorization_path,
            cosign="cosign",
        )
    except ValueError as error:
        assert "Sigstore verification failed" in str(error)
    else:
        raise AssertionError("invalid signature produced a commercial authorization")
    assert not report_path.exists()
    assert not authorization_path.exists()


def test_rejects_output_collision_and_noncanonical_timestamp(tmp_path, monkeypatch):
    config, *_ = release_fixture(tmp_path)
    permit_valid_release(monkeypatch)
    output = tmp_path / "same.json"
    try:
        MODULE.build(
            root=tmp_path,
            config_path=config,
            output_report=output,
            output_authorization=output,
            cosign="cosign",
            verified_at="2026-07-10T12:00:00Z",
        )
    except ValueError as error:
        assert "must differ" in str(error)
    else:
        raise AssertionError("colliding commercial authorization outputs were accepted")
    assert not output.exists()

    for timestamp in (
        "2026-07-10T12:00:00+00:00",
        "2026-07-10T12:00:00.123Z",
    ):
        try:
            MODULE.build(
                root=tmp_path,
                config_path=config,
                output_report=tmp_path / "report.json",
                output_authorization=tmp_path / "authorization.json",
                cosign="cosign",
                verified_at=timestamp,
            )
        except ValueError as error:
            assert "canonical" in str(error)
        else:
            raise AssertionError("noncanonical commercial authorization time was accepted")


def test_safe_output_rejects_parent_escape_and_symlink(tmp_path):
    outside = tmp_path.parent / "outside-auth.json"
    for raw in (Path("../outside-auth.json"), outside):
        try:
            MODULE.safe_output(tmp_path, raw)
        except ValueError as error:
            assert "outside" in str(error) or "unsafe" in str(error)
        else:
            raise AssertionError("commercial authorization output escaped the repository")
    linked = tmp_path / "linked"
    linked.symlink_to(tmp_path.parent, target_is_directory=True)
    try:
        MODULE.safe_output(tmp_path, linked / "authorization.json")
    except ValueError as error:
        assert "unsafe" in str(error)
    else:
        raise AssertionError("symlinked commercial authorization parent was accepted")
