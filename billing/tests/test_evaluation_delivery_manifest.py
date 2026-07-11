import hashlib
import json

import pytest

import evaluation_delivery_manifest as delivery


def write_private(path, payload):
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    return path, raw


def package(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    release = "a" * 40
    workload = "b" * 64
    session = "c" * 32
    baseline = {
        "schema_version": 1,
        "scope": "full_pipeline",
        "mode": "baseline",
        "benchmark_session_id": session,
        "release_sha": release,
        "dependency_profile": delivery.PROFILE,
        "workload_manifest_digest_hex": workload,
        "verification_succeeded": True,
        "exit_status": 0,
    }
    candidate = {**baseline, "mode": "bounded"}
    bundle = {
        "schema_version": 1,
        "manifest_digest_hex": workload,
        "proof_digest_hex": "d" * 64,
        "provenance": {
            "prover_version": "0.6.1",
            "verifier_version": "0.6.1",
            "dependency_profile": delivery.PROFILE,
            "release_sha": release,
        },
    }
    workload_manifest = {
        "schema_version": 1,
        "backend": "plonky3",
        "profile": delivery.PROFILE,
        "workload_id": "fibonacci",
        "logical_rows": 1048576,
        "deterministic_seed": 0,
        "expected_verifier": "p3_uni_stark_0.6.1",
    }
    bundle["manifest"] = workload_manifest
    artifacts = {}
    for name, payload, media_type in (
        ("workload_manifest", workload_manifest, "application/json"),
        ("adapter_artifact", b"adapter", "application/octet-stream"),
        ("baseline_benchmark_report", baseline, "application/json"),
        ("candidate_benchmark_report", candidate, "application/json"),
        ("proof_bundle", bundle, "application/json"),
        ("raw_measurements_archive", b"raw", "application/zstd"),
        ("reproduction_instructions", b"reproduce", "text/markdown"),
        ("known_limitations", b"limits", "text/markdown"),
        ("production_recommendation", b"recommend", "text/markdown"),
        ("written_acceptance", b"accepted", "application/pdf"),
    ):
        path, raw = write_private(root / f"{name}.dat", payload)
        artifacts[name] = {
            "name": name,
            "relative_path": path.name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "media_type": media_type,
        }
    verification = {
        "schema_version": delivery.VERIFICATION_SCHEMA,
        "verifier_target": delivery.VERIFIER,
        "verification_succeeded": True,
        "proof_bundle_sha256": artifacts["proof_bundle"]["sha256"],
        "proof_digest_hex": "d" * 64,
        "release_sha": release,
        "verified_at": "2020-01-01T12:00:00Z",
        "exact_command": ["hc-cli", "plonky3", "verify", "--bundle", "bundle.json"],
    }
    path, raw = write_private(root / "official_verification_report.dat", verification)
    artifacts["official_verification_report"] = {
        "name": "official_verification_report",
        "relative_path": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "media_type": "application/json",
    }
    manifest = {
        "schema_version": delivery.SCHEMA_VERSION,
        "status": "complete",
        "agreement_id": "eval-001",
        "offer_id": "founding_evaluation",
        "workload_manifest_digest_hex": workload,
        "scope_sha256": "e" * 64,
        "qualification_sha256": "f" * 64,
        "partner_preflight_sha256": "0" * 64,
        "agreement_gate_sha256": "1" * 64,
        "release_sha": release,
        "adapter_revision": "2" * 40,
        "official_verifier_target": delivery.VERIFIER,
        "artifacts": list(artifacts.values()),
        "retention": {
            "policy_id": "tinyzkp-evaluation-retention-v1",
            "application_delete_by": "2030-01-01T00:00:00Z",
            "artifact_retain_until": "2029-01-01T00:00:00Z",
            "artifact_delete_by": "2030-01-01T00:00:00Z",
            "deletion_owner": "TinyZKP operator",
        },
        "data_boundary": dict(delivery.DATA_BOUNDARY),
        "prepared_by": "TinyZKP operator",
        "completed_at": "2020-01-01T11:00:00Z",
        "accepted_at": "2020-01-01T13:00:00Z",
    }
    manifest_path, _ = write_private(tmp_path / "delivery.json", manifest)
    return manifest_path, root, manifest, artifacts


def test_complete_delivery_package_verifies(tmp_path):
    manifest_path, root, manifest, _ = package(tmp_path)
    loaded, digest = delivery.validate_manifest(manifest_path, root)
    assert loaded == manifest
    assert digest == hashlib.sha256(manifest_path.read_bytes()).hexdigest()


def test_artifact_tampering_fails(tmp_path):
    manifest_path, root, _, _ = package(tmp_path)
    target = root / "proof_bundle.dat"
    target.write_bytes(b"tampered")
    target.chmod(0o600)
    with pytest.raises(ValueError, match="does not match"):
        delivery.validate_manifest(manifest_path, root)


def test_verifier_failure_fails(tmp_path):
    manifest_path, root, manifest, artifacts = package(tmp_path)
    path = root / "official_verification_report.dat"
    report = json.loads(path.read_text())
    report["verification_succeeded"] = False
    path, raw = write_private(path, report)
    for descriptor in manifest["artifacts"]:
        if descriptor["name"] == "official_verification_report":
            descriptor["sha256"] = hashlib.sha256(raw).hexdigest()
            descriptor["size_bytes"] = len(raw)
    write_private(manifest_path, manifest)
    with pytest.raises(ValueError, match="not bound"):
        delivery.validate_manifest(manifest_path, root)


def test_path_traversal_and_symlink_fail(tmp_path):
    manifest_path, root, manifest, _ = package(tmp_path)
    manifest["artifacts"][0]["relative_path"] = "../escape"
    write_private(manifest_path, manifest)
    with pytest.raises(ValueError, match="stay below"):
        delivery.validate_manifest(manifest_path, root)


def test_data_boundary_and_retention_fail_closed(tmp_path):
    manifest_path, root, manifest, _ = package(tmp_path)
    manifest["data_boundary"]["witness_data_included"] = True
    write_private(manifest_path, manifest)
    with pytest.raises(ValueError, match="data boundary"):
        delivery.validate_manifest(manifest_path, root)


def test_manifest_and_artifacts_must_be_owner_only(tmp_path):
    manifest_path, root, _, _ = package(tmp_path)
    manifest_path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        delivery.validate_manifest(manifest_path, root)


def test_duplicate_json_keys_fail_closed():
    with pytest.raises(ValueError, match="duplicates JSON key"):
        delivery.parse_json(b'{"status":"complete","status":"failed"}', "manifest")
