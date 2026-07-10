from __future__ import annotations

import json
from pathlib import Path

import pytest
from blake3 import blake3

from tinyzkp import (
    ArtifactError,
    ResourcePolicyV1,
    WorkloadManifestV1,
    canonical_json_v1,
    decode_base64url,
    load_bundle,
    load_manifest,
    load_report,
)


def policy(tmp_path) -> ResourcePolicyV1:
    return ResourcePolicyV1(
        mode="scratch",
        max_resident_bytes=128 * 1024 * 1024,
        max_scratch_bytes=2 * 1024 * 1024 * 1024,
        scratch_dir=str(tmp_path),
        max_threads=1,
        checkpoint_policy="retain_on_failure",
    )


def test_canonical_json_golden_vector():
    value = {"z": [3, {"b": True, "a": "value"}], "a": 1}
    encoded = canonical_json_v1(value)
    assert encoded == b'{"a":1,"z":[3,{"a":"value","b":true}]}'
    assert blake3(encoded).hexdigest() == (
        "75cb2762f02e1cf0c67805150ce6179cf7f05e6eb28e5353d5923dcccbf7598c"
    )


def test_manifest_round_trip_and_digest(tmp_path):
    manifest = WorkloadManifestV1.fibonacci(0, 1, 1024, policy(tmp_path))
    manifest.validate()
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")
    loaded = load_manifest(path)
    assert loaded == manifest
    assert loaded.digest_hex() == manifest.digest_hex()


def test_shared_manifest_vector_matches_rust_digest():
    root = Path(__file__).resolve().parents[3]
    manifest = load_manifest(root / "test-vectors/plonky3/fibonacci-16.manifest.json")
    assert manifest.digest_hex() == (
        "9d131602e27428ca290c5ca87d543d085873840e4dba22dd3d8074945e57efcd"
    )


def test_maximum_goldilocks_manifest_matches_rust_digest():
    root = Path(__file__).resolve().parents[3]
    manifest = load_manifest(
        root / "test-vectors/plonky3/fibonacci-max-field.manifest.json"
    )
    assert manifest.input_generator["initial_a"] == 18446744069414584320
    assert manifest.digest_hex() == (
        "d66d868441137e6db964add9d7e4a2164ca3a722c66e73cbf06c2a576efee653"
    )


def test_shared_bundle_fixture_and_fail_closed_mutations(tmp_path):
    root = Path(__file__).resolve().parents[3]
    fixture = root / "test-vectors/plonky3/fibonacci-16.bundle.json"
    bundle = load_bundle(fixture)
    assert bundle.provenance["dependency_profile"] == "tinyzkp-p3-goldilocks-v1"

    raw = json.loads(fixture.read_text(encoding="utf-8"))
    raw["proof_base64url"] = raw["proof_base64url"][:-1]
    truncated = tmp_path / "truncated.json"
    truncated.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ArtifactError):
        load_bundle(truncated)

    raw = json.loads(fixture.read_text(encoding="utf-8"))
    raw["provenance"]["dependency_profile"] = "unreviewed-profile"
    skewed = tmp_path / "skewed.json"
    skewed.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ArtifactError):
        load_bundle(skewed)

    raw = json.loads(fixture.read_text(encoding="utf-8"))
    raw["unknown"] = True
    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ArtifactError):
        load_bundle(unknown)


def test_shared_report_fixture_rejects_unknown_fields(tmp_path):
    root = Path(__file__).resolve().parents[3]
    fixture = root / "test-vectors/plonky3/benchmark-report-v1.json"
    assert load_report(fixture).mode == "bounded"
    raw = json.loads(fixture.read_text(encoding="utf-8"))
    raw["unbound_metric"] = 1
    path = tmp_path / "report.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ArtifactError):
        load_report(path)

    raw = json.loads(fixture.read_text(encoding="utf-8"))
    raw["benchmark_session_id"] = "not-a-session"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ArtifactError):
        load_report(path)

    raw = json.loads(fixture.read_text(encoding="utf-8"))
    raw["total_memory_bytes"] = 1 << 64
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ArtifactError):
        load_report(path)

    raw = json.loads(fixture.read_text(encoding="utf-8"))
    raw["storage_available_bytes"] = raw["storage_total_bytes"] + 1
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ArtifactError):
        load_report(path)

    raw = json.loads(fixture.read_text(encoding="utf-8"))
    raw["scratch_directory_mode"] = 0o755
    raw["scratch_owned_by_runner"] = False
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ArtifactError):
        load_report(path)


def test_unknown_version_and_non_power_of_two_rejected(tmp_path):
    manifest = WorkloadManifestV1.fibonacci(0, 1, 1000, policy(tmp_path))
    with pytest.raises(ArtifactError):
        manifest.validate()


def test_canonical_json_rejects_float():
    with pytest.raises(ArtifactError):
        canonical_json_v1({"value": 1.5})


def test_uint64_boundaries_reject_booleans_and_overflow(tmp_path):
    manifest = WorkloadManifestV1.fibonacci(True, 1, 16, policy(tmp_path))
    with pytest.raises(ArtifactError):
        manifest.validate()
    with pytest.raises(ArtifactError):
        canonical_json_v1({"value": 1 << 64})


def test_base64url_requires_canonical_unpadded_encoding():
    assert decode_base64url("AQID") == b"\x01\x02\x03"
    with pytest.raises(ArtifactError):
        decode_base64url("AQID=")
