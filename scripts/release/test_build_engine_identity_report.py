import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile

import build_engine_identity_report as identity
import pytest


RELEASE_SHA = "a" * 40
RELEASE_REF = "backend-v1.0.0"


def canonical(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def descriptor(payload):
    return {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "size": len(payload),
    }


def layer_with_engine(payload: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member = tarfile.TarInfo("usr/local/bin/tinyzkp-engine")
        member.mode = 0o755
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def write_oci(path: Path, *, revision=RELEASE_SHA, engine_payload=b"engine"):
    config = canonical(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "User": identity.EXPECTED_USER,
                "WorkingDir": "/work",
                "Entrypoint": ["/usr/local/bin/tinyzkp-engine"],
                "Cmd": ["--help"],
                "Volumes": {"/scratch": {}, "/work": {}},
                "Labels": {
                    "org.opencontainers.image.source": identity.EXPECTED_SOURCE,
                    "org.opencontainers.image.revision": revision,
                    "org.opencontainers.image.version": RELEASE_REF,
                    "org.opencontainers.image.tinyzkp.profile": identity.PROFILE,
                },
            },
        }
    )
    config_descriptor = descriptor(config)
    layer = layer_with_engine(engine_payload)
    layer_descriptor = {
        **descriptor(layer),
        "mediaType": "application/vnd.oci.image.layer.v1.tar",
    }
    manifest = canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config_descriptor,
            "layers": [layer_descriptor],
        }
    )
    manifest_descriptor = {
        **descriptor(manifest),
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "platform": {"architecture": "amd64", "os": "linux"},
    }
    files = {
        "oci-layout": canonical({"imageLayoutVersion": "1.0.0"}),
        "index.json": canonical(
            {"schemaVersion": 2, "manifests": [manifest_descriptor]}
        ),
        f"blobs/sha256/{config_descriptor['digest'][7:]}": config,
        f"blobs/sha256/{layer_descriptor['digest'][7:]}": layer,
        f"blobs/sha256/{manifest_descriptor['digest'][7:]}": manifest,
    }
    with tarfile.open(path, "w") as archive:
        for name, payload in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))


def write_inputs(root: Path):
    engine = root / "release-artifacts" / "tinyzkp-engine-linux-x86_64"
    engine.parent.mkdir()
    engine.write_bytes(b"engine")
    engine.chmod(0o755)
    release = root / "release-artifacts" / "engine-release.json"
    release.write_text(
        json.dumps(
            {
                "service": "cli",
                "package_version": "0.1.0",
                "release_sha": RELEASE_SHA,
                "release_ref": RELEASE_REF,
                "backend": "plonky3",
                "plonky3_version": "0.6.1",
                "compatibility_profile": identity.PROFILE,
                "dependency_lock_sha256": "b" * 64,
            }
        )
    )
    compatibility = root / "release-artifacts" / "plonky3-compatibility-v1.json"
    compatibility.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "profile_id": identity.PROFILE,
                "release_status": "reviewed",
                "cargo_lock_sha256": "b" * 64,
                "upstream": {"tag": "v0.6.1"},
            }
        )
    )
    oci = root / "release-artifacts" / "tinyzkp-engine.oci.tar"
    write_oci(oci)
    return engine, release, oci, compatibility


def test_report_binds_cli_oci_and_compatibility_artifacts(tmp_path):
    engine, release, oci, compatibility = write_inputs(tmp_path)
    report = identity.build_report(
        root=tmp_path,
        release_sha=RELEASE_SHA,
        release_ref=RELEASE_REF,
        engine=engine,
        engine_release=release,
        oci_archive=oci,
        compatibility_manifest=compatibility,
        checked_at="2026-01-01T00:00:00Z",
    )

    assert set(report["surfaces"]) == {"engine_cli", "engine_oci"}
    assert report["surfaces"]["engine_cli"]["artifact"] == (
        "release-artifacts/tinyzkp-engine-linux-x86_64"
    )
    assert report["surfaces"]["engine_oci"]["platform"] == "linux/amd64"
    assert (
        report["surfaces"]["engine_oci"]["embedded_engine_sha256"]
        == hashlib.sha256(b"engine").hexdigest()
    )
    assert report["compatibility"]["profile_id"] == identity.PROFILE


def test_report_rejects_oci_release_skew(tmp_path):
    engine, release, oci, compatibility = write_inputs(tmp_path)
    write_oci(oci, revision="c" * 40)
    with pytest.raises(ValueError, match="runtime identity"):
        identity.build_report(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            release_ref=RELEASE_REF,
            engine=engine,
            engine_release=release,
            oci_archive=oci,
            compatibility_manifest=compatibility,
        )


def test_report_rejects_different_binary_inside_oci(tmp_path):
    engine, release, oci, compatibility = write_inputs(tmp_path)
    write_oci(oci, engine_payload=b"different-engine")
    with pytest.raises(ValueError, match="embedded engine digest differs"):
        identity.build_report(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            release_ref=RELEASE_REF,
            engine=engine,
            engine_release=release,
            oci_archive=oci,
            compatibility_manifest=compatibility,
        )


def test_atomic_report_is_owner_only(tmp_path):
    output = tmp_path / "identity.json"
    identity.write_json_atomic(output, {"status": "ready"})
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
