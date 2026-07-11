from __future__ import annotations

from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import zipfile

import pytest

import verify_sdk_python_wheelhouse as wheelhouse


def documents() -> tuple[bytes, bytes, bytes, bytes]:
    root = wheelhouse.ROOT
    return (
        (root / wheelhouse.LOCK_PATH).read_bytes(),
        (root / wheelhouse.REQUIREMENTS_PATH).read_bytes(),
        (root / wheelhouse.MANIFEST_PATH).read_bytes(),
        (root / wheelhouse.PYPROJECT_PATH).read_bytes(),
    )


def canonical(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"


def resign_lock(
    lock_payload: bytes,
    requirements_payload: bytes,
    manifest_payload: bytes,
    pyproject_payload: bytes,
) -> bytes:
    lock = json.loads(lock_payload)
    lock["requirements_sha256"] = hashlib.sha256(requirements_payload).hexdigest()
    lock["wheelhouse_manifest_sha256"] = hashlib.sha256(manifest_payload).hexdigest()
    lock["pyproject_sha256"] = hashlib.sha256(pyproject_payload).hexdigest()
    return canonical(lock)


def test_current_worktree_lock_is_complete_and_canonical():
    identity = wheelhouse.worktree_lock_identity()
    assert identity["target"] == wheelhouse.TARGET
    assert identity["packages"] == wheelhouse.EXPECTED_PACKAGES
    assert identity["wheel_count"] == 10
    assert identity["wheel_bytes"] == 4_008_859
    assert len(identity["wheel_set_sha256"]) == 64


def test_old_environment_flag_cannot_bypass_requirement_mutation(monkeypatch):
    monkeypatch.setenv("TINYZKP_HASH_LOCKED_PYTHON_WHEELHOUSE", "1")
    lock, requirements, manifest, pyproject = documents()
    with pytest.raises(ValueError, match="digest-skewed"):
        wheelhouse.validate_lock_documents(
            lock, requirements + b"# mutation\n", manifest, pyproject
        )


def test_manual_status_and_unknown_fields_are_rejected():
    lock, requirements, manifest, pyproject = documents()
    value = json.loads(lock)
    value["status"] = "ready"
    with pytest.raises(ValueError, match="missing or unknown"):
        wheelhouse.validate_lock_documents(
            canonical(value), requirements, manifest, pyproject
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["wheels"][0].update(url="https://example.com/x.whl"),
        lambda value: value["wheels"][0].update(bytes=True),
        lambda value: value["wheels"][0].update(filename="../escape.whl"),
        lambda value: value["wheels"].append(value["wheels"][0]),
        lambda value: value["wheels"].reverse(),
    ],
)
def test_manifest_url_type_path_duplicate_and_order_mutations_fail(mutation):
    lock, requirements, manifest, pyproject = documents()
    value = json.loads(manifest)
    mutation(value)
    changed = canonical(value)
    changed_lock = resign_lock(lock, requirements, changed, pyproject)
    with pytest.raises(ValueError):
        wheelhouse.validate_lock_documents(
            changed_lock, requirements, changed, pyproject
        )


def test_pyproject_root_drift_fails_even_when_its_digest_is_updated():
    lock, requirements, manifest, pyproject = documents()
    changed = pyproject.replace(b"pytest==8.4.2", b"pytest>=7", 1)
    changed_lock = resign_lock(lock, requirements, manifest, changed)
    with pytest.raises(ValueError, match="dependency roots"):
        wheelhouse.validate_lock_documents(
            changed_lock, requirements, manifest, changed
        )


def synthetic_wheel(*, unsafe_name: str | None = None) -> tuple[bytes, dict[str, object]]:
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "demo-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nRequires-Python: >=3.9\n\n",
        )
        archive.writestr(
            "demo-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
        )
        archive.writestr("demo-1.0.dist-info/RECORD", "")
        archive.writestr(unsafe_name or "demo/__init__.py", "")
    payload = output.getvalue()
    descriptor = {
        "distribution": "demo",
        "version": "1.0",
        "filename": "demo-1.0-py3-none-any.whl",
        "url": "https://files.pythonhosted.org/packages/00/demo-1.0-py3-none-any.whl",
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "tags": ["py3-none-any"],
        "requires_python": ">=3.9",
        "requires_dist": [],
    }
    return payload, descriptor


def test_wheel_metadata_and_safe_zip_are_verified():
    payload, descriptor = synthetic_wheel()
    wheelhouse.verify_wheel_payload(payload, descriptor)
    descriptor["version"] = "2.0"
    with pytest.raises(ValueError, match="metadata differs"):
        wheelhouse.verify_wheel_payload(payload, descriptor)


def test_wheel_zip_traversal_is_rejected():
    payload, descriptor = synthetic_wheel(unsafe_name="../escape")
    with pytest.raises(ValueError, match="unsafe entry"):
        wheelhouse.verify_wheel_payload(payload, descriptor)


def test_wheelhouse_rejects_extra_files_and_symlinks(tmp_path):
    payload, descriptor = synthetic_wheel()
    tmp_path.chmod(0o700)
    candidate = tmp_path / str(descriptor["filename"])
    candidate.write_bytes(payload)
    candidate.chmod(0o400)
    identity = {"wheels": [descriptor], "schema_version": 1}
    wheelhouse.verify_wheelhouse(tmp_path, identity)
    extra = tmp_path / "extra.whl"
    extra.write_bytes(b"extra")
    with pytest.raises(ValueError, match="missing or extra"):
        wheelhouse.verify_wheelhouse(tmp_path, identity)
    extra.unlink()
    candidate.chmod(0o600)
    candidate.unlink()
    os.symlink("missing", candidate)
    with pytest.raises(ValueError):
        wheelhouse.verify_wheelhouse(tmp_path, identity)


def test_committed_identity_reads_only_fixed_paths():
    payloads = dict(
        zip(
            (
                wheelhouse.LOCK_PATH,
                wheelhouse.REQUIREMENTS_PATH,
                wheelhouse.MANIFEST_PATH,
                wheelhouse.PYPROJECT_PATH,
            ),
            documents(),
            strict=True,
        )
    )
    requested: list[str] = []

    def read_blob(_root: Path, _release: str, relative: str) -> bytes:
        requested.append(relative)
        return payloads[relative]

    identity = wheelhouse.committed_lock_identity(Path("/tmp"), "a" * 40, read_blob)
    assert requested == [
        wheelhouse.LOCK_PATH,
        wheelhouse.REQUIREMENTS_PATH,
        wheelhouse.MANIFEST_PATH,
        wheelhouse.PYPROJECT_PATH,
    ]
    assert identity["packages"] == wheelhouse.EXPECTED_PACKAGES
