import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile

import pytest

import verify_sdk_npm_tarballs as npm


def archive(*, name="safe", member_type="file", duplicate=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        metadata = json.dumps({"name": "safe", "version": "1.0.0"}).encode()
        info = tarfile.TarInfo("package/package.json")
        info.size = len(metadata)
        tar.addfile(info, io.BytesIO(metadata))
        info = tarfile.TarInfo(f"package/{name}")
        if member_type == "symlink":
            info.type = tarfile.SYMTYPE
            info.linkname = "package/package.json"
            tar.addfile(info)
        else:
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
            if duplicate:
                second = tarfile.TarInfo(f"package/{name}")
                second.size = 1
                tar.addfile(second, io.BytesIO(b"y"))
    payload = output.getvalue()
    return payload, {
        "name": "safe",
        "version": "1.0.0",
        "filename": "safe-1.0.0.tgz",
        "archive_root": "package",
        "url": "https://registry.npmjs.org/safe/-/safe-1.0.0.tgz",
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "integrity": "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode(),
    }


def test_tar_validator_rejects_traversal_links_and_duplicates():
    for kwargs in (
        {"name": "../escape"},
        {"member_type": "symlink"},
        {"duplicate": True},
    ):
        payload, record = archive(**kwargs)
        with pytest.raises(ValueError):
            npm.verify_tarball_bytes(payload, record)


def test_worktree_manifest_binds_exact_package_roots_and_lock():
    identity = npm.worktree_lock_identity(npm.ROOT)
    assert identity["tarball_count"] == 7
    package = json.loads((npm.ROOT / "clients/typescript/package.json").read_text())
    assert package["devDependencies"]["@types/node"] == "20.19.39"
    assert package["devDependencies"]["typescript"] == "5.9.3"


def test_materializer_has_no_proxy_or_redirect_fallback():
    source = Path(npm.__file__).read_text(encoding="utf-8")
    assert "ProxyHandler({})" in source
    assert "redirects are forbidden" in source
    assert "extractall(" not in source
