import io
from pathlib import Path
import tarfile

import pytest

import extract_public_beta_evidence as extractor


def archive(path: Path, members: dict[str, bytes | None]) -> None:
    with tarfile.open(path, "w:gz") as bundle:
        for name, payload in members.items():
            item = tarfile.TarInfo(name)
            if payload is None:
                item.type = tarfile.DIRTYPE
                bundle.addfile(item)
            else:
                item.size = len(payload)
                bundle.addfile(item, io.BytesIO(payload))


def test_extracts_private_repository_local_evidence(tmp_path):
    payload = tmp_path / "evidence.tar.gz"
    archive(
        payload,
        {
            "release-evidence/": None,
            "release-evidence/public-beta-evidence.json": b"{}\n",
            "release-evidence/artifacts/ci.json": b"{}\n",
        },
    )
    manifest = extractor.extract(payload, tmp_path)
    assert manifest == tmp_path / "release-evidence/public-beta-evidence.json"
    assert (tmp_path / "release-evidence/artifacts/ci.json").read_bytes() == b"{}\n"
    assert (manifest.stat().st_mode & 0o777) == 0o600


@pytest.mark.parametrize(
    "name",
    ["../escape", "/absolute", "release-evidence/../escape", "other/file"],
)
def test_rejects_paths_outside_release_evidence(tmp_path, name):
    payload = tmp_path / "evidence.tar.gz"
    archive(payload, {name: b"unsafe"})
    with pytest.raises(ValueError, match="unsafe path"):
        extractor.extract(payload, tmp_path)
    assert not (tmp_path / "release-evidence").exists()


def test_rejects_symlinks(tmp_path):
    payload = tmp_path / "evidence.tar.gz"
    with tarfile.open(payload, "w:gz") as bundle:
        item = tarfile.TarInfo("release-evidence/link")
        item.type = tarfile.SYMTYPE
        item.linkname = "/etc/passwd"
        bundle.addfile(item)
    with pytest.raises(ValueError, match="link or device"):
        extractor.extract(payload, tmp_path)
