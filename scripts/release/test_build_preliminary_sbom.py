import importlib.util
import json
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("build_preliminary_sbom.py")
SPEC = importlib.util.spec_from_file_location("build_preliminary_sbom", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


LOCK = b'''version = 4

[[package]]
name = "alpha"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "workspace-member"
version = "0.1.0"
'''


def test_preliminary_spdx_is_deterministic_and_lock_bound(tmp_path):
    lock = tmp_path / "Cargo.lock"
    lock.write_bytes(LOCK)
    first = MODULE.build_sbom(lock, release_sha="abc123", created="2026-07-10T00:00:00Z")
    second = MODULE.build_sbom(lock, release_sha="abc123", created="2026-07-10T00:00:00Z")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["spdxVersion"] == "SPDX-2.3"
    assert len(first["packages"]) == 2
    alpha = next(package for package in first["packages"] if package["name"] == "alpha")
    assert alpha["checksums"][0]["checksumValue"] == "a" * 64
    assert alpha["externalRefs"][0]["referenceLocator"] == "pkg:cargo/alpha@1.2.3"
    assert "abc123" in first["documentNamespace"]
    offset = MODULE.build_sbom(lock, release_sha="abc123", created="2026-07-09T17:00:00-07:00")
    assert offset["creationInfo"]["created"] == "2026-07-10T00:00:00Z"


def test_preliminary_spdx_rejects_ambiguous_identity_and_bad_lock_checksum(tmp_path):
    lock = tmp_path / "Cargo.lock"
    lock.write_bytes(LOCK.replace(b"a" * 64, b"not-a-checksum"))
    for release_sha, created in (("bad sha", "2026-07-10T00:00:00Z"), ("abc", "2026-07-10T00:00:00.1Z")):
        try:
            MODULE.build_sbom(lock, release_sha=release_sha, created=created)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid SBOM identity was accepted")
    try:
        MODULE.build_sbom(lock, release_sha="abc", created="2026-07-10T00:00:00Z")
    except ValueError as error:
        assert "checksum" in str(error)
    else:
        raise AssertionError("malformed Cargo.lock checksum was accepted")
