import hashlib
import importlib.util
import json
from pathlib import Path
import stat
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
    sbom = tmp_path / "tinyzkp-backend.spdx.json"
    sbom.write_text("{}", encoding="utf-8")
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text(f"{sha256(sbom)}  {sbom.name}\n", encoding="utf-8")
    try:
        module.verify_checksum_manifest(
            checksums, sbom, module.REQUIRED_CHECKSUM_ENTRIES
        )
    except ValueError as error:
        assert "omits required release artifacts" in str(error)
    else:
        raise AssertionError("partial release checksum manifest was accepted")


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
                "name": "tinyzkp-backend",
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
