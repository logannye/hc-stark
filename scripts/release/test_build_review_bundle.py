import importlib.util
import json
from pathlib import Path
import stat
import zipfile


MODULE_PATH = Path(__file__).with_name("build_review_bundle.py")
SPEC = importlib.util.spec_from_file_location("build_review_bundle", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_review_bundle_is_byte_deterministic(tmp_path):
    sbom = tmp_path / "preliminary.spdx.json"
    sbom.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "documentNamespace": "https://tinyzkp.com/spdx/test",
                "creationInfo": {"created": "2026-07-10T00:00:00Z"},
                "packages": [{"SPDXID": "SPDXRef-Package-test", "name": "test"}],
            }
        )
    )
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    optional = {"sbom": [sbom]}
    one = MODULE.build_bundle(output=first, release_sha="abc123", optional=optional)
    two = MODULE.build_bundle(output=second, release_sha="abc123", optional=optional)
    assert first.read_bytes() == second.read_bytes()
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert stat.S_IMODE(second.stat().st_mode) == 0o600
    assert one["bundle_sha256"] == two["bundle_sha256"]
    assert any(
        "HC_RELEASE_SHA=abc123 python3 scripts/release/run_fuzz_smoke.py" in command
        for command in one["reproduction_commands"]
    )
    assert sum("--require-fixed-host" in command for command in one["reproduction_commands"]) == 4
    with zipfile.ZipFile(first) as archive:
        assert "review-manifest.json" in archive.namelist()
        assert "docs/security/threat_model.md" in archive.namelist()
        assert "crates/hc-plonky3/src/bounded_prover.rs" in archive.namelist()
        assert "crates/hc-plonky3/src/fri.rs" in archive.namelist()
        assert "fuzz/fuzz_targets/resume_checkpoint_v2.rs" in archive.namelist()
        assert "fuzz/fuzz_targets/plonky3_proof_bytes_v1.rs" in archive.namelist()
        assert "fuzz/Cargo.lock" in archive.namelist()
        assert "clients/rust/Cargo.lock" in archive.namelist()
        assert "site/schemas/benchmark-report-v1.schema.json" in archive.namelist()
        assert "test-vectors/plonky3/benchmark-report-v1.json" in archive.namelist()
        assert "scripts/benchmark/run_plonky3_cgroup.py" in archive.namelist()
        assert "evidence/sbom/preliminary.spdx.json" in archive.namelist()


def test_review_bundle_requires_a_real_non_symlink_spdx_inventory(tmp_path):
    try:
        MODULE.build_bundle(output=tmp_path / "missing.zip", release_sha="abc123", optional={})
    except ValueError as error:
        assert "SBOM" in str(error)
    else:
        raise AssertionError("review bundle accepted a missing SBOM")

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{}")
    try:
        MODULE.build_bundle(
            output=tmp_path / "malformed.zip",
            release_sha="abc123",
            optional={"sbom": [malformed]},
        )
    except ValueError as error:
        assert "SPDX" in str(error)
    else:
        raise AssertionError("review bundle accepted malformed SPDX")

    valid = tmp_path / "valid.json"
    valid.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "documentNamespace": "https://tinyzkp.com/spdx/test",
                "creationInfo": {"created": "2026-07-10T00:00:00Z"},
                "packages": [{"SPDXID": "SPDXRef-Package-test", "name": "test"}],
            }
        )
    )
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(valid)
    try:
        MODULE.build_bundle(
            output=tmp_path / "symlink.zip",
            release_sha="abc123",
            optional={"sbom": [symlink]},
        )
    except ValueError as error:
        assert "unsafe" in str(error)
    else:
        raise AssertionError("review bundle accepted a symlinked SBOM")
