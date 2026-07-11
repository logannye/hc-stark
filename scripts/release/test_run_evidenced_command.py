import importlib.util
from pathlib import Path
import sys

import pytest


MODULE_PATH = Path(__file__).with_name("run_evidenced_command.py")
SPEC = importlib.util.spec_from_file_location("run_evidenced_command", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def test_runner_has_only_fixed_gate_commands_and_timeouts():
    assert set(module.GATES) == {
        "clean_release_source",
        "plonky3_dependency_profile_pinned",
        "official_verifier_fibonacci",
        "official_verifier_poseidon2",
        "deterministic_cross_mode_proofs",
        "replacement_sdk_contracts",
    }
    for spec in module.GATES.values():
        assert spec["command"]
        assert isinstance(spec["timeout"], int) and spec["timeout"] > 0
        assert spec["parser"].endswith("_v1")


def test_evidence_runner_never_materializes_or_downloads_sdk_wheels():
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert "materialize_wheelhouse(" not in source
    assert "urlopen(" not in source
    assert "--sdk-python-wheelhouse" in source
    assert "--sdk-npm-tarballs" in source


def test_sdk_gate_uses_sealed_dependencies_and_direct_node_without_npm():
    gate = (MODULE_PATH.parents[1] / "ci" / "sdk_contract_gate.sh").read_text(encoding="utf-8")
    assert "TINYZKP_SEALED_PYTHON_WHEELS" in gate
    assert "TINYZKP_SEALED_NPM_TARBALLS" in gate
    assert "npm ci" not in gate
    assert "TINYZKP_NPM" not in gate
    assert '"$node_bin" "$typescript_root/node_modules/typescript/bin/tsc"' in gate
    assert "CARGO RUSTC" in gate


def test_output_parsers_reject_generic_success_text_and_duplicate_markers():
    assert module.parse_output(
        "clean_release_source", b"all tests passed\n"
    )["passed"] is False
    marker = b"PASS TinyZKP deterministic cross-mode proof vectors\n"
    assert module.parse_output("deterministic_cross_mode_proofs", marker)["passed"] is True
    assert module.parse_output("deterministic_cross_mode_proofs", marker * 2)["passed"] is False

    sdk_marker = b"PASS TinyZKP replacement SDK contracts\n"
    python_marker = (
        b"PASS TinyZKP locked Python SDK environment (10 wheels, "
        + b"a" * 64
        + b")\n"
    )
    npm_marker = (
        b"PASS TinyZKP locked TypeScript SDK environment (7 tarballs, "
        + b"b" * 64
        + b")\n"
    )
    parsed = module.parse_output("replacement_sdk_contracts", python_marker + npm_marker + sdk_marker)
    assert parsed["passed"] is True
    assert parsed["python_wheel_count"] == 10
    assert parsed["python_wheel_set_sha256"] == "a" * 64
    assert parsed["npm_tarball_count"] == 7
    assert parsed["npm_tarball_set_sha256"] == "b" * 64
    assert module.parse_output(
        "replacement_sdk_contracts", python_marker * 2 + npm_marker + sdk_marker
    )["passed"] is False


def test_run_rejects_unreviewed_commands_before_touching_outputs(tmp_path):
    with pytest.raises(ValueError, match="not allowlisted"):
        module.run(
            gate="printf-anything",
            release_sha="a" * 40,
            report_path=tmp_path / "report.json",
            log_path=tmp_path / "log",
            root=tmp_path,
        )
    assert not (tmp_path / "report.json").exists()
