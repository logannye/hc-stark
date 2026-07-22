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
        "air_job_contracts",
    }
    for spec in module.GATES.values():
        assert spec["command"]
        assert isinstance(spec["timeout"], int) and spec["timeout"] > 0
        assert spec["parser"].endswith("_v1")


def test_air_job_contract_gate_is_local_and_exact():
    spec = module.GATES["air_job_contracts"]
    assert spec["command"] == [
        "cargo",
        "test",
        "-p",
        "hc-cli",
        "--locked",
        "plonky3_air_job_contracts",
    ]
    assert spec["test"] == "plonky3_air_job_contracts"


def test_generic_gate_tool_versions_are_exact_and_closed():
    assert module.GENERIC_TOOL_VERSIONS == {
        "bash": "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)",
        "python3": "Python 3.12.13",
    }
    for name, version in module.GENERIC_TOOL_VERSIONS.items():
        assert module.owner_ga_generic_tool_identity_valid(name, {"version": version})
        assert module.generic_tool_version_valid(name, version)
        assert module.owner_ga_generic_tool_identity_valid(
            name, {"version": version + "\nextra detail"}
        )
        assert not module.owner_ga_generic_tool_identity_valid(
            name, {"version": version + ".1"}
        )
    assert not module.owner_ga_generic_tool_identity_valid("node", {"version": "v20"})
    assert not module.owner_ga_generic_tool_identity_valid("bash", {})
    assert not module.generic_tool_version_valid("python3", "Python 3.12.12")


def test_linux_rust_tool_versions_bind_release_commit_and_host():
    for name, expected in module.RUST_TOOL_VERSIONS.items():
        lines = [expected["first_line"]]
        lines.extend(
            f"{key}: {value}" for key, value in expected.items() if key != "first_line"
        )
        version = "\n".join(lines)
        assert module.rust_tool_version_valid(name, version)
        assert not module.rust_tool_version_valid(
            name,
            version.replace("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"),
        )
        assert not module.rust_tool_version_valid(name, version + "\nrelease: 1.95.0")


def test_output_parsers_reject_generic_success_text_and_duplicate_markers():
    assert (
        module.parse_output("clean_release_source", b"all tests passed\n")["passed"]
        is False
    )
    marker = b"PASS TinyZKP deterministic cross-mode proof vectors\n"
    assert (
        module.parse_output("deterministic_cross_mode_proofs", marker)["passed"] is True
    )
    assert (
        module.parse_output("deterministic_cross_mode_proofs", marker * 2)["passed"]
        is False
    )


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
