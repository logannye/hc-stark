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


def test_only_known_answers_gate_has_exact_external_write_boundary():
    for gate, spec in module.GATES.items():
        paths = module.external_writable_paths(spec)
        if gate == "deterministic_cross_mode_proofs":
            assert paths == module.KAT_EXTERNAL_WRITABLE_PATHS
            assert module.writable_path_names(spec) == [
                "cargo-target",
                "gate-work",
                "tmp",
                "tinyzkp-kat-fibonacci-16",
                "tinyzkp-kat-poseidon2-8",
            ]
        else:
            assert paths == ()
            assert module.writable_path_names(spec) == [
                "cargo-target",
                "gate-work",
                "tmp",
            ]


def test_external_write_boundary_is_private_collision_safe_and_removed(tmp_path):
    paths = (tmp_path / "first", tmp_path / "second")
    prepared = module._prepare_external_writable_paths(paths, allowed_paths=paths)
    assert prepared == paths
    assert all(
        path.is_dir() and (path.stat().st_mode & 0o777) == 0o700 for path in paths
    )
    module._cleanup_external_writable_paths(prepared, allowed_paths=paths)
    assert all(not path.exists() for path in paths)

    paths[0].mkdir(mode=0o700)
    sentinel = paths[0] / "owner-data"
    sentinel.write_text("do not remove", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        module._prepare_external_writable_paths(paths, allowed_paths=paths)
    assert sentinel.read_text(encoding="utf-8") == "do not remove"


def test_external_write_boundary_rejects_unlisted_paths(tmp_path):
    allowed = (tmp_path / "allowed",)
    with pytest.raises(ValueError, match="not exactly allowlisted"):
        module._prepare_external_writable_paths(
            (tmp_path / "different",), allowed_paths=allowed
        )
    assert not (tmp_path / "different").exists()


def test_air_job_contract_gate_is_local_and_exact():
    spec = module.GATES["air_job_contracts"]
    assert spec["command"] == [
        "cargo",
        "test",
        "-p",
        "hc-cli",
        "--locked",
        "plonky3_air_job_contracts",
        "--",
        "--exact",
    ]
    assert spec["test"] == "plonky3_air_job_contracts"


def test_cargo_test_gates_bind_the_exact_parser_identity():
    for gate in (
        "official_verifier_fibonacci",
        "official_verifier_poseidon2",
        "air_job_contracts",
    ):
        spec = module.GATES[gate]
        assert spec["command"][-3:] == [spec["test"], "--", "--exact"]


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
