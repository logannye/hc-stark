import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

import pytest


MODULE_PATH = Path(__file__).with_name("run_fixed_host_release_matrix.py")
SPEC = importlib.util.spec_from_file_location("run_fixed_host_release_matrix", MODULE_PATH)
assert SPEC and SPEC.loader
MATRIX = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MATRIX
SPEC.loader.exec_module(MATRIX)


RELEASE_SHA = "a" * 40


def test_matrix_is_the_exact_blocking_resource_matrix():
    assert [
        (
            entry.entry_id,
            entry.workload,
            entry.logical_rows,
            entry.mode,
            entry.gate,
            entry.report_name,
        )
        for entry in MATRIX.MATRIX
    ] == [
        (
            "fibonacci_1m",
            "fibonacci",
            1_048_576,
            "throughput",
            "one-million",
            "fibonacci-1m.json",
        ),
        (
            "poseidon2_1m",
            "poseidon2_goldilocks",
            1_048_576,
            "throughput",
            "one-million",
            "poseidon2-1m.json",
        ),
        (
            "fibonacci_16m",
            "fibonacci",
            16_777_216,
            "ceiling",
            "ten-million",
            "fibonacci-16m.json",
        ),
        (
            "poseidon2_16m",
            "poseidon2_goldilocks",
            16_777_216,
            "ceiling",
            "ten-million",
            "poseidon2-16m.json",
        ),
    ]


def test_exact_commands_preserve_fixed_host_and_release_gate_contract(tmp_path):
    scratch = Path("/var/lib/tinyzkp-bench/scratch")
    cgroup = Path("/sys/fs/cgroup/tinyzkp-bench")
    cli = Path("/opt/tinyzkp/hc-cli")

    for entry in MATRIX.MATRIX:
        paths = MATRIX.report_paths(entry, tmp_path)
        preflight = MATRIX.build_preflight_command(entry, scratch, cgroup, paths)
        benchmark = MATRIX.build_benchmark_command(entry, cli, cgroup, paths)
        gate = MATRIX.build_gate_command(entry, RELEASE_SHA, paths)

        assert preflight[-2:] == ["--output", str(paths["host_preflight"])]
        assert preflight[preflight.index("--scratch-dir") + 1] == str(
            scratch / entry.scratch_relative
        )
        assert "--require-fixed-host" in benchmark
        assert benchmark[benchmark.index("--mode") + 1] == entry.mode
        assert benchmark[benchmark.index("--report") + 1] == str(
            paths["candidate_report"]
        )
        assert gate[gate.index("--expected-release-sha") + 1] == RELEASE_SHA
        assert gate[gate.index("--gate") + 1] == entry.gate
        if entry.mode == "throughput":
            assert benchmark[-2:] == [
                "--baseline-memory-cap",
                str(16 * 1024**3),
            ]
            assert gate[-2:] == ["--baseline", str(paths["baseline_report"])]
        else:
            assert "--baseline-memory-cap" not in benchmark
            assert "--baseline" not in gate


def test_new_state_never_claims_release_or_external_gate_completion(tmp_path):
    cli = tmp_path / "hc-cli"
    cli.write_bytes(b"binary")
    state = MATRIX.new_state(
        RELEASE_SHA,
        "b" * 64,
        cli,
        {"release_sha": RELEASE_SHA},
        tmp_path / "reports",
        Path("/var/lib/tinyzkp-bench/scratch"),
        Path("/sys/fs/cgroup/tinyzkp-bench"),
    )

    assert state["release_eligible"] is False
    assert state["local_matrix_gates_passed"] is False
    assert all(value is False for value in state["authority"].values())
    assert all(
        value == "required_external" for value in state["external_gates"].values()
    )
    assert [entry["status"] for entry in state["entries"]] == ["pending"] * 4


def test_precheck_fails_before_collecting_metadata_off_linux(monkeypatch, tmp_path):
    called = False

    def collect(_path):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(MATRIX.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(MATRIX.HARNESS, "collect_host_metadata", collect)
    with pytest.raises(RuntimeError, match="requires Linux"):
        MATRIX.precheck_host(tmp_path / "scratch", tmp_path / "cgroup")
    assert called is False


def test_existing_matrix_state_must_already_be_owner_only(tmp_path):
    state = tmp_path / "state.json"
    state.write_text("{}", encoding="utf-8")
    state.chmod(0o644)
    with pytest.raises(ValueError, match="not owner-only"):
        MATRIX.require_owner_artifact(state, os.geteuid())


def test_release_sha_is_canonical_git_sha_only():
    assert MATRIX.validate_release_sha(RELEASE_SHA) == RELEASE_SHA
    for invalid in ("A" * 40, "a" * 39, "a" * 64, "release-main"):
        with pytest.raises(ValueError, match="40-character"):
            MATRIX.validate_release_sha(invalid)


def test_artifact_descriptor_detects_tampering_and_path_escape(tmp_path):
    output = tmp_path / "reports"
    output.mkdir(mode=0o700)
    report = output / "report.json"
    report.write_text("{}\n", encoding="utf-8")
    report.chmod(0o600)
    descriptor = MATRIX.artifact_descriptor("candidate_report", report, output)
    assert MATRIX.verify_artifact_descriptor(descriptor, output, os.geteuid()) == report

    report.write_text('{"changed":true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="metadata changed|digest changed"):
        MATRIX.verify_artifact_descriptor(descriptor, output, os.geteuid())

    escaped = dict(descriptor, path="../outside.json")
    with pytest.raises(ValueError, match="escapes"):
        MATRIX.verify_artifact_descriptor(escaped, output, os.geteuid())


def test_stable_snapshot_rejects_symlink_and_hardlink(tmp_path):
    original = tmp_path / "original.json"
    original.write_text("{}\n", encoding="utf-8")
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(original)
    with pytest.raises(ValueError, match="safely open"):
        MATRIX.stable_file_snapshot(symlink)

    hardlink = tmp_path / "hardlink.json"
    os.link(original, hardlink)
    with pytest.raises(ValueError, match="single-link"):
        MATRIX.stable_file_snapshot(original)


def test_stable_snapshot_rejects_path_replacement_during_read(monkeypatch, tmp_path):
    artifact = tmp_path / "artifact.json"
    replacement = tmp_path / "replacement.json"
    artifact.write_text('{"first":true}\n', encoding="utf-8")
    replacement.write_text('{"other":true}\n', encoding="utf-8")
    real_lstat = MATRIX._path_lstat
    calls = 0

    def replacing_lstat(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            os.replace(replacement, artifact)
        return real_lstat(path)

    monkeypatch.setattr(MATRIX, "_path_lstat", replacing_lstat)
    with pytest.raises(ValueError, match="replaced during read"):
        MATRIX.stable_file_snapshot(artifact)


def _eligible_host():
    return {
        "hardware": "fixed-host; logical_cpus=8",
        "logical_cpu_count": 8,
        "total_memory_bytes": 16 * 1024**3,
        "operating_system": "Linux-test",
        "storage_device": "259:1:nvme0n1p1",
        "storage_is_rotational": False,
        "storage_is_nvme": True,
        "storage_total_bytes": 1_000_000_000_000,
    }


def test_execute_resumes_only_revalidated_complete_entries(monkeypatch, tmp_path):
    output = tmp_path / "reports"
    scratch = tmp_path / "scratch"
    cgroup = tmp_path / "cgroup"
    cli = tmp_path / "hc-cli"
    cli.write_bytes(b"release-binary")
    cli.chmod(0o700)
    args = argparse.Namespace(
        output_dir=output,
        scratch_root=scratch,
        cgroup_parent=cgroup,
        hc_cli=cli,
        release_sha=RELEASE_SHA,
    )

    monkeypatch.setattr(MATRIX, "validate_source_identity", lambda _sha: "b" * 64)
    monkeypatch.setattr(
        MATRIX,
        "validate_cli_identity",
        lambda _cli, _sha: {
            "service": "cli",
            "release_sha": RELEASE_SHA,
            "backend": "plonky3",
        },
    )
    monkeypatch.setattr(MATRIX, "validate_matrix_manifest", lambda *_args: {})
    monkeypatch.setattr(MATRIX, "precheck_host", lambda *_args: _eligible_host())

    run_calls = []

    def run_entry(entry, **_kwargs):
        run_calls.append(entry.entry_id)
        return _eligible_host()

    monkeypatch.setattr(MATRIX, "run_entry", run_entry)
    monkeypatch.setattr(
        MATRIX,
        "descriptors_for_entry",
        lambda entry, *_args: [
            {
                "role": "synthetic",
                "path": f"{entry.entry_id}.json",
                "sha256": "0" * 64,
                "size_bytes": 1,
                "mode": 0o600,
            }
        ],
    )

    assert MATRIX.execute(args) == 0
    assert run_calls == [entry.entry_id for entry in MATRIX.MATRIX]
    state_path = output / "fixed-host-release-matrix-v1.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert state["status"] == "local_matrix_complete_external_gates_pending"
    assert state["local_matrix_gates_passed"] is True
    assert state["release_eligible"] is False

    revalidated = []
    monkeypatch.setattr(
        MATRIX,
        "revalidate_complete_entry",
        lambda entry, *_args: revalidated.append(entry.entry_id),
    )
    monkeypatch.setattr(
        MATRIX,
        "run_entry",
        lambda *_args, **_kwargs: pytest.fail("completed entries must not rerun"),
    )
    assert MATRIX.execute(args) == 0
    assert revalidated == [entry.entry_id for entry in MATRIX.MATRIX]


def test_loaded_state_rejects_any_release_authority_claim(tmp_path):
    cli = tmp_path / "hc-cli"
    cli.write_bytes(b"binary")
    output = tmp_path / "reports"
    scratch = Path("/var/lib/tinyzkp-bench/scratch")
    cgroup = Path("/sys/fs/cgroup/tinyzkp-bench")
    state = MATRIX.new_state(
        RELEASE_SHA,
        "b" * 64,
        cli,
        {"release_sha": RELEASE_SHA},
        output,
        scratch,
        cgroup,
    )
    state["authority"]["may_approve_backend_release"] = True
    with pytest.raises(ValueError, match="overstates"):
        MATRIX.validate_loaded_state(
            state,
            release_sha=RELEASE_SHA,
            source_tree_sha256="b" * 64,
            cli=cli,
            output_dir=output,
            scratch_root=scratch,
            cgroup_parent=cgroup,
        )
