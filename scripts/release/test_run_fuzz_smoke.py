import importlib.util
from pathlib import Path
import stat
import subprocess


MODULE_PATH = Path(__file__).with_name("run_fuzz_smoke.py")
SPEC = importlib.util.spec_from_file_location("run_fuzz_smoke", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_all_backend_fuzz_surfaces_are_included():
    assert MODULE.TARGETS == (
        "workload_manifest_v1",
        "proof_bundle_v1",
        "plonky3_proof_bytes_v1",
        "benchmark_report_v1",
        "checkpoint_manifest_v2",
        "challenger_snapshot_v1",
        "scratch_artifact_header_v1",
        "checkpoint_identity_v2",
        "resume_checkpoint_v2",
    )


def test_run_target_hashes_log_and_pins_nightly_command(tmp_path, monkeypatch):
    def fake_run(command, **kwargs):
        execution = Path(command[5])
        (execution / "new-coverage-unit").write_bytes(b"coverage")
        kwargs["stdout"].write(b"fuzz target passed\n")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(
        MODULE,
        "seed_payloads",
        lambda target: [bytes([index + 1]) * (index + 1) for index in range(26)],
    )
    result = MODULE.run_target(
        "proof_bundle_v1",
        seconds=5,
        rss_limit_mb=256,
        log_dir=tmp_path / "logs",
    )
    assert result["exit_status"] == 0
    assert result["command"][:4] == ["cargo", "+nightly", "fuzz", "run"]
    assert result["command"][5].endswith("execution-corpus/proof_bundle_v1")
    assert result["command"][6].endswith("smoke-corpus/proof_bundle_v1")
    assert result["smoke_seed_count"] == MODULE.SMOKE_SEED_LIMIT
    assert len(result["smoke_corpus_sha256"]) == 64
    assert len(result["log_sha256"]) == 64
    log_path = Path(result["log_path"])
    assert log_path.read_text() == "fuzz target passed\n"
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "logs").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "logs" / "smoke-corpus").stat().st_mode) == 0o700
    assert not (tmp_path / "logs" / "execution-corpus" / "proof_bundle_v1").exists()
    assert result["artifacts"] == []


def test_smoke_corpus_is_deterministic_and_rejects_symlinks(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(
        MODULE,
        "seed_payloads",
        lambda target: [bytes([index]) * (index + 1) for index in range(40)],
    )
    first = MODULE.prepare_smoke_corpus("checkpoint_manifest_v2", log_dir=tmp_path / "logs")
    second = MODULE.prepare_smoke_corpus("checkpoint_manifest_v2", log_dir=tmp_path / "logs")
    assert first[1:] == second[1:]

    destination = tmp_path / "logs" / "smoke-corpus" / "resume_checkpoint_v2"
    destination.symlink_to(tmp_path, target_is_directory=True)
    try:
        MODULE.prepare_smoke_corpus("resume_checkpoint_v2", log_dir=tmp_path / "logs")
    except ValueError as error:
        assert "unsafe" in str(error)
    else:
        raise AssertionError("symlinked fuzz corpus must fail closed")


def test_tracked_smoke_seeds_are_self_contained_and_bounded():
    for target in MODULE.TARGETS:
        seeds = MODULE.seed_payloads(target)
        assert seeds
        assert len(seeds) <= MODULE.SMOKE_SEED_LIMIT
        assert all(0 < len(seed) <= MODULE.MAX_SMOKE_SEED_BYTES for seed in seeds)
    assert MODULE.checkpoint_seed().startswith(b'{"artifacts":[]')


def test_tool_version_fails_closed(monkeypatch):
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, "missing\n"),
    )
    try:
        MODULE.tool_version(["cargo", "+nightly", "fuzz", "--version"])
    except RuntimeError as error:
        assert "unable to identify fuzz toolchain" in str(error)
    else:
        raise AssertionError("unidentified fuzz toolchain must fail closed")


def test_main_rejects_cargo_fuzz_version_skew(tmp_path, monkeypatch):
    monkeypatch.setattr(
        MODULE,
        "tool_version",
        lambda command: "cargo-fuzz 99.0.0" if command[0] == "cargo" else "rustc nightly",
    )
    try:
        MODULE.main(
            [
                "--seconds",
                "1",
                "--output",
                str(tmp_path / "report.json"),
                "--log-dir",
                str(tmp_path / "logs"),
            ]
        )
    except RuntimeError as error:
        assert "cargo-fuzz version mismatch" in str(error)
    else:
        raise AssertionError("cargo-fuzz version skew must fail before fuzzing")
