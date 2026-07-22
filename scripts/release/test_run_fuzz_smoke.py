import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tomllib


MODULE_PATH = Path(__file__).with_name("run_fuzz_smoke.py")
SPEC = importlib.util.spec_from_file_location("run_fuzz_smoke", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_all_backend_fuzz_surfaces_are_included():
    assert MODULE.FUZZ_TOOLCHAIN == "nightly-2026-04-15"
    assert MODULE.CARGO_FUZZ_VERSION == "cargo-fuzz 0.13.2"
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
        "air_package_v1",
        "trace_manifest_v1",
        "air_proof_bundle_v1",
        "zstd_trace_chunk_v1",
        "public_inputs_v1",
    )


def test_fuzz_manifest_is_an_explicit_standalone_workspace():
    manifest = tomllib.loads((MODULE.ROOT / "fuzz" / "Cargo.toml").read_text())
    assert manifest["workspace"] == {}
    bins = {entry["name"] for entry in manifest["bin"]}
    assert {"air_proof_bundle_v1", "public_inputs_v1"} <= bins
    assert {"hosted_proof_bundle_v1", "beta_api_request_v1"}.isdisjoint(bins)


def test_partial_diagnostics_do_not_require_release_descriptors(monkeypatch):
    MODULE.verify_opened_tool_descriptors([], ("a", "b", "c"))

    monkeypatch.setattr(
        MODULE.evidence_runtime,
        "_digest_descriptor",
        lambda descriptor: {10: "a", 11: "b", 12: "c"}[descriptor],
    )
    MODULE.verify_opened_tool_descriptors([10, 11, 12], ("a", "b", "c"))

    try:
        MODULE.verify_opened_tool_descriptors([10], ("a", "b", "c"))
    except RuntimeError as error:
        assert "descriptor set is incomplete" in str(error)
    else:
        raise AssertionError("a partial release descriptor set was accepted")


def test_partial_diagnostics_select_the_reviewed_nightly():
    environment = MODULE.fuzz_environment(
        {"PATH": "/safe/bin", "RUSTUP_TOOLCHAIN": "attacker-controlled"}
    )
    assert environment["RUSTUP_TOOLCHAIN"] == MODULE.FUZZ_TOOLCHAIN
    assert environment["PATH"] == "/safe/bin"


def test_run_target_hashes_log_and_pins_nightly_command(tmp_path, monkeypatch):
    def fake_run(command, **kwargs):
        if command[1] == "build":
            binary = Path(command[5]) / command[3] / "release" / command[6]
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"#!/bin/sh\nexit 0\n")
            binary.chmod(0o700)
            return 0, False
        execution = Path(command[6])
        (execution / "new-coverage-unit").write_bytes(b"coverage")
        kwargs["log"].write(
            b"#50\tDONE cov: 1 ft: 1 corp: 1/1b\n"
            b"Done 50 runs in 5 second(s)\n"
            b"stat::number_of_executed_units: 50\n"
            b"stat::peak_rss_mb: 32\n"
        )
        return 0, False

    monkeypatch.setattr(MODULE.evidence_runtime, "run_logged", fake_run)
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
        target_dir=tmp_path / "cargo-target",
        target_triple="x86_64-unknown-linux-gnu",
    )
    assert result["exit_status"] == 0
    assert result["build_command"][:2] == ["cargo-fuzz", "build"]
    assert result["build_command"][5] == "cargo-target"
    assert result["run_command"][6].endswith("execution-corpus/proof_bundle_v1")
    assert result["run_command"][7].endswith("smoke-corpus/proof_bundle_v1")
    assert result["fuzz_binary"]["path"].endswith(
        "cargo-target/x86_64-unknown-linux-gnu/release/proof_bundle_v1"
    )
    assert result["fuzz_binary"]["descriptor_execution"] is False
    assert len(result["fuzz_binary"]["sha256"]) == 64
    assert result["smoke_seed_count"] == MODULE.SMOKE_SEED_LIMIT
    assert len(result["smoke_corpus_sha256"]) == 64
    assert result["target_marker"] == MODULE.expected_target_marker(
        "proof_bundle_v1", result["smoke_corpus_sha256"]
    )
    assert len(result["log_sha256"]) == 64
    log_path = tmp_path / "logs" / result["log_file"]
    assert result["libfuzzer_done"] is True
    assert result["done_executed_units"] == 50
    assert result["libfuzzer_elapsed_seconds"] == 5
    assert result["executed_units"] == 50
    assert result["peak_rss_mb"] == 32
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "logs").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "logs" / "smoke-corpus").stat().st_mode) == 0o700
    assert not (tmp_path / "logs" / "execution-corpus" / "proof_bundle_v1").exists()
    assert result["artifacts"] == []


def test_run_target_rejects_transient_seed_corpus_mutation(tmp_path, monkeypatch):
    def fake_run(command, **kwargs):
        if command[1] == "build":
            binary = Path(command[5]) / command[3] / "release" / command[6]
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"#!/bin/sh\nexit 0\n")
            binary.chmod(0o700)
            return 0, False
        seed = next(Path(command[7]).iterdir())
        seed.write_bytes(b"mutated")
        return 1, False

    monkeypatch.setattr(MODULE.evidence_runtime, "run_logged", fake_run)
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "seed_payloads", lambda target: [b"seed"])
    try:
        MODULE.run_target(
            "proof_bundle_v1",
            seconds=1,
            rss_limit_mb=64,
            log_dir=tmp_path / "logs",
            target_dir=tmp_path / "cargo-target",
            target_triple="x86_64-unknown-linux-gnu",
        )
    except ValueError as error:
        assert "corpus changed" in str(error)
    else:
        raise AssertionError("mutated fuzz seed corpus was accepted")


def test_smoke_corpus_is_deterministic_and_rejects_symlinks(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(
        MODULE,
        "seed_payloads",
        lambda target: [bytes([index]) * (index + 1) for index in range(40)],
    )
    first = MODULE.prepare_smoke_corpus(
        "checkpoint_manifest_v2", log_dir=tmp_path / "logs"
    )
    second = MODULE.prepare_smoke_corpus(
        "checkpoint_manifest_v2", log_dir=tmp_path / "logs"
    )
    assert first[1:] == second[1:]

    destination = tmp_path / "logs" / "smoke-corpus" / "resume_checkpoint_v2"
    destination.symlink_to(tmp_path, target_is_directory=True)
    try:
        MODULE.prepare_smoke_corpus("resume_checkpoint_v2", log_dir=tmp_path / "logs")
    except ValueError as error:
        assert "symlink" in str(error)
    else:
        raise AssertionError("symlinked fuzz corpus must fail closed")


def test_smoke_corpus_rejects_symlinked_parent_without_deleting_victim(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "seed_payloads", lambda target: [b"seed"])
    victim = tmp_path / "victim"
    target = victim / "smoke-corpus" / "resume_checkpoint_v2"
    target.mkdir(parents=True)
    marker = target / "must-survive"
    marker.write_bytes(b"safe")
    alias = tmp_path / "alias"
    alias.symlink_to(victim, target_is_directory=True)
    try:
        MODULE.prepare_smoke_corpus("resume_checkpoint_v2", log_dir=alias)
    except ValueError as error:
        assert "symlink" in str(error)
    else:
        raise AssertionError("symlinked fuzz parent was accepted")
    assert marker.read_bytes() == b"safe"


def test_tracked_smoke_seeds_are_self_contained_and_bounded():
    for target in MODULE.TARGETS:
        seeds = MODULE.seed_payloads(target)
        assert seeds
        assert len(seeds) <= MODULE.SMOKE_SEED_LIMIT
        assert all(0 < len(seed) <= MODULE.MAX_SMOKE_SEED_BYTES for seed in seeds)
    assert MODULE.checkpoint_seed().startswith(b'{"artifacts":[]')
    air_bundle = json.loads(MODULE.air_proof_bundle_seed())
    assert air_bundle["air"]["profile"] == MODULE.PROFILE
    public_inputs = json.loads(MODULE.public_inputs_seed())
    assert public_inputs["air_digest_hex"] == MODULE.DECLARATIVE_AIR_DIGEST


def test_tool_version_fails_closed(monkeypatch):
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, "missing\n"),
    )
    try:
        MODULE.tool_version(["cargo", f"+{MODULE.FUZZ_TOOLCHAIN}", "fuzz", "--version"])
    except RuntimeError as error:
        assert "unable to identify fuzz toolchain" in str(error)
    else:
        raise AssertionError("unidentified fuzz toolchain must fail closed")


def test_libfuzzer_summary_requires_done_units_elapsed_and_peak_rss():
    assert MODULE.parse_libfuzzer_summary(b"fuzz target passed\n") is None
    payload = (
        b"#42 DONE cov: 1\n"
        b"Done 42 runs in 60 second(s)\n"
        b"stat::number_of_executed_units: 42\n"
        b"stat::peak_rss_mb: 12\n"
    )
    assert MODULE.parse_libfuzzer_summary(payload) == {
        "libfuzzer_done": True,
        "done_executed_units": 42,
        "libfuzzer_elapsed_seconds": 60,
        "executed_units": 42,
        "peak_rss_mb": 12,
    }
    assert (
        MODULE.parse_libfuzzer_summary(payload.replace(b"#42 DONE", b"#41 DONE"))
        is None
    )
    assert MODULE.parse_libfuzzer_summary(payload + payload) is None


def test_target_marker_is_exact_unique_and_corpus_bound():
    marker = MODULE.expected_target_marker("proof_bundle_v1", "a" * 64)
    payload = MODULE.target_marker_line(marker)
    assert MODULE.parse_target_marker(payload) == marker
    assert MODULE.parse_target_marker(payload * 2) is None
    assert (
        MODULE.parse_target_marker(payload.replace(b"a" * 64, b"b" * 64))
        != marker
    )
    assert MODULE.parse_target_marker(b"target passed\n") is None


def test_main_rejects_cargo_fuzz_version_skew(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    lock = tmp_path / "fuzz" / "Cargo.lock"
    lock.parent.mkdir()
    lock.write_bytes(b"lock")
    lock_digest = MODULE.hashlib.sha256(lock.read_bytes()).hexdigest()
    monkeypatch.setattr(
        MODULE.evidence_runtime,
        "release_source_identity",
        lambda *args, **kwargs: {
            "release_sha": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "dependency_lock_sha256": "c" * 64,
            "rust_toolchain_sha256": "d" * 64,
        },
    )
    monkeypatch.setattr(
        MODULE.evidence_runtime,
        "owner_ga_tool_policy",
        lambda *args, **kwargs: {"policy": "owner_only_ga_v1"},
    )
    monkeypatch.setattr(
        MODULE.evidence_runtime,
        "commit_file_sha256",
        lambda *args, **kwargs: lock_digest,
    )
    monkeypatch.setattr(
        MODULE.evidence_runtime,
        "executable_identity",
        lambda name, *args, **kwargs: {
            "path": f"/tool/{name}",
            "sha256": "e" * 64,
            "version": f"{name} nightly",
        },
    )
    monkeypatch.setattr(
        MODULE.evidence_runtime,
        "rustup_tool_path",
        lambda toolchain, name, **kwargs: Path(f"/tool/{name}"),
    )
    monkeypatch.setattr(
        MODULE,
        "tool_version",
        lambda command, environment=None: "cargo-fuzz 99.0.0",
    )
    try:
        MODULE.main(
            [
                "--seconds",
                "1",
                "--output",
                str(tmp_path / "report.json"),
                "--log-dir",
                str(tmp_path / "raw-reports" / "logs"),
                "--partial",
            ]
        )
    except RuntimeError as error:
        assert "cargo-fuzz version mismatch" in str(error)
    else:
        raise AssertionError("cargo-fuzz version skew must fail before fuzzing")
