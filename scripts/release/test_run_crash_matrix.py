import importlib.util
from pathlib import Path
import stat


MODULE_PATH = Path(__file__).with_name("run_crash_matrix.py")
SPEC = importlib.util.spec_from_file_location("run_crash_matrix", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_run_case_hashes_log_and_binds_single_phase(tmp_path, monkeypatch):
    observed = {}

    def fake_run(command, **kwargs):
        observed.update(kwargs["environment"])
        kwargs["log"].write(
            b"tinyzkp-crash-proof phase=trace_lde "
            + b"resumed="
            + b"a" * 64
            + b" reference="
            + b"a" * 64
            + b"\n"
            + b"test bounded_prover::tests::"
            b"single_checkpoint_phase_from_environment_resumes_to_identical_proof_bytes ... ok\n"
            b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            b"59 filtered out; finished in 1.00s\n"
        )
        return 0, False

    monkeypatch.setattr(MODULE.evidence_runtime, "run_logged", fake_run)
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setenv("TINYZKP_DISK_FULL_SCRATCH", "/inherited/unsafe")
    monkeypatch.setenv("TINYZKP_FAIL_AFTER", "inherited")
    result = MODULE.run_case(
        "checkpoint_trace_lde",
        *MODULE.PHASE_TEST,
        log_dir=tmp_path / "logs",
        release=True,
        phase="trace_lde",
    )
    assert result["exit_status"] == 0
    assert result["phase"] == "trace_lde"
    assert observed["TINYZKP_SINGLE_CRASH_PHASE"] == "trace_lde"
    assert "TINYZKP_DISK_FULL_SCRATCH" not in observed
    assert "TINYZKP_FAIL_AFTER" not in observed
    assert result["selected_environment"] == {"TINYZKP_SINGLE_CRASH_PHASE": "trace_lde"}
    assert result["proof_blake3_hex"] == "a" * 64
    assert result["proof_bytes_equal"] is True
    assert MODULE.test_execution_passed(result["test_execution"])
    assert result["timed_out"] is False
    assert "--lib" in result["command"]
    assert "--release" in result["command"]
    assert len(result["log_sha256"]) == 64
    assert (tmp_path / "logs" / result["log_file"]).is_file()
    assert stat.S_IMODE((tmp_path / "logs").stat().st_mode) == 0o700
    assert (
        stat.S_IMODE((tmp_path / "logs" / result["log_file"]).stat().st_mode) == 0o600
    )


def test_run_case_rejects_symlinked_log_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    linked = tmp_path / "logs"
    linked.symlink_to(tmp_path, target_is_directory=True)
    try:
        MODULE.run_case(
            "checkpoint_trace",
            *MODULE.PHASE_TEST,
            log_dir=linked,
            release=True,
            phase="trace",
        )
    except ValueError as error:
        assert "symlink" in str(error)
    else:
        raise AssertionError("symlinked crash log directory was accepted")


def test_run_case_rejects_symlinked_parent_directory(tmp_path, monkeypatch):
    victim = tmp_path / "victim"
    victim.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(victim, target_is_directory=True)
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    try:
        MODULE.run_case(
            "checkpoint_trace",
            *MODULE.PHASE_TEST,
            log_dir=alias / "logs",
            release=True,
            phase="trace",
        )
    except ValueError as error:
        assert "symlink" in str(error)
    else:
        raise AssertionError("symlinked parent directory was accepted")


def test_test_execution_rejects_zero_or_different_tests():
    assert not MODULE.test_execution_passed(
        MODULE.parse_test_execution(
            b"running 0 tests\n"
            b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
            b"60 filtered out; finished in 0.00s\n",
            MODULE.PHASE_TEST[1],
        )
    )
    payload = (
        f"test {MODULE.PHASE_TEST[1]} ... ok\n"
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
        "59 filtered out; finished in 1.00s\n"
    ).encode()
    parsed = MODULE.parse_test_execution(payload, MODULE.PHASE_TEST[1])
    assert MODULE.test_execution_passed(parsed)
    assert parsed["exact_test_occurrences"] == 1
    assert parsed["result_summaries_after_exact_test"] == 1
    assert not MODULE.test_execution_passed(
        {**parsed, "exact_test_occurrences": True}
    )
    duplicate_summary = payload + (
        "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
        "0 filtered out; finished in 0.00s\n"
    ).encode()
    assert not MODULE.test_execution_passed(
        MODULE.parse_test_execution(duplicate_summary, MODULE.PHASE_TEST[1])
    )

    child_summary = (
        "test child ... ok\n"
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
        "0 filtered out; finished in 0.10s\n"
    ).encode()
    nested = MODULE.parse_test_execution(child_summary + payload, MODULE.PHASE_TEST[1])
    assert nested["result_summary_count"] == 2
    assert nested["result_summaries_after_exact_test"] == 1
    assert MODULE.test_execution_passed(nested)


def test_partial_matrix_expects_no_descriptor_bound_release_tools():
    assert MODULE.tool_descriptor_pairs([], ("cargo", "rustc"), partial=True) == ()
    try:
        MODULE.tool_descriptor_pairs([1], ("cargo", "rustc"), partial=True)
    except ValueError as error:
        assert "descriptor set is incomplete" in str(error)
    else:
        raise AssertionError("partial mode accepted an unexpected release descriptor")

    assert MODULE.tool_descriptor_pairs(
        [10, 11], ("cargo", "rustc"), partial=False
    ) == ((10, "cargo"), (11, "rustc"))
    try:
        MODULE.tool_descriptor_pairs([], ("cargo", "rustc"), partial=False)
    except ValueError as error:
        assert "descriptor set is incomplete" in str(error)
    else:
        raise AssertionError("release mode accepted missing tool descriptors")


def test_release_mode_requires_disk_full_contract():
    try:
        MODULE.main(
            ["--output", "raw-reports/report.json", "--log-dir", "raw-reports/logs"]
        )
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError("release crash evidence omitted the disk-full contract")


def test_disk_full_contract_rejects_an_arbitrary_host_directory(tmp_path):
    tmp_path.chmod(0o700)
    identity = {"release_sha": "a" * 40, "source_tree_sha256": "b" * 64}
    try:
        MODULE.create_disk_full_contract(tmp_path.absolute(), identity)
    except ValueError as error:
        if MODULE.sys.platform == "linux":
            assert "dedicated device" in str(error) or "mounted filesystem" in str(
                error
            )
        else:
            assert "supported only on Linux" in str(error)
    else:
        raise AssertionError(
            "an arbitrary host directory was accepted for disk filling"
        )


def test_disk_full_contract_requires_all_safety_mount_options():
    required = {"rw", "nodev", "nosuid", "noexec", "relatime"}
    assert MODULE.required_mount_options_present(required)
    for missing in ("rw", "nodev", "nosuid", "noexec"):
        assert not MODULE.required_mount_options_present(required - {missing})
    assert not MODULE.required_mount_options_present("rw,nodev,nosuid,noexec")


def test_disk_full_marker_requires_enospc_and_identical_resumed_proof():
    digest = b"a" * 64
    parsed = MODULE.parse_disk_full_marker(
        b"tinyzkp-disk-full-resume enospc=true resumed="
        + digest
        + b" reference="
        + digest
        + b"\n"
    )
    assert parsed == {
        "disk_full_enospc_observed": True,
        "proof_blake3_hex": "a" * 64,
        "reference_proof_blake3_hex": "a" * 64,
        "proof_bytes_equal": True,
    }
    assert (
        MODULE.parse_disk_full_marker(b"test passed\n")["disk_full_enospc_observed"]
        is False
    )
    assert (
        MODULE.parse_disk_full_marker(
            b"tinyzkp-disk-full-resume enospc=false resumed="
            + digest
            + b" reference="
            + digest
        )["disk_full_enospc_observed"]
        is False
    )
    duplicate = (
        b"tinyzkp-disk-full-resume enospc=true resumed="
        + digest
        + b" reference="
        + digest
        + b"\n"
    ) * 2
    assert (
        MODULE.parse_disk_full_marker(duplicate)["disk_full_enospc_observed"] is False
    )


def test_checkpoint_marker_requires_exactly_one_phase_and_matching_digests():
    digest = b"a" * 64
    marker = (
        b"tinyzkp-crash-proof phase=trace_lde resumed="
        + digest
        + b" reference="
        + digest
        + b"\n"
    )
    assert MODULE.parse_checkpoint_marker(marker) == {
        "observed_phase": "trace_lde",
        "proof_blake3_hex": "a" * 64,
        "reference_proof_blake3_hex": "a" * 64,
        "proof_bytes_equal": True,
    }
    assert MODULE.parse_checkpoint_marker(marker * 2)["observed_phase"] is None
    mismatched = marker.replace(b"reference=" + digest, b"reference=" + b"b" * 64)
    assert MODULE.parse_checkpoint_marker(mismatched)["proof_bytes_equal"] is False


def test_release_matrix_names_every_durable_phase_and_integrity_case():
    assert MODULE.PHASES == (
        "trace",
        "trace_lde",
        "trace_commitment",
        "quotient",
        "quotient_lde",
        "quotient_commitment",
        "openings",
        "fri_layer_0",
        "fri_layer_1",
        "fri_layer_2",
        "fri_layer_3",
        "fri_layer_4",
        "fri_layer_5",
        "proof_assembly",
    )
    assert {case[0] for case in MODULE.INTEGRITY_CASES} == {
        "saved_artifact_reuse",
        "corrupt_artifact_and_stale_identity",
        "cancellation_retention",
        "sigterm_checkpoint_resume",
        "truncation_and_checksum",
        "path_traversal",
        "symlink_rejection",
    }
