import importlib.util
from pathlib import Path
import subprocess


MODULE_PATH = Path(__file__).with_name("run_crash_matrix.py")
SPEC = importlib.util.spec_from_file_location("run_crash_matrix", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_run_case_hashes_log_and_binds_single_phase(tmp_path, monkeypatch):
    observed = {}

    def fake_run(command, **kwargs):
        observed.update(kwargs["env"])
        kwargs["stdout"].write(b"checkpoint resumed to identical proof\n")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
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
    assert "--release" in result["command"]
    assert len(result["log_sha256"]) == 64
    assert Path(result["log_path"]).read_text() == "checkpoint resumed to identical proof\n"


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
        "truncation_and_checksum",
        "path_traversal",
        "symlink_rejection",
    }
