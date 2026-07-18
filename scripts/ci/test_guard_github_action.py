from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / ".github" / "actions" / "tinyzkp-guard"


def test_action_is_thin_and_never_handles_license_keys() -> None:
    metadata = (ACTION / "action.yml").read_text(encoding="utf-8")
    script = (ACTION / "run.sh").read_text(encoding="utf-8")
    assert "using: composite" in metadata
    assert "license" not in metadata.lower()
    assert "activate" not in script
    assert "doctor --job" in script
    assert "run --job" in script
    assert "policy check" in script
    assert "curl" not in script


def test_action_shell_is_syntactically_valid() -> None:
    subprocess.run(["bash", "-n", str(ACTION / "run.sh")], check=True)


def test_action_rejects_invalid_run_flag_without_invoking_guard(tmp_path: Path) -> None:
    result = subprocess.run(
        [str(ACTION / "run.sh")],
        cwd=tmp_path,
        env={
            "TINYZKP_ACTION_GUARD": "/does/not/exist",
            "TINYZKP_ACTION_JOB": "job.json",
            "TINYZKP_ACTION_RUN": "yes",
            "TINYZKP_ACTION_REPORT": "report.json",
            "TINYZKP_ACTION_BASELINE": "",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 11
    assert result.stderr == "run-proof must be true or false\n"
