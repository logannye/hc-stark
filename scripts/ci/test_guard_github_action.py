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
    assert '"${TINYZKP_ACTION_GUARD}" run' in script
    assert '--job "${TINYZKP_ACTION_JOB}"' in script
    assert '"${TINYZKP_ACTION_GUARD}" resume' in script
    assert "policy check" in script
    assert "curl" not in script


def test_action_shell_is_syntactically_valid() -> None:
    subprocess.run(["bash", "-n", str(ACTION / "run.sh")], check=True)


def test_action_rejects_invalid_operation_without_invoking_guard(tmp_path: Path) -> None:
    result = subprocess.run(
        [str(ACTION / "run.sh")],
        cwd=tmp_path,
        env={
            "TINYZKP_ACTION_OPERATION": "invalid",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 11
    assert result.stderr == "operation must be one of: doctor, run, resume, policy\n"
