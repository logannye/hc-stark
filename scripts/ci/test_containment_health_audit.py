"""Compatibility checks for the retired audit entrypoint test location."""

import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/monitoring/api_health_audit.sh"
INSTALLER = ROOT / "deploy/macos/install_api_audit_launchagent.sh"


def run_mode(mode: str | None):
    env = os.environ.copy()
    if mode is None:
        env.pop("TINYZKP_AUDIT_MODE", None)
    else:
        env["TINYZKP_AUDIT_MODE"] = mode
    return subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )


def test_retired_containment_and_production_modes_fail_closed():
    for mode in ("containment", "production"):
        result = run_mode(mode)
        assert result.returncode == 2
        assert (
            "canonical, guard_prelaunch, guard_transition, guard_live, or guard_frozen"
            in result.stderr
        )


def test_missing_mode_fails_closed():
    result = run_mode(None)
    assert result.returncode == 2
    assert (
        "canonical, guard_prelaunch, guard_transition, guard_live, or guard_frozen"
        in result.stderr
    )


def test_macos_installer_deploys_matching_guard_auditor_and_atomic_migration():
    installer = INSTALLER.read_text(encoding="utf-8")
    assert "migrate_audit_env.py" in installer
    assert "guard_health_audit.py" in installer
    assert "containment_health_audit.py" not in installer
