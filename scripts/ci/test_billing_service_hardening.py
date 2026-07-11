import datetime as dt
import json
import os
from pathlib import Path
import shlex
import sqlite3
import stat
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "billing"))

import evaluation_store  # noqa: E402


@pytest.mark.parametrize("relative", ["deploy/hetzner/deploy.sh", "deploy/hetzner/setup.sh"])
def test_billing_webhook_is_non_root_and_owner_only(relative):
    text = (ROOT / relative).read_text(encoding="utf-8")
    for marker in (
        "User=tinyzkp-billing",
        "Group=tinyzkp-billing",
        "UMask=0077",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ReadWritePaths=/opt/hc-stark/data",
        "ensure-service-data-root --path /opt/hc-stark/data",
        "/var/lib/tinyzkp-private/billing",
    ):
        assert marker in text
    assert "chown -R tinyzkp-billing" not in text


def test_setup_and_deploy_install_one_canonical_backup_and_retention_schedule():
    commands = {}
    for relative in ("deploy/hetzner/setup.sh", "deploy/hetzner/deploy.sh"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        backup = [
            line
            for line in text.splitlines()
            if line.startswith("0 2 ") and "/billing/backup.sh" in line
        ]
        retention = [
            line for line in text.splitlines() if "purge-expired --apply" in line
        ]
        assert len(backup) == 1
        assert len(retention) == 1
        assert "rm -f /etc/cron.d/hc-backup" in text
        commands[relative] = (backup[0], retention[0])

    assert commands["deploy/hetzner/setup.sh"] == commands[
        "deploy/hetzner/deploy.sh"
    ]


@pytest.mark.parametrize("relative", ["deploy/hetzner/deploy.sh", "deploy/hetzner/setup.sh"])
def test_recovery_cron_enforces_application_retention(relative):
    text = (ROOT / relative).read_text(encoding="utf-8")
    assert "evaluation_intake.py" in text
    assert "purge-expired --apply" in text
    retention_line = next(
        line for line in text.splitlines() if "purge-expired --apply" in line
    )
    fields = retention_line.split(maxsplit=6)
    assert fields[:5] == ["17", "3", "*", "*", "*"]
    assert fields[5] == "tinyzkp-billing"
    assert "umask 077" in retention_line
    assert ">> /opt/hc-stark/data/evaluation-retention.log" in retention_line
    assert ">> /var/log/hc-evaluation-retention.log" not in retention_line
    assert "lifecycle_nudges.py" not in text
    assert "checkout_recovery.py" not in text


def test_retention_command_purges_as_ledger_owner_in_subprocess(tmp_path):
    """Faithfully exercise cron's same-owner and private-log contract in CI."""
    db_path = tmp_path / "data" / "evaluation_applications.sqlite"
    expired_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=366)
    application_id = evaluation_store.create_application(
        name="Retention probe",
        email="",
        category="General Inquiry",
        message="Expired no-email retention probe",
        qualification={
            "contact_method": "github",
            "contact_handle": "https://tinyzkp.com/status",
            "consent": "twelve_month_retention",
        },
        path=db_path,
        now=expired_at,
    )
    assert db_path.stat().st_uid == os.geteuid()

    log_path = tmp_path / "data" / "evaluation-retention.log"
    command = " ".join(
        [
            "umask 077; exec",
            shlex.quote(sys.executable),
            shlex.quote(str(ROOT / "billing" / "evaluation_intake.py")),
            "--db",
            shlex.quote(str(db_path)),
            "purge-expired --apply",
            ">>",
            shlex.quote(str(log_path)),
            "2>&1",
        ]
    )
    completed = subprocess.run(
        ["/bin/sh", "-c", command],
        cwd=ROOT,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
    result = json.loads(log_path.read_text(encoding="utf-8"))
    assert result == {"apply": True, "deleted": 1}
    assert evaluation_store.get_application(application_id, path=db_path) is None


def test_documented_operator_can_open_root_owned_contract_ledger(tmp_path):
    billing_dir = tmp_path / "tinyzkp-private" / "billing"
    billing_dir.mkdir(mode=0o700, parents=True)
    billing_dir.chmod(0o700)
    ledger = billing_dir / "contract_billing.sqlite"
    program = (
        "import sys; from pathlib import Path; "
        f"sys.path.insert(0, {str(ROOT / 'billing')!r}); "
        "import contract_billing; "
        f"connection = contract_billing.open_billing_ledger(Path({str(ledger)!r})); "
        "connection.close()"
    )

    completed = subprocess.run(
        [sys.executable, "-c", program],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert ledger.stat().st_uid == os.geteuid()
    assert stat.S_IMODE(ledger.stat().st_mode) == 0o600
    with sqlite3.connect(ledger) as connection:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name = 'billing_operations'"
        ).fetchone()
    assert table == ("billing_operations",)


def test_deploy_requires_complete_preflight_evidence_before_any_mutation():
    deploy = (ROOT / "deploy" / "hetzner" / "deploy.sh").read_text(encoding="utf-8")
    evidence_check = deploy.index("--verify-evidence")

    assert 'PREFLIGHT_EVIDENCE="/var/lib/tinyzkp-private/deploy/production-preflight.json"' in deploy
    assert 'PAGES_BINDINGS_FILE="/var/lib/tinyzkp-private/deploy/pages-bindings.env"' in deploy
    commands = {line.strip() for line in deploy.splitlines() if line.strip()}
    assert not any(line.startswith("git fetch") for line in commands)
    assert not any(line.startswith("git checkout") for line in commands)
    assert not any(line.startswith("git pull") for line in commands)
    assert evidence_check < deploy.index("sync_host_billing_services() {")
    assert "install_billing_runtime.sh" not in deploy
    assert "--expected-release-sha \"$RELEASE_SHA\"" in deploy
    assert "scripts/ci/run_production_preflight.sh" in deploy[:evidence_check]
    assert "TINYZKP_CLEAN_LAUNCH=1" in deploy.splitlines()[0]
    assert '"${COMPOSE[@]}" up -d --no-build' in deploy
    assert '"${COMPOSE[@]}" build' not in deploy
    assert "--consume-evidence" in deploy
    assert deploy.index('PATH="/usr/sbin:/usr/bin:/sbin:/bin"') < evidence_check
    assert 'install -d -o root -g root -m 0700 /opt/hc-stark/backups' in deploy


def test_production_launchers_and_docker_context_fail_closed():
    for relative in (
        "deploy/hetzner/deploy.sh",
        "deploy/hetzner/install_billing_runtime.sh",
        "scripts/ci/run_production_preflight.sh",
    ):
        first = (ROOT / relative).read_text(encoding="utf-8").splitlines()[0]
        assert "/usr/bin/env -S -i" in first
        assert "TINYZKP_CLEAN_LAUNCH=1" in first
    wrapper = (ROOT / "scripts/ci/run_production_preflight.sh").read_text(
        encoding="utf-8"
    )
    assert "PYTHONPYCACHEPREFIX" in wrapper
    assert "ls-files --others --ignored" in wrapper
    assert "ls-files -v" in wrapper
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert ignored.startswith("*\n")
    assert "!crates/**" in ignored
    assert "**/__pycache__/" in ignored
    gitignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/data/" in gitignored
    assert "/backups/" in gitignored
