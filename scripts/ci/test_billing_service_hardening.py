import datetime as dt
import json
import os
from pathlib import Path
import shlex
import sqlite3
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "billing"))

import evaluation_store  # noqa: E402

sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import backup_restore_check  # noqa: E402


def test_canonical_billing_webhook_is_non_root_and_owner_only():
    text = (ROOT / "deploy/hetzner/hc-billing-webhook.service").read_text(
        encoding="utf-8"
    )
    for marker in (
        "User=tinyzkp-billing",
        "Group=tinyzkp-billing",
        "UMask=0077",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ReadWritePaths=/opt/hc-stark/data",
    ):
        assert marker in text
    assert "chown -R tinyzkp-billing" not in text

    deploy = (ROOT / "deploy/hetzner/deploy.sh").read_text(encoding="utf-8")
    helper = (ROOT / "deploy/hetzner/deployment_transaction.py").read_text(
        encoding="utf-8"
    )
    assert "hc-billing-webhook.service" in deploy
    assert "hc-billing-webhook.service" in helper


def test_setup_and_deploy_install_one_canonical_backup_and_retention_schedule():
    cron = (ROOT / "deploy/hetzner/hc-billing.cron").read_text(encoding="utf-8")
    backup = [
        line
        for line in cron.splitlines()
        if line.startswith("0 2 ") and "/billing/backup.sh" in line
    ]
    retention = [line for line in cron.splitlines() if "purge-expired --apply" in line]
    assert len(backup) == 1
    assert len(retention) == 1
    helper = (ROOT / "deploy/hetzner/deployment_transaction.py").read_text(
        encoding="utf-8"
    )
    assert '"cron": REPO / "deploy/hetzner/hc-billing.cron"' in helper
    assert '"cron": pathlib.Path("/etc/cron.d/hc-billing")' in helper
    for relative in ("deploy/hetzner/setup.sh", "deploy/hetzner/deploy.sh"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert not any(line.startswith("0 2 ") for line in text.splitlines())


def test_recovery_cron_enforces_application_retention():
    text = (ROOT / "deploy/hetzner/hc-billing.cron").read_text(encoding="utf-8")
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

    assert 'DEPLOY_STATE="/var/lib/tinyzkp-private/deploy"' in deploy
    assert 'PREFLIGHT_EVIDENCE="$DEPLOY_STATE/production-preflight.json"' in deploy
    assert 'PAGES_BINDINGS_FILE="$DEPLOY_STATE/pages-bindings.env"' in deploy
    commands = {line.strip() for line in deploy.splitlines() if line.strip()}
    assert not any(line.startswith("git fetch") for line in commands)
    assert not any(line.startswith("git checkout") for line in commands)
    assert not any(line.startswith("git pull") for line in commands)
    assert evidence_check < deploy.index(" begin \\")
    assert "install_billing_runtime.sh" not in deploy
    assert "--expected-release-sha \"$RELEASE_SHA\"" in deploy
    assert "scripts/ci/run_production_preflight.sh" in deploy[:evidence_check]
    assert "TINYZKP_CLEAN_LAUNCH=1" in deploy.splitlines()[0]
    assert '"${COMPOSE[@]}" up -d --no-build' in deploy
    assert '"${COMPOSE[@]}" build' not in deploy
    assert "--consume-evidence" in deploy
    assert deploy.index('PATH="/usr/sbin:/usr/bin:/sbin:/bin"') < evidence_check
    assert 'export HC_IMAGE_TAG="$RELEASE_SHA"' in deploy
    assert "tinyzkp/hc-server:$RELEASE_SHA" in deploy
    assert ":latest" not in deploy
    assert "deployment.lock" in deploy
    assert "trap rollback_on_exit EXIT" in deploy
    assert "install-configs" in deploy
    assert " commit " in deploy


def test_setup_is_bootstrap_only_and_has_no_release_authority():
    setup = (ROOT / "deploy/hetzner/setup.sh").read_text(encoding="utf-8")
    commands = [
        line.strip()
        for line in setup.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    forbidden = (
        "apt-get ",
        "systemctl ",
        "docker compose",
        "docker run",
        "ufw ",
        "curl ",
        "> /etc/",
        "cp ",
        "install_billing_runtime.sh explicitly",
    )
    assert all(not any(marker in line for marker in forbidden) for line in commands)
    assert "RELEASE AUTHORITY: NONE" in setup
    assert "setup.sh accepts no package, deploy, or service-start options" in setup
    assert "Do not use setup.sh to install an unpinned latest package" in setup
    assert "deploy.sh will reject missing evidence and transact every live mutation" in setup
    assert "systemctl start hc-stark" not in setup
    assert "systemctl start hc-billing-webhook" not in setup


def test_backup_drift_gate_routes_live_schedule_to_transaction_not_setup():
    required = backup_restore_check.REQUIRED_MARKERS
    forbidden = backup_restore_check.FORBIDDEN_MARKERS
    assert "deploy/hetzner/hc-billing.cron" in required
    assert "deploy/hetzner/deployment_transaction.py" in required
    assert "/etc/cron.d/hc-billing" in forbidden["deploy/hetzner/setup.sh"]
    assert "systemctl start" in forbidden["deploy/hetzner/setup.sh"]
    assert backup_restore_check.check(ROOT) == []


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
