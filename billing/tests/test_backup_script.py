import os
import pathlib
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKUP_SCRIPT = ROOT / "billing" / "backup.sh"
sys.path.insert(0, str(ROOT / "billing"))

import backup_env_exec  # noqa: E402


def create_db(path: pathlib.Path, table: str, value: str) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(
            f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, label TEXT NOT NULL)"
        )
        conn.execute(f"INSERT INTO {table} (label) VALUES (?)", (value,))


def query_one(path: pathlib.Path, sql: str) -> str:
    with sqlite3.connect(path) as conn:
        row = conn.execute(sql).fetchone()
    assert row is not None
    return str(row[0])


def file_mode(path: pathlib.Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def backup_env(
    tmp_path: pathlib.Path, data_dir: pathlib.Path, backup_dir: pathlib.Path
) -> dict[str, str]:
    billing_dir = tmp_path / "private" / "billing"
    billing_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    billing_dir.chmod(0o700)
    billing_ledger = billing_dir / "contract_billing.sqlite"
    if not billing_ledger.exists():
        create_db(billing_ledger, "billing_operations", "billing-a")
    billing_ledger.chmod(0o600)
    contract_dir = tmp_path / "contracts"
    contract_dir.mkdir(mode=0o700, exist_ok=True)
    contract_dir.chmod(0o700)
    for name, payload in (
        ("eval-001.evidence.json", b'{"schema_version":1}\n'),
        ("eval-001.signed.pdf", b"signed-contract"),
    ):
        path = contract_dir / name
        path.write_bytes(payload)
        path.chmod(0o600)
    env = os.environ.copy()
    env.update(
        {
            "HC_BACKUP_ENV_FILE": str(tmp_path / "missing.env"),
            "HC_BACKUP_DATA_DIR": str(data_dir),
            "HC_BACKUP_DIR": str(backup_dir),
            "HC_BACKUP_DATE": "20260623_010203",
            "HC_BACKUP_REMOTE_DATE": "2026-06-23",
            "HC_BACKUP_RETENTION_DAYS": "30",
            "HC_CONTRACT_DATA_DIR": str(contract_dir),
            "TINYZKP_CONTRACT_BILLING_LEDGER_PATH": str(billing_ledger),
        }
    )
    env.pop("HC_BACKUP_REMOTE", None)
    env.pop("HC_BACKUP_HTTP_URL", None)
    env.pop("HC_BACKUP_HTTP_TOKEN_FILE", None)
    env.pop("HC_BACKUP_HTTP_RETENTION_CONFIRMED", None)
    return env


def prepare_data_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    create_db(data_dir / "tenant_store.sqlite", "tenants", "tenant-a")
    create_db(data_dir / "usage.sqlite", "usage_log", "proof-a")
    create_db(data_dir / "evaluation_applications.sqlite", "applications", "eval-a")
    (data_dir / "api_keys.txt").write_text("tenant-a:tzk_test\n", encoding="utf-8")
    return data_dir


def run_backup(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    if shutil.which("sqlite3") is None:
        raise AssertionError("sqlite3 CLI is required to exercise billing/backup.sh")
    return subprocess.run(
        ["bash", str(BACKUP_SCRIPT)],
        check=False,
        env=env,
        text=True,
        capture_output=True,
    )


def test_backup_script_creates_recoverable_snapshots_with_restrictive_permissions(
    tmp_path,
):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    env = backup_env(tmp_path, data_dir, backup_dir)
    billing_ledger = pathlib.Path(env["TINYZKP_CONTRACT_BILLING_LEDGER_PATH"])

    result = run_backup(env)

    assert result.returncode != 0
    assert "Backed up tenant_store.sqlite" in result.stdout
    assert "Backed up usage.sqlite" in result.stdout
    assert "Backed up evaluation_applications.sqlite" in result.stdout
    assert "Backed up contract billing ledger" in result.stdout
    assert "Backed up api_keys.txt" in result.stdout
    assert "Backed up private contracts" in result.stdout
    assert "no usable off-box backup transport" in result.stderr
    assert file_mode(backup_dir) == 0o700
    assert billing_ledger.parent != data_dir
    assert not (data_dir / "contract_billing.sqlite").exists()

    tenant_snapshot = backup_dir / "tenant_store_20260623_010203.sqlite"
    usage_snapshot = backup_dir / "usage_20260623_010203.sqlite"
    evaluation_snapshot = backup_dir / "evaluation_applications_20260623_010203.sqlite"
    billing_snapshot = backup_dir / "contract_billing_20260623_010203.sqlite"
    keys_snapshot = backup_dir / "api_keys_20260623_010203.txt"
    contracts_snapshot = backup_dir / "contracts_20260623_010203.tar.gz"

    assert file_mode(tenant_snapshot) == 0o600
    assert file_mode(usage_snapshot) == 0o600
    assert file_mode(evaluation_snapshot) == 0o600
    assert file_mode(billing_snapshot) == 0o600
    assert file_mode(keys_snapshot) == 0o600
    assert file_mode(contracts_snapshot) == 0o600
    assert query_one(tenant_snapshot, "SELECT label FROM tenants") == "tenant-a"
    assert query_one(usage_snapshot, "SELECT label FROM usage_log") == "proof-a"
    assert query_one(evaluation_snapshot, "SELECT label FROM applications") == "eval-a"
    assert (
        query_one(billing_snapshot, "SELECT label FROM billing_operations")
        == "billing-a"
    )
    assert keys_snapshot.read_text(encoding="utf-8") == "tenant-a:tzk_test\n"
    with tarfile.open(contracts_snapshot, "r:gz") as archive:
        assert (
            archive.extractfile("./eval-001.evidence.json").read()
            == b'{"schema_version":1}\n'
        )
        assert archive.extractfile("./eval-001.signed.pdf").read() == b"signed-contract"


def test_backup_script_pushes_to_dated_rclone_target_when_remote_is_configured(
    tmp_path,
):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    rclone_log = tmp_path / "rclone.args"
    rclone = fake_bin / "rclone"
    rclone.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'BEGIN\\0' >> \"$RCLONE_LOG\"\n"
        'printf \'%s\\0\' "$@" >> "$RCLONE_LOG"\n'
        "printf 'END\\0' >> \"$RCLONE_LOG\"\n"
        "exit 0\n",
        encoding="utf-8",
    )
    rclone.chmod(0o755)

    env = backup_env(tmp_path, data_dir, backup_dir)
    env["HC_BACKUP_REMOTE"] = "s3:tinyzkp-backups/"
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    env["RCLONE_LOG"] = str(rclone_log)

    result = run_backup(env)

    assert result.returncode == 0, result.stderr
    assert "Off-box backup pushed to s3:tinyzkp-backups/" in result.stdout
    assert "Pruned off-box backups older than 30 days" in result.stdout
    assert rclone_log.read_bytes().split(b"\0") == [
        b"BEGIN",
        b"copy",
        str(backup_dir).encode(),
        b"s3:tinyzkp-backups/2026-06-23",
        b"--max-age",
        b"25h",
        b"END",
        b"BEGIN",
        b"delete",
        b"s3:tinyzkp-backups",
        b"--min-age",
        b"30d",
        b"--rmdirs",
        b"END",
        b"",
    ]


def test_backup_script_pushes_each_snapshot_through_http_ingest(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    curl_log = tmp_path / "curl.configs"
    curl = fake_bin / "curl"
    curl.write_text(
        "#!/usr/bin/env bash\n"
        'cat >> "$CURL_LOG"\n'
        "printf '\\n---request---\\n' >> \"$CURL_LOG\"\n"
        "exit 0\n",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    token_file = tmp_path / "token"
    token_file.write_text("a" * 64 + "\n", encoding="utf-8")
    token_file.chmod(0o600)

    env = backup_env(tmp_path, data_dir, backup_dir)
    env["HC_BACKUP_HTTP_URL"] = "https://backup.example/v1/backups"
    env["HC_BACKUP_HTTP_TOKEN_FILE"] = str(token_file)
    env["HC_BACKUP_HTTP_RETENTION_CONFIRMED"] = "1"
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    env["CURL_LOG"] = str(curl_log)

    result = run_backup(env)

    assert result.returncode == 0, result.stderr
    assert "authenticated HTTP ingest" in result.stdout
    assert "a" * 64 not in result.stdout
    configs = curl_log.read_text(encoding="utf-8")
    assert configs.count("---request---") == 6
    assert (
        "https://backup.example/v1/backups/2026-06-23/tenant_store_20260623_010203.sqlite"
        in configs
    )
    assert (
        "https://backup.example/v1/backups/2026-06-23/evaluation_applications_20260623_010203.sqlite"
        in configs
    )
    assert (
        "https://backup.example/v1/backups/2026-06-23/contract_billing_20260623_010203.sqlite"
        in configs
    )
    assert (
        "https://backup.example/v1/backups/2026-06-23/contracts_20260623_010203.tar.gz"
        in configs
    )
    assert 'header = "X-Content-SHA256: ' in configs


def test_backup_script_fails_closed_when_http_retention_is_not_confirmed(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text("#!/usr/bin/env bash\ncat >/dev/null\nexit 0\n", encoding="utf-8")
    curl.chmod(0o755)
    token_file = tmp_path / "token"
    token_file.write_text("a" * 64 + "\n", encoding="utf-8")
    token_file.chmod(0o600)

    env = backup_env(tmp_path, data_dir, backup_dir)
    env["HC_BACKUP_HTTP_URL"] = "https://backup.example/v1/backups"
    env["HC_BACKUP_HTTP_TOKEN_FILE"] = str(token_file)
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"

    result = run_backup(env)

    assert result.returncode != 0
    assert "HTTP backup destination retention is not confirmed" in result.stderr


def test_backup_env_is_parsed_as_private_data_without_shell_evaluation(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    rclone = fake_bin / "rclone"
    rclone.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    rclone.chmod(0o755)
    marker = tmp_path / "shell-code-ran"
    env_file = tmp_path / "production.env"
    env_file.write_text(
        "# Parsed as data; unrelated assignments are ignored.\n"
        "HC_BACKUP_REMOTE='s3:tinyzkp-backups'\n"
        f"UNRELATED_VALUE=$(touch {marker})\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)

    env = backup_env(tmp_path, data_dir, backup_dir)
    env["HC_BACKUP_ENV_FILE"] = str(env_file)
    env["HC_BACKUP_PYTHON"] = sys.executable
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    result = run_backup(env)

    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert "Off-box backup pushed to s3:tinyzkp-backups" in result.stdout


def test_backup_rejects_unsafe_or_non_data_env_file(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    env = backup_env(tmp_path, data_dir, backup_dir)
    env["HC_BACKUP_PYTHON"] = sys.executable
    env_file = tmp_path / "production.env"
    env_file.write_text("HC_BACKUP_REMOTE=s3:private\n", encoding="utf-8")
    env["HC_BACKUP_ENV_FILE"] = str(env_file)

    result = run_backup(env)
    assert result.returncode != 0
    assert "must be owner-only" in result.stderr

    env_file.chmod(0o600)
    env_file.write_text("touch /tmp/not-data\n", encoding="utf-8")
    result = run_backup(env)
    assert result.returncode != 0
    assert "data-only KEY=value" in result.stderr

    target = tmp_path / "target.env"
    target.write_text("HC_BACKUP_REMOTE=s3:private\n", encoding="utf-8")
    target.chmod(0o600)
    env_file.unlink()
    env_file.symlink_to(target)
    result = run_backup(env)
    assert result.returncode != 0
    assert "unavailable or unsafe" in result.stderr


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        ({"HC_BACKUP_RETENTION_DAYS": "0"}, "integer from 1"),
        ({"HC_BACKUP_RETENTION_DAYS": "1 -delete"}, "integer from 1"),
        ({"HC_BACKUP_RETENTION_DAYS": "3651"}, "integer from 1"),
        ({"HC_BACKUP_DIR": "relative/backups"}, "safe absolute"),
        ({"HC_BACKUP_DATA_DIR": "/opt/../etc"}, "safe absolute"),
        ({"HC_BACKUP_REMOTE": "s3:../../root"}, "malformed"),
        (
            {
                "HC_BACKUP_HTTP_URL": "http://backup.example/v1",
                "HC_BACKUP_HTTP_TOKEN_FILE": "/secure/token",
                "HC_BACKUP_HTTP_RETENTION_CONFIRMED": "1",
            },
            "credential-free HTTPS",
        ),
        (
            {
                "HC_BACKUP_HTTP_URL": "https://user@backup.example/v1",
                "HC_BACKUP_HTTP_TOKEN_FILE": "/secure/token",
                "HC_BACKUP_HTTP_RETENTION_CONFIRMED": "1",
            },
            "credential-free HTTPS",
        ),
        (
            {
                "HC_BACKUP_HTTP_URL": 'https://backup.example/"--config',
                "HC_BACKUP_HTTP_TOKEN_FILE": "/secure/token",
                "HC_BACKUP_HTTP_RETENTION_CONFIRMED": "1",
            },
            "credential-free HTTPS",
        ),
        (
            {
                "HC_BACKUP_HTTP_URL": "https://backup.example/v1",
                "HC_BACKUP_HTTP_TOKEN_FILE": "/secure/token",
                "HC_BACKUP_HTTP_RETENTION_CONFIRMED": "0",
            },
            "must equal 1",
        ),
    ],
)
def test_backup_env_rejects_invalid_or_command_shaped_values(settings, message):
    with pytest.raises(backup_env_exec.BackupEnvError, match=message):
        backup_env_exec.validate_backup_values(settings)


def test_backup_script_rejects_retention_argument_injection(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    env = backup_env(tmp_path, data_dir, backup_dir)
    env["HC_BACKUP_RETENTION_DAYS"] = "1 -delete"

    result = run_backup(env)

    assert result.returncode != 0
    assert "must be an integer from 1 through 3650" in result.stderr
    assert not backup_dir.exists()


def test_backup_fails_when_rclone_remote_has_no_rclone_binary(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    restricted_bin = tmp_path / "restricted-bin"
    restricted_bin.mkdir()
    for command in (
        "bash",
        "chmod",
        "date",
        "dirname",
        "find",
        "grep",
        "install",
        "mkdir",
        "sqlite3",
        "tar",
    ):
        executable = shutil.which(command)
        assert executable is not None
        (restricted_bin / command).symlink_to(executable)
    (restricted_bin / "python3").symlink_to(sys.executable)

    env = backup_env(tmp_path, data_dir, backup_dir)
    env["HC_BACKUP_REMOTE"] = "s3:tinyzkp-backups"
    env["PATH"] = str(restricted_bin)
    result = run_backup(env)

    assert result.returncode != 0
    assert "HC_BACKUP_REMOTE is configured but rclone is unavailable" in result.stderr


def test_backup_rejects_unsafe_contract_files(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    env = backup_env(tmp_path, data_dir, backup_dir)
    contract_dir = pathlib.Path(env["HC_CONTRACT_DATA_DIR"])
    unsafe = contract_dir / "unsafe-link"
    unsafe.symlink_to(contract_dir / "eval-001.evidence.json")
    result = run_backup(env)
    assert result.returncode != 0
    assert "contract directory contains a symlink" in result.stderr

    unsafe.unlink()
    (contract_dir / "eval-001.evidence.json").chmod(0o644)
    result = run_backup(env)
    assert result.returncode != 0
    assert "contract directory is not owner-only" in result.stderr
