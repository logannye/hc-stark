import os
import pathlib
import shutil
import sqlite3
import stat
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKUP_SCRIPT = ROOT / "billing" / "backup.sh"


def create_db(path: pathlib.Path, table: str, value: str) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, label TEXT NOT NULL)")
        conn.execute(f"INSERT INTO {table} (label) VALUES (?)", (value,))


def query_one(path: pathlib.Path, sql: str) -> str:
    with sqlite3.connect(path) as conn:
        row = conn.execute(sql).fetchone()
    assert row is not None
    return str(row[0])


def file_mode(path: pathlib.Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def backup_env(tmp_path: pathlib.Path, data_dir: pathlib.Path, backup_dir: pathlib.Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "HC_BACKUP_ENV_FILE": str(tmp_path / "missing.env"),
            "HC_BACKUP_DATA_DIR": str(data_dir),
            "HC_BACKUP_DIR": str(backup_dir),
            "HC_BACKUP_DATE": "20260623_010203",
            "HC_BACKUP_REMOTE_DATE": "2026-06-23",
            "HC_BACKUP_RETENTION_DAYS": "30",
        }
    )
    env.pop("HC_BACKUP_REMOTE", None)
    env.pop("HC_BACKUP_HTTP_URL", None)
    env.pop("HC_BACKUP_HTTP_TOKEN_FILE", None)
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


def test_backup_script_creates_recoverable_snapshots_with_restrictive_permissions(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"

    result = run_backup(backup_env(tmp_path, data_dir, backup_dir))

    assert result.returncode == 0, result.stderr
    assert "Backed up tenant_store.sqlite" in result.stdout
    assert "Backed up usage.sqlite" in result.stdout
    assert "Backed up evaluation_applications.sqlite" in result.stdout
    assert "Backed up api_keys.txt" in result.stdout
    assert "on-disk backup ONLY" in result.stderr
    assert file_mode(backup_dir) == 0o700

    tenant_snapshot = backup_dir / "tenant_store_20260623_010203.sqlite"
    usage_snapshot = backup_dir / "usage_20260623_010203.sqlite"
    evaluation_snapshot = backup_dir / "evaluation_applications_20260623_010203.sqlite"
    keys_snapshot = backup_dir / "api_keys_20260623_010203.txt"

    assert file_mode(tenant_snapshot) == 0o600
    assert file_mode(usage_snapshot) == 0o600
    assert file_mode(evaluation_snapshot) == 0o600
    assert file_mode(keys_snapshot) == 0o600
    assert query_one(tenant_snapshot, "SELECT label FROM tenants") == "tenant-a"
    assert query_one(usage_snapshot, "SELECT label FROM usage_log") == "proof-a"
    assert query_one(evaluation_snapshot, "SELECT label FROM applications") == "eval-a"
    assert keys_snapshot.read_text(encoding="utf-8") == "tenant-a:tzk_test\n"


def test_backup_script_pushes_to_dated_rclone_target_when_remote_is_configured(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    rclone_log = tmp_path / "rclone.args"
    rclone = fake_bin / "rclone"
    rclone.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\0' \"$@\" > \"$RCLONE_LOG\"\n"
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
    assert rclone_log.read_bytes().split(b"\0")[:-1] == [
        b"copy",
        str(backup_dir).encode(),
        b"s3:tinyzkp-backups/2026-06-23",
        b"--max-age",
        b"25h",
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
        "cat >> \"$CURL_LOG\"\n"
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
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    env["CURL_LOG"] = str(curl_log)

    result = run_backup(env)

    assert result.returncode == 0, result.stderr
    assert "authenticated HTTP ingest" in result.stdout
    assert "a" * 64 not in result.stdout
    configs = curl_log.read_text(encoding="utf-8")
    assert configs.count("---request---") == 4
    assert "https://backup.example/v1/backups/2026-06-23/tenant_store_20260623_010203.sqlite" in configs
    assert "https://backup.example/v1/backups/2026-06-23/evaluation_applications_20260623_010203.sqlite" in configs
    assert 'header = "X-Content-SHA256: ' in configs
