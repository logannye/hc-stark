import os
import pathlib
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time

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
    path.chmod(0o600)


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
    env_file = tmp_path / "backup.env"
    loader_token = tmp_path / "loader-token"
    loader_token.write_text("b" * 64 + "\n", encoding="ascii")
    loader_token.chmod(0o600)
    env = os.environ.copy()
    env.update(
        {
            "TINYZKP_BACKUP_TEST_ENV_FILE": str(env_file),
            "TINYZKP_BACKUP_TEST_TOKEN_FILE": str(loader_token),
            "TINYZKP_BACKUP_TEST_DATE": "20260623_010203",
            "TINYZKP_BACKUP_TEST_REMOTE_DATE": "2026-06-23",
            "TINYZKP_BACKUP_TEST_SYNC_ENV": "1",
            "HC_BACKUP_DATA_DIR": str(data_dir),
            "HC_BACKUP_DIR": str(backup_dir),
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
    data_dir.mkdir(mode=0o700)
    create_db(data_dir / "tenant_store.sqlite", "tenants", "tenant-a")
    create_db(data_dir / "usage.sqlite", "usage_log", "proof-a")
    create_db(data_dir / "evaluation_applications.sqlite", "applications", "eval-a")
    (data_dir / "api_keys.txt").write_text("tenant-a:tzk_test\n", encoding="utf-8")
    (data_dir / "api_keys.txt").chmod(0o600)
    return data_dir


def run_backup(
    env: dict[str, str], script: pathlib.Path = BACKUP_SCRIPT
) -> subprocess.CompletedProcess[str]:
    if env.get("TINYZKP_BACKUP_TEST_SYNC_ENV") == "1":
        env_file = pathlib.Path(env["TINYZKP_BACKUP_TEST_ENV_FILE"])
        env_file.write_text(
            "\n".join(
                f"{key}={env[key]}"
                for key in sorted(backup_env_exec.BACKUP_KEYS)
                if env.get(key)
            )
            + "\n",
            encoding="utf-8",
        )
        env_file.chmod(0o600)
    return subprocess.run(
        [str(script)],
        check=False,
        env=env,
        text=True,
        capture_output=True,
    )


def instrumented_backup_script(
    tmp_path: pathlib.Path, **binary_paths: pathlib.Path
) -> pathlib.Path:
    """Copy the fixed-path production script and replace binaries for a test."""

    directory = tmp_path / "instrumented-billing"
    directory.mkdir()
    for name in ("backup_env_exec.py", "validate_private_contract_dir.py"):
        shutil.copy2(ROOT / "billing" / name, directory / name)
    text = BACKUP_SCRIPT.read_text(encoding="utf-8")
    for variable, path in binary_paths.items():
        needle = f"{variable}=/usr/bin/{variable.removesuffix('_BIN').lower()}"
        assert needle in text
        text = text.replace(needle, f"{variable}={path}", 1)
    script = directory / "backup.sh"
    script.write_text(text, encoding="utf-8")
    script.chmod(0o755)
    return script


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
    manifest_snapshot = backup_dir / "manifest_20260623_010203.json"

    assert file_mode(tenant_snapshot) == 0o600
    assert file_mode(usage_snapshot) == 0o600
    assert file_mode(evaluation_snapshot) == 0o600
    assert file_mode(billing_snapshot) == 0o600
    assert file_mode(keys_snapshot) == 0o600
    assert file_mode(contracts_snapshot) == 0o600
    assert file_mode(manifest_snapshot) == 0o600
    backup_env_exec.verify_backup_manifest(manifest_snapshot)
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
        "#!/bin/sh\n"
        f"printf 'BEGIN\\0' >> {shlex.quote(str(rclone_log))}\n"
        f"printf '%s\\0' \"$@\" >> {shlex.quote(str(rclone_log))}\n"
        f"printf 'END\\0' >> {shlex.quote(str(rclone_log))}\n"
        "exit 0\n",
        encoding="utf-8",
    )
    rclone.chmod(0o755)

    env = backup_env(tmp_path, data_dir, backup_dir)
    env["HC_BACKUP_REMOTE"] = "s3:tinyzkp-backups/"
    script = instrumented_backup_script(tmp_path, RCLONE_BIN=rclone)

    result = run_backup(env, script)

    assert result.returncode == 0, result.stderr
    assert "Off-box backup pushed to s3:tinyzkp-backups/" in result.stdout
    assert "Pruned exact off-box backup artifacts older than 30 days" in result.stdout
    arguments = rclone_log.read_bytes().split(b"\0")
    assert arguments[:6] == [
        b"BEGIN",
        b"copyto",
        str(backup_dir / "tenant_store_20260623_010203.sqlite").encode(),
        b"s3:tinyzkp-backups/2026-06-23/tenant_store_20260623_010203.sqlite",
        b"END",
        b"BEGIN",
    ]
    assert arguments.count(b"copyto") == 7
    assert b"delete" in arguments
    assert b"--include" in arguments
    assert b"**/tenant_store_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9].sqlite" in arguments
    assert arguments[-4:] == [b"--exclude", b"**", b"END", b""]


def test_backup_script_pushes_each_snapshot_through_http_ingest(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    curl_log = tmp_path / "curl.configs"
    curl = fake_bin / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        f"cat >> {shlex.quote(str(curl_log))}\n"
        f"printf '\\n---request---\\n' >> {shlex.quote(str(curl_log))}\n"
        "printf '201'\n"
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
    script = instrumented_backup_script(tmp_path, CURL_BIN=curl)

    result = run_backup(env, script)

    assert result.returncode == 0, result.stderr
    assert "authenticated HTTP ingest" in result.stdout
    assert "a" * 64 not in result.stdout
    configs = curl_log.read_text(encoding="utf-8")
    assert configs.count("---request---") == 7
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
    curl.write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n", encoding="utf-8")
    curl.chmod(0o755)
    token_file = tmp_path / "token"
    token_file.write_text("a" * 64 + "\n", encoding="utf-8")
    token_file.chmod(0o600)

    env = backup_env(tmp_path, data_dir, backup_dir)
    env["HC_BACKUP_HTTP_URL"] = "https://backup.example/v1/backups"
    env["HC_BACKUP_HTTP_TOKEN_FILE"] = str(token_file)
    script = instrumented_backup_script(tmp_path, CURL_BIN=curl)

    result = run_backup(env, script)

    assert result.returncode != 0
    assert "HC_BACKUP_HTTP_RETENTION_CONFIRMED must equal 1" in result.stderr


def test_backup_env_is_parsed_as_private_data_without_shell_evaluation(tmp_path):
    marker = tmp_path / "shell-code-ran"
    env_file = tmp_path / "production.env"
    env_file.write_text(
        "# Parsed as data; unrelated assignments are ignored.\n"
        "HC_BACKUP_REMOTE='s3:tinyzkp-backups'\n"
        f"UNRELATED_VALUE=$(touch {marker})\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)

    environment = backup_env_exec.environment_for_backup(
        env_file,
        {
            "PATH": str(tmp_path / "attacker-bin"),
            "LD_PRELOAD": str(tmp_path / "inject.so"),
            "PYTHONPATH": str(tmp_path / "python"),
            "HC_BACKUP_PYTHON": str(tmp_path / "python3"),
            "HC_BACKUP_DATE": "19990101_000000",
            "HC_BACKUP_REMOTE_DATE": "1999-01-01",
            "HC_BACKUP_DIR": str(tmp_path / "attacker-backups"),
            "TINYZKP_BACKUP_ENV_LOADED": "forged",
        },
    )

    assert not marker.exists()
    assert environment == {
        "PATH": backup_env_exec.FIXED_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "RCLONE_CONFIG": str(backup_env_exec.FIXED_RCLONE_CONFIG),
        "HC_BACKUP_REMOTE": "s3:tinyzkp-backups",
        "TINYZKP_BACKUP_ENV_LOADED": backup_env_exec.BACKUP_ENV_MARKER,
    }


def test_backup_process_lock_rejects_concurrent_invocation(tmp_path):
    lock_path = tmp_path / "backup.lock"
    first_descriptor = backup_env_exec.acquire_backup_lock(
        lock_path, production=False
    )
    contender = (
        "import os, pathlib, sys; "
        "sys.path.insert(0, sys.argv[1]); "
        "import backup_env_exec; "
        "path = pathlib.Path(sys.argv[2]); "
        "\ntry:\n"
        " descriptor = backup_env_exec.acquire_backup_lock(path, production=False)\n"
        "except backup_env_exec.BackupEnvError as error:\n"
        " print(error, file=sys.stderr)\n"
        " raise SystemExit(17)\n"
        "else:\n"
        " os.close(descriptor)\n"
    )
    try:
        blocked = subprocess.run(
            [sys.executable, "-c", contender, str(ROOT / "billing"), str(lock_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    finally:
        os.close(first_descriptor)

    assert blocked.returncode == 17
    assert "another TinyZKP backup is already active" in blocked.stderr

    after_release = subprocess.run(
        [sys.executable, "-c", contender, str(ROOT / "billing"), str(lock_path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert after_release.returncode == 0, after_release.stderr


def test_forged_inherited_loader_marker_cannot_bypass_private_env(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    approved_backup_dir = tmp_path / "approved-backups"
    inherited_backup_dir = tmp_path / "inherited-attacker-backups"
    base = backup_env(tmp_path, data_dir, approved_backup_dir)
    env_file = tmp_path / "production.env"
    env_file.write_text(
        "\n".join(
            (
                f"HC_BACKUP_DATA_DIR={base['HC_BACKUP_DATA_DIR']}",
                f"HC_BACKUP_DIR={base['HC_BACKUP_DIR']}",
                f"HC_CONTRACT_DATA_DIR={base['HC_CONTRACT_DATA_DIR']}",
                "TINYZKP_CONTRACT_BILLING_LEDGER_PATH="
                f"{base['TINYZKP_CONTRACT_BILLING_LEDGER_PATH']}",
                "HC_BACKUP_RETENTION_DAYS=30",
                "",
            )
        ),
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    base["TINYZKP_BACKUP_TEST_ENV_FILE"] = str(env_file)
    base["TINYZKP_BACKUP_TEST_SYNC_ENV"] = "0"
    base["HC_BACKUP_DIR"] = str(inherited_backup_dir)
    base["TINYZKP_BACKUP_ENV_LOADED"] = backup_env_exec.BACKUP_ENV_MARKER
    base["HC_BACKUP_DATE"] = "19990101_000000"

    result = run_backup(base)

    assert result.returncode != 0
    assert "no usable off-box backup transport" in result.stderr
    assert approved_backup_dir.is_dir()
    assert not inherited_backup_dir.exists()
    assert not list(approved_backup_dir.glob("*_19990101_000000.*"))


def test_backup_rejects_unsafe_or_non_data_env_file(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    env = backup_env(tmp_path, data_dir, backup_dir)
    env_file = tmp_path / "production.env"
    env_file.write_text("HC_BACKUP_REMOTE=s3:private\n", encoding="utf-8")
    env["TINYZKP_BACKUP_TEST_ENV_FILE"] = str(env_file)
    env["TINYZKP_BACKUP_TEST_SYNC_ENV"] = "0"

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


@pytest.mark.parametrize(
    ("timestamp", "remote_date", "message"),
    [
        ("20260230_010203", "2026-02-28", "canonical UTC"),
        ("20260623_010203;touch", "2026-06-23", "canonical UTC"),
        ("20260623_010203", "2026/06/23", "canonical UTC"),
        ("20260623_010203", "2026-06-24", "same UTC day"),
    ],
)
def test_backup_dates_reject_noncanonical_or_inconsistent_values(
    timestamp, remote_date, message
):
    with pytest.raises(backup_env_exec.BackupEnvError, match=message):
        backup_env_exec.validate_backup_dates(timestamp, remote_date)


def test_backup_script_rejects_invalid_timestamp_before_creating_root(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    env = backup_env(tmp_path, data_dir, backup_dir)
    env["TINYZKP_BACKUP_TEST_DATE"] = "20260230_010203"

    result = run_backup(env)

    assert result.returncode != 0
    assert "canonical UTC" in result.stderr
    assert not backup_dir.exists()


@pytest.mark.parametrize("overlap", ["data", "contracts", "ledger", "scripts"])
def test_backup_layout_rejects_source_or_code_overlap(tmp_path, overlap):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    contract_dir = tmp_path / "contracts"
    contract_dir.mkdir()
    ledger = tmp_path / "billing" / "contract_billing.sqlite"
    ledger.parent.mkdir()
    ledger.write_bytes(b"ledger")
    script_dir = tmp_path / "scripts"
    script_dir.mkdir()
    paths = {
        "data": data_dir,
        "contracts": contract_dir,
        "ledger": ledger.parent,
        "scripts": script_dir,
    }

    with pytest.raises(backup_env_exec.BackupEnvError, match="overlaps"):
        backup_env_exec.validate_backup_layout(
            backup_dir=paths[overlap],
            data_dir=data_dir,
            contract_dir=contract_dir,
            billing_ledger_path=ledger,
            script_dir=script_dir,
            timestamp="20260623_010203",
        )


def test_backup_layout_rejects_symlink_or_non_private_root(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    ledger = tmp_path / "ledger.sqlite"

    real_root = tmp_path / "real-backups"
    real_root.mkdir(mode=0o700)
    symlink_root = tmp_path / "backups"
    symlink_root.symlink_to(real_root)
    with pytest.raises(backup_env_exec.BackupEnvError, match="symlink"):
        backup_env_exec.validate_backup_layout(
            backup_dir=symlink_root,
            data_dir=data_dir,
            contract_dir=contracts,
            billing_ledger_path=ledger,
            script_dir=scripts,
            timestamp="20260623_010203",
        )

    symlink_root.unlink()
    symlink_root.mkdir(mode=0o755)
    with pytest.raises(backup_env_exec.BackupEnvError, match="owner-only"):
        backup_env_exec.validate_backup_layout(
            backup_dir=symlink_root,
            data_dir=data_dir,
            contract_dir=contracts,
            billing_ledger_path=ledger,
            script_dir=scripts,
            timestamp="20260623_010203",
        )


def test_backup_layout_rejects_source_and_artifact_hardlinks(tmp_path):
    data_dir = prepare_data_dir(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    ledger = tmp_path / "ledger.sqlite"

    source_link = tmp_path / "tenant-hardlink.sqlite"
    os.link(data_dir / "tenant_store.sqlite", source_link)
    with pytest.raises(backup_env_exec.BackupEnvError, match="hard-linked"):
        backup_env_exec.validate_backup_layout(
            backup_dir=backup_dir,
            data_dir=data_dir,
            contract_dir=contracts,
            billing_ledger_path=ledger,
            script_dir=scripts,
            timestamp="20260623_010203",
        )

    source_link.unlink()
    artifact = backup_dir / "usage_20260101_000000.sqlite"
    artifact.write_bytes(b"backup")
    artifact.chmod(0o600)
    os.link(artifact, tmp_path / "artifact-hardlink.sqlite")
    with pytest.raises(backup_env_exec.BackupEnvError, match="hard-linked"):
        backup_env_exec.validate_backup_layout(
            backup_dir=backup_dir,
            data_dir=data_dir,
            contract_dir=contracts,
            billing_ledger_path=ledger,
            script_dir=scripts,
            timestamp="20260623_010203",
        )


def test_prune_removes_only_exact_tinyzkp_artifact_names(tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    exact = backup_dir / "usage_20260101_000000.sqlite"
    near_match = backup_dir / "usage_customer.sqlite"
    suffix_match = backup_dir / "customer_20260101_000000.sqlite"
    foreign = backup_dir / "other.sqlite"
    for path in (exact, near_match, suffix_match, foreign):
        path.write_bytes(b"data")
        path.chmod(0o600)
        old = time.time() - 60 * 86400
        os.utime(path, (old, old))

    removed = backup_env_exec.prune_backup_artifacts(backup_dir, 30)

    assert removed == 1
    assert not exact.exists()
    assert near_match.exists()
    assert suffix_match.exists()
    assert foreign.exists()


def test_production_backup_orchestration_is_privilege_separated_and_fail_closed():
    script = BACKUP_SCRIPT.read_text(encoding="utf-8")
    create_stage = script.index("create-staging")
    first_snapshot = script.index("--kind sqlite", create_stage)
    root_copy = script.index("--kind copy", first_snapshot)
    manifest = script.index("create-manifest", root_copy)
    resume = script.index("resume_quiesced_services\n", manifest)
    offbox = script.index("# --- Off-box copy", resume)

    assert "/var/lib/tinyzkp-backup-staging/run_$DATE" in script
    assert "/var/lib/tinyzkp-private/backup-staging" not in script
    assert '"$SYSTEMCTL_BIN" stop hc-stark.service' in script
    assert '"$SYSTEMCTL_BIN" stop hc-billing-webhook.service' in script
    assert "a production writer remained active" in script
    assert '"$RUNUSER_BIN" --user tinyzkp-billing' in script
    assert "TINYZKP_BACKUP_LOCK_HELD" in script
    assert create_stage < first_snapshot < root_copy < manifest < resume < offbox
    assert "trap 'resume_quiesced_services; exit 129' HUP" in script
    assert "trap 'resume_quiesced_services; exit 130' INT" in script
    assert "trap 'resume_quiesced_services; exit 143' TERM" in script


def test_linux_root_backup_integration_remains_an_explicit_release_gate():
    operations = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
    assert "Linux root backup integration" in operations
    assert "must remain blocked" in operations


def test_restore_runbook_uses_atomic_dirfd_helper_instead_of_root_copy():
    runbook = (ROOT / "docs" / "runbooks" / "restore.md").read_text(
        encoding="utf-8"
    )
    helper = (ROOT / "billing" / "backup_env_exec.py").read_text(encoding="utf-8")
    assert runbook.count("restore-artifact") == 5
    assert 'cp "${RESTORE_DIR}' not in runbook
    assert "src_dir_fd=directory_descriptor" in helper
    assert "dst_dir_fd=directory_descriptor" in helper
    assert "follow_symlinks=False" in helper
    assert "os.fchown(directory_descriptor, 0, 0)" in helper
