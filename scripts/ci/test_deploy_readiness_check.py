import hashlib
import importlib.util
import json
import os
import pathlib
import sqlite3
import sys
import types

import pytest
import deploy_readiness_check as readiness


LIVE_KEY = "sk_live_" + "a" * 32
WEBHOOK_SECRET = "whsec_" + "b" * 32
ACCOUNT_ID = "acct_" + "c" * 16
INTERNAL_SECRET = "TinyZKP-Internal-Secret-0123456789-abcd"


def _valid_production_env(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o700)
    data_dir.chmod(0o700)
    billing_dir = tmp_path / "private" / "billing"
    billing_dir.mkdir(mode=0o700, parents=True)
    billing_dir.chmod(0o700)
    evaluation = data_dir / "evaluation_applications.sqlite"
    ledger = billing_dir / "contract_billing.sqlite"
    schemas = {
        data_dir / "tenant_store.sqlite": """
            CREATE TABLE tenants (tenant_id TEXT, api_key_hash TEXT, status TEXT, plan TEXT);
            CREATE TABLE processed_events (event_id TEXT, processed_at_ms INTEGER);
            CREATE TABLE magic_links (token_hash TEXT, tenant_id TEXT, expires_at_ms INTEGER);
            CREATE TABLE sessions (token_hash TEXT, tenant_id TEXT, expires_at_ms INTEGER);
        """,
        data_dir / "usage.sqlite": """
            CREATE TABLE usage_log (tenant_id TEXT, job_id TEXT, trace_length INTEGER, billed INTEGER);
            CREATE TABLE verify_log (tenant_id TEXT, duration_ms INTEGER, completed_at_ms INTEGER);
            CREATE TABLE failed_proofs (tenant_id TEXT, job_id TEXT, error TEXT, failed_at_ms INTEGER);
        """,
        evaluation: """
            CREATE TABLE evaluation_applications (
              application_id TEXT, status TEXT, retention_deadline TEXT,
              qualification_json TEXT
            );
        """,
        ledger: """
            CREATE TABLE billing_operations (
              operation_key TEXT, plan_sha256 TEXT, action TEXT, phase TEXT
            );
        """,
    }
    for path, schema in schemas.items():
        with sqlite3.connect(path) as connection:
            connection.executescript(schema)
        path.chmod(0o600)
    (data_dir / "api_keys.txt").write_text(
        "tenant-a:tzk_live_key:standard\n", encoding="utf-8"
    )
    (data_dir / "api_keys.txt").chmod(0o600)
    return {
        "STRIPE_SECRET_KEY": LIVE_KEY,
        "STRIPE_WEBHOOK_SECRET": WEBHOOK_SECRET,
        "INTERNAL_SECRET": INTERNAL_SECRET,
        "STRIPE_EXPECTED_ACCOUNT_ID": ACCOUNT_ID,
        "STRIPE_EXPECTED_DISPLAY_NAME": "LN Holdings",
        "HC_EVALUATION_STORE_PATH": str(evaluation),
        "HC_BACKUP_DATA_DIR": str(data_dir),
        "TINYZKP_CONTRACT_BILLING_LEDGER_PATH": str(ledger),
        "HC_BACKUP_REMOTE": "r2-crypt:tinyzkp",
        "TINYZKP_MAINTENANCE_MODE": "1",
    }


def _release_authorization():
    return {
        "schema_version": 1,
        "status": "ready",
        "release_sha": "1" * 40,
        "source_tree_sha256": "2" * 64,
        "backend_evidence_sha256": "3" * 64,
        "backend_release_ready_report_sha256": "4" * 64,
        "signed_release_manifest_sha256": "5" * 64,
        "signature_bundle_sha256": "6" * 64,
        "verified_at": "2026-01-01T00:00:00Z",
        "validator": "scripts/ci/backend_release_ready.py",
        "validator_exit_code": 0,
    }


def _configure_release(env, tmp_path, payload=None):
    authorization = tmp_path / "authorization.json"
    bundle = tmp_path / "authorization.sigstore.json"
    authorization.write_text(
        json.dumps(payload or _release_authorization(), sort_keys=True),
        encoding="utf-8",
    )
    bundle.write_text("{}", encoding="utf-8")
    authorization.chmod(0o600)
    bundle.chmod(0o600)
    env.update(
        {
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION": str(authorization),
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_SHA256": hashlib.sha256(
                authorization.read_bytes()
            ).hexdigest(),
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE": str(bundle),
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE_SHA256": hashlib.sha256(
                bundle.read_bytes()
            ).hexdigest(),
        }
    )
    return authorization, bundle


def _failures(env, *, check_host_python=False):
    failures, warnings = readiness.check_env(env, check_host_python=check_host_python)
    return "\n".join(failures), "\n".join(warnings)


def _production_failures(env):
    failures, warnings = readiness.check_env(env, production=True)
    return "\n".join(failures), "\n".join(warnings)


def _private_env_file(tmp_path, content="ARBITRARY_CONFIG=loaded\n"):
    env_file = tmp_path / "production.env"
    env_file.write_text(content, encoding="utf-8")
    env_file.chmod(0o600)
    return env_file


def test_production_store_owners_match_their_runtime_processes(monkeypatch):
    monkeypatch.setattr(readiness.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        readiness.pwd,
        "getpwnam",
        lambda name: types.SimpleNamespace(pw_uid=4242) if name == "tinyzkp-billing" else None,
    )

    assert readiness._expected_store_owner_ids("HC_EVALUATION_STORE_PATH") == {4242}
    assert readiness._expected_store_owner_ids(
        "TINYZKP_CONTRACT_BILLING_LEDGER_PATH"
    ) == {0}


def test_private_production_env_loads_all_assignments_as_inert_data(tmp_path):
    marker = tmp_path / "must-not-exist"
    env_file = _private_env_file(
        tmp_path,
        "# Complete production env, not a backup-only allowlist.\n"
        "ARBITRARY_CONFIG=loaded\n"
        f"INERT_SHELL_TEXT=$(touch {marker})\n"
        'QUOTED_VALUE="value with spaces"\n',
    )

    loaded = readiness.load_private_env_file(env_file)

    assert loaded == {
        "ARBITRARY_CONFIG": "loaded",
        "INERT_SHELL_TEXT": f"$(touch {marker})",
        "QUOTED_VALUE": "value with spaces",
    }
    assert not marker.exists()


def test_private_production_env_rejects_symlink_and_non_regular_file(tmp_path):
    target = _private_env_file(tmp_path)
    symlink = tmp_path / "symlink.env"
    symlink.symlink_to(target)

    with pytest.raises(readiness.ProductionEnvError, match="unavailable or unsafe"):
        readiness.load_private_env_file(symlink)
    with pytest.raises(readiness.ProductionEnvError, match="regular non-symlink"):
        readiness.load_private_env_file(tmp_path)


def test_private_production_env_rejects_group_or_world_access(tmp_path):
    env_file = _private_env_file(tmp_path)
    env_file.chmod(0o640)

    with pytest.raises(readiness.ProductionEnvError, match="owner-only"):
        readiness.load_private_env_file(env_file)


def test_private_production_env_rejects_wrong_owner(tmp_path, monkeypatch):
    env_file = _private_env_file(tmp_path)
    actual_owner = env_file.stat().st_uid
    monkeypatch.setattr(readiness.os, "geteuid", lambda: actual_owner + 1)

    with pytest.raises(readiness.ProductionEnvError, match="current-owner|current operator"):
        readiness.load_private_env_file(env_file)


def test_private_production_env_rejects_oversize_file(tmp_path):
    env_file = _private_env_file(
        tmp_path,
        "OVERSIZE=" + "a" * readiness.MAX_ENV_BYTES,
    )

    with pytest.raises(readiness.ProductionEnvError, match="exceeds 64 KiB"):
        readiness.load_private_env_file(env_file)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("DUPLICATE=one\nDUPLICATE=two\n", "duplicated"),
        ("touch /tmp/not-data\n", "data-only KEY=value"),
        ("export EXPORTED=value\n", "data-only KEY=value"),
    ],
)
def test_private_production_env_rejects_duplicates_and_shell_lines(
    tmp_path, content, message
):
    env_file = _private_env_file(tmp_path, content)

    with pytest.raises(readiness.ProductionEnvError, match=message):
        readiness.load_private_env_file(env_file)


def test_production_cli_uses_strict_env_loader_and_keeps_all_keys(
    tmp_path, monkeypatch, capsys
):
    env_file = _private_env_file(tmp_path)
    captured = {}

    def fake_check_env(env, **kwargs):
        captured.update(env)
        assert kwargs["production"] is True
        return [], []

    monkeypatch.setattr(readiness, "check_env", fake_check_env)
    assert readiness.main(["--production", "--env-file", str(env_file)]) == 0
    assert captured["ARBITRARY_CONFIG"] == "loaded"

    env_file.chmod(0o644)
    captured.clear()
    assert readiness.main(["--production", "--env-file", str(env_file)]) == 1
    assert captured == {}
    assert "owner-only" in capsys.readouterr().err


def test_production_env_rejects_conflicting_shell_override(tmp_path, monkeypatch):
    env_file = _private_env_file(
        tmp_path,
        f"STRIPE_SECRET_KEY={LIVE_KEY}\n",
    )
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_" + "z" * 32)

    with pytest.raises(readiness.ProductionEnvError, match="STRIPE_SECRET_KEY"):
        readiness.merged_env(env_file, production=True)


def test_deploy_release_identity_exports_are_execution_scoped(tmp_path, monkeypatch):
    env_file = _private_env_file(
        tmp_path,
        "HC_RELEASE_SHA=\nHC_RELEASE_REF=\nHC_RELEASE_BUILD_URL=\n"
        f"STRIPE_SECRET_KEY={LIVE_KEY}\n",
    )
    monkeypatch.setenv("HC_RELEASE_SHA", "a" * 40)
    monkeypatch.setenv("HC_RELEASE_REF", "main")
    monkeypatch.setenv("HC_RELEASE_BUILD_URL", "https://github.example/run/1")

    loaded = readiness.merged_env(env_file, production=True)

    assert loaded["HC_RELEASE_SHA"] == ""
    assert loaded["HC_RELEASE_REF"] == ""
    assert loaded["HC_RELEASE_BUILD_URL"] == ""
    assert readiness.EXECUTION_SCOPED_RELEASE_IDENTITY_KEYS == {
        "HC_RELEASE_SHA",
        "HC_RELEASE_REF",
        "HC_RELEASE_BUILD_URL",
    }


def test_deploy_script_exports_only_allowlisted_release_identity_variables():
    deploy = (
        pathlib.Path(__file__).resolve().parents[2]
        / "deploy"
        / "hetzner"
        / "deploy.sh"
    ).read_text(encoding="utf-8")
    exported = {
        line.split("=", 1)[0].removeprefix("export ")
        for line in deploy.splitlines()
        if line.startswith("export HC_RELEASE_")
    }

    assert exported == readiness.EXECUTION_SCOPED_RELEASE_IDENTITY_KEYS


def test_production_env_ignores_unconfigured_shell_values(tmp_path, monkeypatch):
    env_file = _private_env_file(tmp_path, "ARBITRARY_CONFIG=loaded\n")
    monkeypatch.setenv("TINYZKP_EXPECT_RELEASE_SHA", "a" * 40)

    loaded = readiness.merged_env(env_file, production=True)

    assert loaded == {"ARBITRARY_CONFIG": "loaded"}


def test_nonproduction_env_preserves_shell_override_convenience(tmp_path, monkeypatch):
    env_file = _private_env_file(tmp_path, "HC_USAGE_SOURCE=sqlite\n")
    monkeypatch.setenv("HC_USAGE_SOURCE", "postgres")

    assert readiness.merged_env(env_file)["HC_USAGE_SOURCE"] == "postgres"


def test_empty_env_is_local_dispatch_ready():
    failures, warnings = _failures({})
    assert failures == ""
    assert warnings == ""


def test_usage_postgres_read_requires_server_pg_url():
    failures, _warnings = _failures({"HC_SERVER_USAGE_READ_FROM": "postgres"})
    assert "HC_SERVER_USAGE_READ_FROM=postgres requires HC_SERVER_PG_URL" in failures


def test_billing_postgres_source_requires_server_pg_url():
    failures, _warnings = _failures({"HC_USAGE_SOURCE": "postgres"})
    assert "HC_USAGE_SOURCE=postgres requires HC_SERVER_PG_URL" in failures


def test_shared_dispatch_requires_postgres_job_index_and_usage_pg():
    failures, _warnings = _failures({"HC_SERVER_PROVE_DISPATCH": "shared"})
    assert (
        "HC_SERVER_PROVE_DISPATCH=shared requires HC_SERVER_JOB_INDEX_SOURCE=postgres"
        in failures
    )
    assert (
        "HC_SERVER_PROVE_DISPATCH=shared requires HC_JOB_INDEX_PG_URL or HC_SERVER_PG_URL"
        in failures
    )
    assert (
        "HC_SERVER_PROVE_DISPATCH=shared requires HC_JOB_WORKER_USAGE_PG_URL or HC_SERVER_PG_URL"
        in failures
    )


def test_shared_dispatch_accepts_common_server_pg_url():
    failures, _warnings = _failures(
        {
            "HC_SERVER_PROVE_DISPATCH": "shared",
            "HC_SERVER_JOB_INDEX_SOURCE": "postgres",
            "HC_SERVER_PG_URL": "postgres://tinyzkp",
        }
    )
    assert failures == ""


def test_auth_pg_cutover_requires_fail_closed_tenant_mirror():
    failures, _warnings = _failures({"HC_SERVER_AUTH_PG_URL": "postgres://tinyzkp"})
    assert "HC_SERVER_AUTH_PG_URL requires HC_TENANT_PG_REQUIRED=1" in failures


def test_auth_pg_observation_can_be_explicitly_allowed():
    failures, _warnings = _failures(
        {
            "HC_SERVER_AUTH_PG_URL": "postgres://tinyzkp",
            "TINYZKP_DEPLOY_ALLOW_AUTH_PG_FAIL_OPEN": "1",
        }
    )
    assert failures == ""


def test_production_rejects_auth_pg_fail_open_even_without_cutover(tmp_path):
    env = _valid_production_env(tmp_path)
    env["TINYZKP_DEPLOY_ALLOW_AUTH_PG_FAIL_OPEN"] = "1"

    failures, _warnings = readiness.check_env(env, production=True)

    assert "production forbids TINYZKP_DEPLOY_ALLOW_AUTH_PG_FAIL_OPEN" in failures


def test_tenant_pg_required_needs_effective_url():
    failures, _warnings = _failures({"HC_TENANT_PG_REQUIRED": "1"})
    assert (
        "HC_TENANT_PG_REQUIRED=1 requires HC_TENANT_PG_URL or HC_SERVER_AUTH_PG_URL"
        in failures
    )


def test_tenant_pg_can_use_explicit_url_and_required_mode():
    failures, _warnings = _failures(
        {
            "HC_TENANT_PG_URL": "postgres://tinyzkp",
            "HC_TENANT_PG_REQUIRED": "1",
        }
    )
    assert failures == ""


def test_host_python_check_requires_psycopg_when_mirror_enabled(monkeypatch):
    real_find_spec = importlib.util.find_spec

    def fake_find_spec(name):
        if name == "psycopg":
            return None
        return real_find_spec(name)

    monkeypatch.setattr(readiness.importlib.util, "find_spec", fake_find_spec)
    failures, _warnings = _failures(
        {"HC_TENANT_PG_URL": "postgres://tinyzkp"}, check_host_python=True
    )
    assert (
        "HC_TENANT_PG_URL mirroring requires the host Python package psycopg"
        in failures
    )


def test_host_python_check_uses_explicit_interpreter_path():
    failures, _warnings = readiness.check_env(
        {"HC_TENANT_PG_URL": "postgres://tinyzkp"},
        check_host_python=True,
        host_python="/bin/false",
    )
    assert "HC_TENANT_PG_URL mirroring requires psycopg in /bin/false" in "\n".join(
        failures
    )


def test_host_python_check_accepts_current_interpreter_without_mirror():
    failures, _warnings = readiness.check_env(
        {},
        check_host_python=True,
        host_python=sys.executable,
    )
    assert failures == []


def test_production_mode_rejects_placeholder_secrets():
    failures, _warnings = _production_failures(
        {
            "STRIPE_SECRET_KEY": "sk_live_xxx",
            "STRIPE_WEBHOOK_SECRET": "whsec_xxx",
            "INTERNAL_SECRET": "CHANGE_ME_TO_A_RANDOM_STRING",
            "STRIPE_EXPECTED_ACCOUNT_ID": "acct_xxx",
            "STRIPE_EXPECTED_DISPLAY_NAME": "",
            "HC_EVALUATION_STORE_PATH": "",
            "HC_BACKUP_REMOTE": "",
        }
    )
    assert "STRIPE_SECRET_KEY is missing or still a placeholder" in failures
    assert "STRIPE_WEBHOOK_SECRET is missing or still a placeholder" in failures
    assert "INTERNAL_SECRET is missing or still a placeholder" in failures
    assert "STRIPE_EXPECTED_ACCOUNT_ID is missing or still a placeholder" in failures
    assert "HC_EVALUATION_STORE_PATH is missing or still a placeholder" in failures
    assert "TINYZKP_CONTRACT_BILLING_LEDGER_PATH is missing" in failures
    assert "off-host backups require HC_BACKUP_REMOTE" in failures


def test_production_mode_accepts_https_backup_ingest(tmp_path, monkeypatch):
    token_file = tmp_path / "backup-token"
    token_file.write_text("a" * 64, encoding="utf-8")
    token_file.chmod(0o600)
    monkeypatch.setattr(readiness.backup_env_exec, "FIXED_HTTP_TOKEN", token_file)
    env = _valid_production_env(tmp_path)
    env.pop("HC_BACKUP_REMOTE")
    env.update(
        {
            "HC_BACKUP_HTTP_URL": "https://backup.example/v1/backups",
            "HC_BACKUP_HTTP_TOKEN_FILE": str(token_file),
            "HC_BACKUP_HTTP_RETENTION_CONFIRMED": "1",
        }
    )
    failures, _warnings = readiness.check_env(
        env, production=True, check_host_python=True
    )
    assert failures == []


def test_production_host_rclone_probe_is_read_only_and_successful(
    tmp_path, monkeypatch
):
    env = _valid_production_env(tmp_path)
    rclone_config = tmp_path / "rclone.conf"
    rclone_config.write_text("[remote]\ntype = s3\n", encoding="utf-8")
    rclone_config.chmod(0o600)
    monkeypatch.setattr(
        readiness.backup_env_exec, "FIXED_RCLONE_CONFIG", rclone_config
    )
    calls = []
    monkeypatch.setattr(
        readiness.shutil,
        "which",
        lambda command: "/usr/local/bin/rclone" if command == "rclone" else None,
    )

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(readiness.subprocess, "run", fake_run)

    failures, _warnings = readiness.check_env(
        env, production=True, check_host_python=True
    )

    assert failures == []
    assert calls == [
        (
            [
                "/usr/local/bin/rclone",
                "lsd",
                "--max-depth",
                "1",
                "r2-crypt:tinyzkp",
            ],
            {
                "stdin": readiness.subprocess.DEVNULL,
                "stdout": readiness.subprocess.DEVNULL,
                "stderr": readiness.subprocess.DEVNULL,
                "timeout": 30,
                "check": False,
                "env": {
                    "PATH": readiness.backup_env_exec.FIXED_PATH,
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "RCLONE_CONFIG": str(rclone_config),
                },
            },
        )
    ]


def test_production_host_rejects_missing_rclone_for_configured_remote(
    tmp_path, monkeypatch
):
    env = _valid_production_env(tmp_path)
    monkeypatch.setattr(readiness.shutil, "which", lambda _command: None)

    failures, _warnings = readiness.check_env(
        env, production=True, check_host_python=True
    )

    assert "HC_BACKUP_REMOTE requires rclone on the production host" in failures


def test_production_host_rejects_unusable_rclone_remote(tmp_path, monkeypatch):
    env = _valid_production_env(tmp_path)
    rclone_config = tmp_path / "rclone.conf"
    rclone_config.write_text("[remote]\ntype = s3\n", encoding="utf-8")
    rclone_config.chmod(0o600)
    monkeypatch.setattr(
        readiness.backup_env_exec, "FIXED_RCLONE_CONFIG", rclone_config
    )
    monkeypatch.setattr(
        readiness.shutil, "which", lambda _command: "/usr/local/bin/rclone"
    )
    monkeypatch.setattr(
        readiness.subprocess,
        "run",
        lambda *_args, **_kwargs: types.SimpleNamespace(returncode=3),
    )

    failures, _warnings = readiness.check_env(
        env, production=True, check_host_python=True
    )

    assert (
        "HC_BACKUP_REMOTE is not configured, reachable, and readable by rclone"
        in failures
    )


def test_production_host_rejects_local_path_as_backup_remote(tmp_path, monkeypatch):
    env = _valid_production_env(tmp_path)
    env["HC_BACKUP_REMOTE"] = "/mnt/not-off-host"
    monkeypatch.setattr(
        readiness.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("invalid remote must not be probed"),
    )

    failures, _warnings = readiness.check_env(
        env, production=True, check_host_python=True
    )

    assert (
        "HC_BACKUP_REMOTE must name a configured rclone remote (name:path)"
        in failures
    )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        (
            {"HC_BACKUP_RETENTION_DAYS": "1 -delete"},
            "HC_BACKUP_RETENTION_DAYS must be an integer from 1 through 3650",
        ),
        (
            {"HC_BACKUP_REMOTE": 'r2-crypt:tinyzkp/"--config'},
            "HC_BACKUP_REMOTE is malformed",
        ),
    ],
)
def test_production_readiness_reuses_backup_value_validation(
    tmp_path, updates, message
):
    env = _valid_production_env(tmp_path)
    env.update(updates)

    failures, _warnings = readiness.check_env(env, production=True)

    assert any(
        failure.startswith("backup configuration is unsafe:")
        and message in failure
        for failure in failures
    )


def test_production_readiness_rejects_credentialed_backup_url(tmp_path):
    env = _valid_production_env(tmp_path)
    env.pop("HC_BACKUP_REMOTE")
    env.update(
        {
            "HC_BACKUP_HTTP_URL": "https://user@backup.example/v1",
            "HC_BACKUP_HTTP_TOKEN_FILE": "/secure/token",
            "HC_BACKUP_HTTP_RETENTION_CONFIRMED": "1",
        }
    )

    failures, _warnings = readiness.check_env(env, production=True)

    assert any(
        "credential-free HTTPS base URL" in failure for failure in failures
    )


def test_production_mode_rejects_insecure_or_partial_backup_ingest():
    failures, _warnings = _production_failures(
        {
            "STRIPE_SECRET_KEY": "sk_live_real",
            "STRIPE_WEBHOOK_SECRET": "whsec_real",
            "INTERNAL_SECRET": "random-internal-secret",
            "STRIPE_EXPECTED_ACCOUNT_ID": "acct_realaccount",
            "STRIPE_EXPECTED_DISPLAY_NAME": "LN Holdings",
            "HC_EVALUATION_STORE_PATH": "/opt/hc-stark/data/evaluation_applications.sqlite",
            "HC_BACKUP_HTTP_URL": "http://backup.example/v1/backups",
            "TINYZKP_MAINTENANCE_MODE": "1",
        }
    )
    assert "must be configured together" in failures
    assert "must use https" in failures


def test_production_mode_accepts_realistic_values(tmp_path):
    failures, _warnings = _production_failures(_valid_production_env(tmp_path))
    assert failures == ""


def test_production_rejects_noncanonical_stripe_values_and_weak_secret(tmp_path):
    env = _valid_production_env(tmp_path)
    env.update(
        {
            "STRIPE_SECRET_KEY": "sk_test_" + "a" * 32,
            "STRIPE_WEBHOOK_SECRET": "whsec_short",
            "STRIPE_EXPECTED_ACCOUNT_ID": "acct_short",
            "INTERNAL_SECRET": "weak-secret",
        }
    )

    failures, _warnings = readiness.check_env(env, production=True)
    report = "\n".join(failures)

    assert "canonical sk_live_" in report
    assert "canonical whsec_" in report
    assert "canonical acct_" in report
    assert "32-256 non-whitespace" in report


def test_production_validates_private_durable_evaluation_and_ledger_paths(tmp_path):
    env = _valid_production_env(tmp_path)
    evaluation = pathlib.Path(env["HC_EVALUATION_STORE_PATH"])
    ledger = pathlib.Path(env["TINYZKP_CONTRACT_BILLING_LEDGER_PATH"])

    evaluation.chmod(0o644)
    ledger.unlink()
    ledger.symlink_to(evaluation)
    failures, _warnings = readiness.check_env(env, production=True)
    report = "\n".join(failures)
    assert "HC_EVALUATION_STORE_PATH must be owner-only" in report
    assert (
        "TINYZKP_CONTRACT_BILLING_LEDGER_PATH must be a regular non-symlink" in report
    )

    ledger.unlink()
    ledger.write_bytes(b"sqlite-placeholder")
    ledger.chmod(0o600)
    evaluation.chmod(0o400)
    failures, _warnings = readiness.check_env(env, production=True)
    assert any(
        "HC_EVALUATION_STORE_PATH must be owner-writable" in item for item in failures
    )

    evaluation.chmod(0o600)
    env["TINYZKP_CONTRACT_BILLING_LEDGER_PATH"] = "relative.sqlite"
    failures, _warnings = readiness.check_env(env, production=True)
    assert any("absolute durable path" in failure for failure in failures)


def test_production_mode_rejects_partial_annual_release_authorization():
    failures, _warnings = _production_failures(
        {
            "STRIPE_SECRET_KEY": "sk_live_real",
            "STRIPE_WEBHOOK_SECRET": "whsec_real",
            "INTERNAL_SECRET": "random-internal-secret",
            "STRIPE_EXPECTED_ACCOUNT_ID": "acct_realaccount",
            "STRIPE_EXPECTED_DISPLAY_NAME": "LN Holdings",
            "HC_EVALUATION_STORE_PATH": "/opt/hc-stark/data/evaluation_applications.sqlite",
            "HC_BACKUP_REMOTE": "r2-crypt:tinyzkp",
            "TINYZKP_MAINTENANCE_MODE": "1",
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION": "/private/authorization.json",
        }
    )
    assert "requires all four path/digest settings" in failures


def test_production_host_checks_annual_release_artifacts_and_cosign(
    tmp_path, monkeypatch
):
    env = _valid_production_env(tmp_path)
    authorization, _bundle = _configure_release(env, tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    cosign = fake_bin / "cosign"
    cosign.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cosign.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")
    failures, _warnings = readiness.check_env(
        env,
        production=True,
        check_host_python=False,
    )
    assert failures == []

    invalid = _release_authorization()
    invalid["status"] = "blocked"
    authorization.write_text(json.dumps(invalid, sort_keys=True), encoding="utf-8")
    env["TINYZKP_BACKEND_RELEASE_AUTHORIZATION_SHA256"] = hashlib.sha256(
        authorization.read_bytes()
    ).hexdigest()
    failures, _warnings = readiness.check_env(
        env,
        production=True,
        check_host_python=False,
    )
    assert "failed contract_billing validation" in "\n".join(failures)
    assert "authorization is not ready" in "\n".join(failures)

    authorization.write_text(
        json.dumps(_release_authorization(), sort_keys=True), encoding="utf-8"
    )
    env["TINYZKP_BACKEND_RELEASE_AUTHORIZATION_SHA256"] = hashlib.sha256(
        authorization.read_bytes()
    ).hexdigest()
    monkeypatch.setenv("PATH", str(tmp_path / "no-cosign"))
    failures, _warnings = readiness.check_env(
        env,
        production=True,
        check_host_python=False,
    )
    assert "cosign is required" in "\n".join(failures)


def test_production_checks_release_artifacts_without_host_python_flag(
    tmp_path,
):
    env = _valid_production_env(tmp_path)
    env.update(
        {
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION": str(tmp_path / "missing.json"),
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_SHA256": "a" * 64,
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE": str(
                tmp_path / "missing.sigstore.json"
            ),
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE_SHA256": "b" * 64,
        }
    )
    failures, _warnings = readiness.check_env(
        env,
        production=True,
        check_host_python=False,
    )
    assert any("failed contract_billing validation" in item for item in failures)
    assert any("unavailable or unsafe" in item for item in failures)


def test_production_mode_rejects_noncanonical_release_digests():
    failures, _warnings = _production_failures(
        {
            "STRIPE_SECRET_KEY": "sk_live_real",
            "STRIPE_WEBHOOK_SECRET": "whsec_real",
            "INTERNAL_SECRET": "random-internal-secret",
            "STRIPE_EXPECTED_ACCOUNT_ID": "acct_realaccount",
            "STRIPE_EXPECTED_DISPLAY_NAME": "LN Holdings",
            "HC_EVALUATION_STORE_PATH": "/opt/hc-stark/data/evaluation_applications.sqlite",
            "HC_BACKUP_REMOTE": "r2-crypt:tinyzkp",
            "TINYZKP_MAINTENANCE_MODE": "1",
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION": "/private/authorization.json",
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_SHA256": "A" * 64,
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE": "/private/authorization.sigstore.json",
            "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE_SHA256": "b" * 64,
        }
    )
    assert "must be a lowercase SHA-256 digest" in failures


def test_production_mode_requires_fail_closed_webhook_maintenance():
    failures, _warnings = _production_failures(
        {
            "STRIPE_SECRET_KEY": "sk_live_real",
            "STRIPE_WEBHOOK_SECRET": "whsec_real",
            "INTERNAL_SECRET": "random-internal-secret",
            "STRIPE_EXPECTED_ACCOUNT_ID": "acct_realaccount",
            "STRIPE_EXPECTED_DISPLAY_NAME": "LN Holdings",
            "HC_EVALUATION_STORE_PATH": "/opt/hc-stark/data/evaluation_applications.sqlite",
            "HC_BACKUP_REMOTE": "r2-crypt:tinyzkp",
            "TINYZKP_MAINTENANCE_MODE": "0",
        }
    )
    assert "TINYZKP_MAINTENANCE_MODE=1 is required" in failures


def test_production_mode_rejects_all_outbound_email_configuration():
    failures, _warnings = _production_failures(
        {
            "STRIPE_SECRET_KEY": "sk_live_real",
            "STRIPE_WEBHOOK_SECRET": "whsec_real",
            "INTERNAL_SECRET": "random-internal-secret",
            "STRIPE_EXPECTED_ACCOUNT_ID": "acct_realaccount",
            "STRIPE_EXPECTED_DISPLAY_NAME": "LN Holdings",
            "HC_EVALUATION_STORE_PATH": "/opt/hc-stark/data/evaluation_applications.sqlite",
            "HC_BACKUP_REMOTE": "r2-crypt:tinyzkp",
            "TINYZKP_MAINTENANCE_MODE": "1",
            "TINYZKP_OUTBOUND_EMAIL_ENABLED": "1",
            "TINYZKP_CUSTOMER_EMAILS_ENABLED": "true",
            "SMTP_FROM": "founder@unrelated.example",
            "CONTACT_TO_EMAIL": "founder@unrelated.example",
        }
    )
    assert "backend recovery forbids outbound email configuration" in failures
    assert "TINYZKP_OUTBOUND_EMAIL_ENABLED" in failures
    assert "TINYZKP_CUSTOMER_EMAILS_ENABLED" in failures
    assert "SMTP_FROM" in failures
    assert "CONTACT_TO_EMAIL" in failures


def test_production_mode_rejects_legacy_prices_and_meter_overrides():
    failures, _warnings = _production_failures(
        {
            "STRIPE_SECRET_KEY": "sk_live_real",
            "STRIPE_WEBHOOK_SECRET": "whsec_real",
            "INTERNAL_SECRET": "random-internal-secret",
            "STRIPE_EXPECTED_ACCOUNT_ID": "acct_realaccount",
            "STRIPE_EXPECTED_DISPLAY_NAME": "LN Holdings",
            "HC_EVALUATION_STORE_PATH": "/opt/hc-stark/data/evaluation_applications.sqlite",
            "HC_BACKUP_REMOTE": "r2-crypt:tinyzkp",
            "TINYZKP_MAINTENANCE_MODE": "1",
            "STRIPE_PRICE_ID_PRO": "price_legacy",
            "STRIPE_METER_EVENT_NAME": "proof_usage",
            "TINYZKP_ALLOW_LEGACY_METER_EVENTS": "1",
        }
    )
    assert "backend recovery forbids legacy billing configuration" in failures
    assert "STRIPE_PRICE_ID_PRO" in failures
    assert "STRIPE_METER_EVENT_NAME" in failures
    assert "TINYZKP_ALLOW_LEGACY_METER_EVENTS" in failures
