import importlib.util
import sys

import deploy_readiness_check as readiness


def _failures(env, *, check_host_python=False):
    failures, warnings = readiness.check_env(env, check_host_python=check_host_python)
    return "\n".join(failures), "\n".join(warnings)


def _production_failures(env):
    failures, warnings = readiness.check_env(env, production=True)
    return "\n".join(failures), "\n".join(warnings)


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
    assert "HC_SERVER_PROVE_DISPATCH=shared requires HC_SERVER_JOB_INDEX_SOURCE=postgres" in failures
    assert "HC_SERVER_PROVE_DISPATCH=shared requires HC_JOB_INDEX_PG_URL or HC_SERVER_PG_URL" in failures
    assert "HC_SERVER_PROVE_DISPATCH=shared requires HC_JOB_WORKER_USAGE_PG_URL or HC_SERVER_PG_URL" in failures


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


def test_tenant_pg_required_needs_effective_url():
    failures, _warnings = _failures({"HC_TENANT_PG_REQUIRED": "1"})
    assert "HC_TENANT_PG_REQUIRED=1 requires HC_TENANT_PG_URL or HC_SERVER_AUTH_PG_URL" in failures


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
    failures, _warnings = _failures({"HC_TENANT_PG_URL": "postgres://tinyzkp"}, check_host_python=True)
    assert "HC_TENANT_PG_URL mirroring requires the host Python package psycopg" in failures


def test_host_python_check_uses_explicit_interpreter_path():
    failures, _warnings = readiness.check_env(
        {"HC_TENANT_PG_URL": "postgres://tinyzkp"},
        check_host_python=True,
        host_python="/bin/false",
    )
    assert "HC_TENANT_PG_URL mirroring requires psycopg in /bin/false" in "\n".join(failures)


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
    assert "off-host backups require HC_BACKUP_REMOTE" in failures


def test_production_mode_accepts_https_backup_ingest(tmp_path):
    token_file = tmp_path / "backup-token"
    token_file.write_text("a" * 64, encoding="utf-8")
    token_file.chmod(0o600)
    env = {
        "STRIPE_SECRET_KEY": "sk_live_real",
        "STRIPE_WEBHOOK_SECRET": "whsec_real",
        "INTERNAL_SECRET": "random-internal-secret",
        "STRIPE_EXPECTED_ACCOUNT_ID": "acct_realaccount",
        "STRIPE_EXPECTED_DISPLAY_NAME": "LN Holdings",
        "HC_EVALUATION_STORE_PATH": "/opt/hc-stark/data/evaluation_applications.sqlite",
        "HC_BACKUP_HTTP_URL": "https://backup.example/v1/backups",
        "HC_BACKUP_HTTP_TOKEN_FILE": str(token_file),
        "TINYZKP_MAINTENANCE_MODE": "1",
    }
    failures, _warnings = readiness.check_env(env, production=True, check_host_python=True)
    assert failures == []


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


def test_production_mode_accepts_realistic_values():
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
        }
    )
    assert failures == ""


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
