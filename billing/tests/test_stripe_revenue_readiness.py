import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path


BILLING_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = BILLING_DIR / "stripe_revenue_readiness.py"
sys.path.insert(0, str(BILLING_DIR))
spec = importlib.util.spec_from_file_location("stripe_revenue_readiness", MODULE_PATH)
readiness = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = readiness
spec.loader.exec_module(readiness)


def args(**overrides):
    defaults = {
        "stripe_bin": "/opt/homebrew/bin/stripe",
        "stripe_project_name": "",
        "account_source": "cli",
        "stripe_api_key_env": "STRIPE_SECRET_KEY",
        "auto_discover_profile": False,
        "stripe_config_path": readiness.stripe_account_context_check.DEFAULT_CONFIG_PATH,
        "expected_stripe_display_name": "LN Holdings",
        "lookback_hours": 168,
        "timeout": 30,
        "command_timeout": 120,
        "strict_catalog": False,
        "sync_pipeline": False,
        "setup_catalog": "none",
        "push_cloudflare": False,
        "plan_only": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def completed(command, stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def test_plan_only_lists_readiness_steps_without_account_check():
    results = readiness.run_readiness(
        args(
            plan_only=True,
            sync_pipeline=True,
            setup_catalog="pilot",
            push_cloudflare=True,
            stripe_project_name="tinyzkp-prod",
        ),
        account_runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("account check should not run")),
    )

    assert [result.status for result in results] == ["PLAN", "PLAN", "PLAN", "PLAN"]
    assert results[0].name == "Stripe revenue ops audit"
    assert results[1].name == "Stripe checkout monitor"
    assert results[2].name == "Stripe checkout pipeline sync"
    assert results[3].command == [
        "bash",
        "billing/setup_pilot_price.sh",
        "--stripe-cli",
        "--stripe-bin",
        "/opt/homebrew/bin/stripe",
        "--stripe-project-name",
        "tinyzkp-prod",
        "--push-cloudflare",
    ]


def test_api_plan_only_skips_cli_catalog_audit_for_read_only_growth_path():
    results = readiness.run_readiness(
        args(plan_only=True, account_source="api", sync_pipeline=True),
        account_runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("account check should not run")),
    )

    assert [result.status for result in results] == ["PLAN", "PLAN"]
    assert [result.name for result in results] == [
        "Stripe checkout monitor",
        "Stripe checkout pipeline sync",
    ]
    assert "--account-source api" in results[0].detail


def test_auto_discover_profile_updates_planned_child_commands(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        """
[default]
display_name = 'Galen Health'

[tinyzkp-prod]
display_name = 'LN Holdings'
""",
        encoding="utf-8",
    )

    results = readiness.run_readiness(
        args(plan_only=True, auto_discover_profile=True, stripe_config_path=config, sync_pipeline=True),
        account_runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("account check should not run")),
    )

    assert results[0].status == "PASS"
    assert results[0].name == "Stripe profile discovery"
    assert all(
        result.status == "PLAN" and "--stripe-project-name tinyzkp-prod" in result.detail
        for result in results[1:]
    )


def test_auto_discover_profile_reports_missing_tinyzkp_profile_before_account_check(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        """
[default]
display_name = 'Galen Health'
account_id = 'acct_secret123456'
""",
        encoding="utf-8",
    )

    results = readiness.run_readiness(
        args(auto_discover_profile=True, stripe_config_path=config),
        account_runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("account check should not run")),
    )

    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].name == "Stripe profile discovery"
    assert "Galen Health" in results[0].detail
    assert "acct_secret123456" not in results[0].detail


def test_run_readiness_stops_before_commands_when_account_context_fails():
    def account_runner(command, **_kwargs):
        return completed(
            command,
            stdout="""
project-name = 'default'

[default]
display_name = 'Galen Health'
account_id = 'acct_secret123456'
""",
        )

    def unexpected_runner(*_args, **_kwargs):
        raise AssertionError("readiness commands should not run on a mismatched account")

    results = readiness.run_readiness(args(), runner=unexpected_runner, account_runner=account_runner)

    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].name == "Stripe account context"
    assert "Galen Health" in results[0].detail
    assert "acct_secret123456" not in results[0].detail


def test_run_readiness_executes_audit_monitor_sync_and_full_setup_after_account_pass():
    commands = []

    def account_runner(command, **_kwargs):
        return completed(
            command,
            stdout="""
project-name = 'default'

[default]
display_name = 'LN Holdings'
account_id = 'acct_secret123456'
""",
        )

    def runner(command, **_kwargs):
        commands.append(command)
        return completed(command, stdout="ok")

    results = readiness.run_readiness(
        args(sync_pipeline=True, setup_catalog="full", strict_catalog=True, stripe_project_name="tinyzkp-prod"),
        runner=runner,
        account_runner=account_runner,
    )

    assert [result.status for result in results] == ["PASS", "PASS", "PASS", "PASS", "PASS"]
    assert commands[0][:2] == [sys.executable, "billing/stripe_revenue_ops_audit.py"]
    assert "--strict-catalog" in commands[0]
    assert "--stripe-project-name" in commands[0]
    assert "tinyzkp-prod" in commands[0]
    assert commands[1][:2] == [sys.executable, "billing/stripe_checkout_monitor.py"]
    assert commands[2][:2] == [sys.executable, "scripts/marketing/sync_stripe_checkout_pipeline.py"]
    assert commands[3] == [
        "bash",
        "billing/setup_stripe_products.sh",
        "--stripe-cli",
        "--stripe-bin",
        "/opt/homebrew/bin/stripe",
        "--stripe-project-name",
        "tinyzkp-prod",
    ]


def test_run_readiness_redacts_failed_step_output():
    def account_runner(command, **_kwargs):
        return completed(
            command,
            stdout="""
project-name = 'default'

[default]
display_name = 'LN Holdings'
account_id = 'acct_secret123456'
""",
        )

    def runner(command, **_kwargs):
        return completed(command, stderr="buyer@example.com failed on cs_live_secret with sk_live_secretvalue", returncode=1)

    results = readiness.run_readiness(args(), runner=runner, account_runner=account_runner)

    assert len(results) == 2
    assert results[1].status == "FAIL"
    assert "buyer@example.com" not in results[1].detail
    assert "cs_live_secret" not in results[1].detail
    assert "sk_live_secretvalue" not in results[1].detail
    assert "[redacted-email]" in results[1].detail
    assert "[redacted-id]" in results[1].detail
    assert "[redacted-key]" in results[1].detail
