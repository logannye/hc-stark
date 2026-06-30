import importlib.util
import subprocess
import sys
from pathlib import Path


BILLING_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = BILLING_DIR / "stripe_account_context_check.py"
sys.path.insert(0, str(BILLING_DIR))
spec = importlib.util.spec_from_file_location("stripe_account_context_check", MODULE_PATH)
account_check = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = account_check
spec.loader.exec_module(account_check)


def completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(("stripe",), returncode, stdout=stdout, stderr=stderr)


def test_parse_config_uses_active_project_section():
    context = account_check.parse_config(
        """
color = ''
project-name = 'tinyzkp-prod'

[default]
account_id = 'acct_wrong123456'
display_name = 'Other Account'

[tinyzkp-prod]
account_id = 'acct_tinyzkp123456'
display_name = 'LN Holdings'
"""
    )

    assert context.project_name == "tinyzkp-prod"
    assert context.display_name == "LN Holdings"
    assert context.account_id == "acct_tinyzkp123456"


def test_parse_profiles_lists_named_profiles_without_keys():
    profiles = account_check.parse_profiles(
        """
project-name = 'default'

[default]
account_id = 'acct_wrong123456'
display_name = 'Galen Health'
live_mode_api_key = 'sk_live_secretvalue'

[tinyzkp-prod]
account_id = 'acct_tinyzkp123456'
display_name = 'LN Holdings'
"""
    )

    assert [(profile.project_name, profile.display_name) for profile in profiles] == [
        ("default", "Galen Health"),
        ("tinyzkp-prod", "LN Holdings"),
    ]
    assert account_check.safe_profile_dict(profiles[1]) == {
        "project_name": "tinyzkp-prod",
        "display_name": "LN Holdings",
    }


def test_discover_profile_finds_single_matching_display_name(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        """
[default]
display_name = 'Galen Health'
account_id = 'acct_wrong123456'

[tinyzkp-prod]
display_name = 'LN Holdings'
account_id = 'acct_tinyzkp123456'
""",
        encoding="utf-8",
    )

    result = account_check.discover_profile(expected_display_name="LN Holdings", config_path=config)

    assert result.status == "PASS"
    assert result.project_name == "tinyzkp-prod"
    assert result.display_name == "LN Holdings"
    assert "acct_tinyzkp123456" not in result.detail


def test_discover_profile_reports_available_profiles_without_account_ids(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        """
[default]
display_name = 'Galen Health'
account_id = 'acct_secret123456'
""",
        encoding="utf-8",
    )

    result = account_check.discover_profile(expected_display_name="LN Holdings", config_path=config)

    assert result.status == "FAIL"
    assert "Galen Health" in result.detail
    assert "acct_secret123456" not in result.detail


def test_run_check_passes_when_display_name_contains_expected_name():
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        return completed(
            stdout="""
project-name = 'default'

[default]
display_name = 'LN Holdings'
account_id = 'acct_tinyzkp123456'
"""
        )

    result = account_check.run_check(
        stripe_bin="/opt/homebrew/bin/stripe",
        stripe_project_name="tinyzkp-prod",
        expected_display_name="LN Holdings",
        runner=runner,
    )

    assert result.status == "PASS"
    assert "LN Holdings" in result.detail
    assert result.display_name == "LN Holdings"
    assert calls[0][-2:] == ("--project-name", "tinyzkp-prod")


def test_run_check_fails_on_wrong_profile_without_printing_account_id():
    def runner(command, **_kwargs):
        return completed(
            stdout="""
project-name = 'default'

[default]
display_name = 'Galen Health'
account_id = 'acct_secret123456'
"""
        )

    result = account_check.run_check(expected_display_name="LN Holdings", runner=runner)

    assert result.status == "FAIL"
    assert "Galen Health" in result.detail
    assert "LN Holdings" in result.detail
    assert "acct_secret123456" not in result.detail


def test_run_check_redacts_cli_errors():
    def runner(command, **_kwargs):
        return completed(
            stderr="buyer@example.com cannot access sk_live_secretvalue on acct_secret123456",
            returncode=1,
        )

    result = account_check.run_check(expected_display_name="LN Holdings", runner=runner)

    assert result.status == "FAIL"
    assert "buyer@example.com" not in result.detail
    assert "sk_live_secretvalue" not in result.detail
    assert "acct_secret123456" not in result.detail
    assert "[redacted-email]" in result.detail
    assert "[redacted-key]" in result.detail
    assert "[redacted-id]" in result.detail


def test_empty_expected_display_name_fails_closed():
    result = account_check.run_check(expected_display_name=" ")

    assert result.status == "FAIL"
    assert "empty" in result.detail


def test_run_check_api_passes_when_display_name_matches(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fake")
    seen = {}

    def fake_retrieve():
        seen["api_key"] = account_check.stripe.api_key
        return {
            "settings": {"dashboard": {"display_name": "LN Holdings"}},
            "business_profile": {"name": "TinyZKP"},
            "id": "acct_secret123456",
        }

    monkeypatch.setattr(account_check.stripe.Account, "retrieve", fake_retrieve)

    result = account_check.run_check(account_source="api", expected_display_name="LN Holdings")

    assert result.status == "PASS"
    assert result.display_name == "LN Holdings"
    assert seen["api_key"] == "sk_test_fake"
    assert "acct_secret123456" not in result.detail


def test_run_check_api_fails_without_api_key_env(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)

    result = account_check.run_check(account_source="api", stripe_api_key_env="STRIPE_SECRET_KEY")

    assert result.status == "FAIL"
    assert "STRIPE_SECRET_KEY" in result.detail
    assert "not set" in result.detail


def test_run_check_api_fails_on_wrong_account_without_ids(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fake")

    def fake_retrieve():
        return {
            "settings": {"dashboard": {"display_name": "Galen Health"}},
            "business_profile": {"name": "Galen Health"},
            "id": "acct_secret123456",
        }

    monkeypatch.setattr(account_check.stripe.Account, "retrieve", fake_retrieve)

    result = account_check.run_check(account_source="api", expected_display_name="LN Holdings")

    assert result.status == "FAIL"
    assert "Galen Health" in result.detail
    assert "LN Holdings" in result.detail
    assert "acct_secret123456" not in result.detail
