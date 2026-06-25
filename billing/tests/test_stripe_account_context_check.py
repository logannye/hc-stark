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
display_name = 'TinyZKP LLC'
"""
    )

    assert context.project_name == "tinyzkp-prod"
    assert context.display_name == "TinyZKP LLC"
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
display_name = 'TinyZKP Production'
"""
    )

    assert [(profile.project_name, profile.display_name) for profile in profiles] == [
        ("default", "Galen Health"),
        ("tinyzkp-prod", "TinyZKP Production"),
    ]
    assert account_check.safe_profile_dict(profiles[1]) == {
        "project_name": "tinyzkp-prod",
        "display_name": "TinyZKP Production",
    }


def test_discover_profile_finds_single_matching_display_name(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        """
[default]
display_name = 'Galen Health'
account_id = 'acct_wrong123456'

[tinyzkp-prod]
display_name = 'TinyZKP Production'
account_id = 'acct_tinyzkp123456'
""",
        encoding="utf-8",
    )

    result = account_check.discover_profile(expected_display_name="TinyZKP", config_path=config)

    assert result.status == "PASS"
    assert result.project_name == "tinyzkp-prod"
    assert result.display_name == "TinyZKP Production"
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

    result = account_check.discover_profile(expected_display_name="TinyZKP", config_path=config)

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
display_name = 'TinyZKP Production'
account_id = 'acct_tinyzkp123456'
"""
        )

    result = account_check.run_check(
        stripe_bin="/opt/homebrew/bin/stripe",
        stripe_project_name="tinyzkp-prod",
        expected_display_name="TinyZKP",
        runner=runner,
    )

    assert result.status == "PASS"
    assert "TinyZKP Production" in result.detail
    assert result.display_name == "TinyZKP Production"
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

    result = account_check.run_check(expected_display_name="TinyZKP", runner=runner)

    assert result.status == "FAIL"
    assert "Galen Health" in result.detail
    assert "TinyZKP" in result.detail
    assert "acct_secret123456" not in result.detail


def test_run_check_redacts_cli_errors():
    def runner(command, **_kwargs):
        return completed(
            stderr="buyer@example.com cannot access sk_live_secretvalue on acct_secret123456",
            returncode=1,
        )

    result = account_check.run_check(expected_display_name="TinyZKP", runner=runner)

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
