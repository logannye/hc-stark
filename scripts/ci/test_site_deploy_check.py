import pathlib

import pytest

import site_deploy_check as check


def test_placeholder_detects_common_secret_placeholders():
    assert check.placeholder("")
    assert check.placeholder("CHANGE_ME")
    assert check.placeholder("sk_live_xxx")
    assert check.placeholder("price_xxx")
    assert not check.placeholder("price_123_real")


def test_parse_env_file_supports_export_and_quotes(tmp_path):
    env_file = tmp_path / "pages.env"
    env_file.write_text(
        """
        # comment
        export INTERNAL_SECRET='secret-value'
        TINYZKP_RELEASE_SHA=abc123
        """,
        encoding="utf-8",
    )
    parsed = check.parse_env_file(env_file)
    assert parsed["INTERNAL_SECRET"] == "secret-value"
    assert parsed["TINYZKP_RELEASE_SHA"] == "abc123"


def test_validate_production_bindings_accepts_complete_set():
    bindings = {
        "INTERNAL_SECRET": "secret-value",
    }
    failures = []
    check.validate_production_bindings(bindings, failures)
    assert failures == []


def test_validate_production_bindings_requires_no_application_secrets():
    bindings = {}
    failures = []
    check.validate_production_bindings(bindings, failures)
    assert failures == []


def test_static_check_classifies_current_site_bindings():
    failures = []
    check.validate_wrangler(failures)
    check.validate_required_files(failures)
    refs = check.validate_functions(failures)
    assert failures == []
    assert check.REQUIRED_BINDINGS <= refs
    assert refs == {"ASSETS"}
    assert "guard-social.png" in check.REQUIRED_FILES
    assert "favicon.svg" in check.REQUIRED_FILES


def test_load_bindings_reports_missing_file(tmp_path):
    missing = pathlib.Path(tmp_path / "missing.env")
    try:
        check.load_bindings(missing)
    except FileNotFoundError as exc:
        assert str(missing) in str(exc)
    else:
        raise AssertionError("missing bindings file did not raise")


def _private_pages_bindings(tmp_path, content="INTERNAL_SECRET=private-value\n"):
    path = tmp_path / "pages-private.env"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_production_pages_bindings_use_strict_all_key_data_parser(tmp_path):
    path = _private_pages_bindings(
        tmp_path,
        "INTERNAL_SECRET=private-value\nWEBHOOK_BASE_URL=https://webhook.tinyzkp.com\n",
    )

    assert check.load_bindings(path, production=True) == {
        "INTERNAL_SECRET": "private-value",
        "WEBHOOK_BASE_URL": "https://webhook.tinyzkp.com",
    }


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("INTERNAL_SECRET=one\nINTERNAL_SECRET=two\n", "duplicated"),
        ("export INTERNAL_SECRET=value\n", "data-only KEY=value"),
        ("source /tmp/not-data\n", "data-only KEY=value"),
        ("INTERNAL_SECRET=" + "a" * (64 * 1024) + "\n", "exceeds 64 KiB"),
    ],
)
def test_production_pages_bindings_reject_duplicates_shell_and_oversize(
    tmp_path, content, message
):
    path = _private_pages_bindings(tmp_path, content)
    with pytest.raises(check.ProductionEnvError, match=message):
        check.load_bindings(path, production=True)


def test_production_pages_bindings_reject_mode_symlink_and_wrong_owner(
    tmp_path, monkeypatch
):
    target = _private_pages_bindings(tmp_path)
    target.chmod(0o400)
    with pytest.raises(check.ProductionEnvError, match="mode 0600"):
        check.load_bindings(target, production=True)

    target.chmod(0o600)
    symlink = tmp_path / "pages-link.env"
    symlink.symlink_to(target)
    with pytest.raises(check.ProductionEnvError, match="unavailable or unsafe"):
        check.load_bindings(symlink, production=True)

    actual_owner = target.stat().st_uid
    monkeypatch.setattr(check.os, "geteuid", lambda: actual_owner + 1)
    with pytest.raises(check.ProductionEnvError, match="current-owner|current operator"):
        check.load_bindings(target, production=True)
