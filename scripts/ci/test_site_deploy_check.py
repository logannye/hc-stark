import pathlib

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
        STRIPE_SECRET_KEY="sk_live_real"
        TINYZKP_DEMO_API_KEY=tzk_demo
        """,
        encoding="utf-8",
    )
    parsed = check.parse_env_file(env_file)
    assert parsed["INTERNAL_SECRET"] == "secret-value"
    assert parsed["STRIPE_SECRET_KEY"] == "sk_live_real"
    assert parsed["TINYZKP_DEMO_API_KEY"] == "tzk_demo"


def test_validate_production_bindings_accepts_complete_set():
    bindings = {
        "INTERNAL_SECRET": "secret-value",
        "STRIPE_SECRET_KEY": "sk_live_real",
        "STRIPE_PRICE_ID_TRACE_STEP_METERED": "price_trace",
        "STRIPE_PRICE_ID_DEVELOPER": "price_developer",
        "STRIPE_PRICE_ID_PRO": "price_pro",
        "STRIPE_PRICE_ID_SCALE": "price_scale",
        "STRIPE_PRICE_ID_METERED": "price_metered",
        "TINYZKP_DEMO_API_KEY": "tzk_demo",
    }
    failures = []
    check.validate_production_bindings(bindings, failures)
    assert failures == []


def test_validate_production_bindings_requires_one_proof_meter_price():
    bindings = {
        "INTERNAL_SECRET": "secret-value",
        "STRIPE_SECRET_KEY": "sk_live_real",
        "STRIPE_PRICE_ID_TRACE_STEP_METERED": "price_trace",
        "STRIPE_PRICE_ID_DEVELOPER": "price_developer",
        "STRIPE_PRICE_ID_PRO": "price_pro",
        "STRIPE_PRICE_ID_SCALE": "price_scale",
        "TINYZKP_DEMO_API_KEY": "tzk_demo",
    }
    failures = []
    check.validate_production_bindings(bindings, failures)
    assert "requires one of: STRIPE_PRICE_ID_METERED, STRIPE_PRICE_ID" in "\n".join(failures)


def test_static_check_classifies_current_site_bindings():
    failures = []
    check.validate_wrangler(failures)
    check.validate_required_files(failures)
    refs = check.validate_functions(failures)
    assert failures == []
    assert check.REQUIRED_BINDINGS <= refs
    assert "WEBHOOK_BASE_URL" in refs
    assert "og-image.png" in check.REQUIRED_FILES
    assert "favicon.svg" in check.REQUIRED_FILES


def test_load_bindings_reports_missing_file(tmp_path):
    missing = pathlib.Path(tmp_path / "missing.env")
    try:
        check.load_bindings(missing)
    except FileNotFoundError as exc:
        assert str(missing) in str(exc)
    else:
        raise AssertionError("missing bindings file did not raise")
