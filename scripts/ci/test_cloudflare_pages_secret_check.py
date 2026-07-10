import cloudflare_pages_secret_check as check


def test_parse_secret_names_returns_names_only():
    output = """
      - INTERNAL_SECRET: Value Encrypted
      - STRIPE_SECRET_KEY: Value Encrypted
      noise that must be ignored
    """
    assert check.parse_secret_names(output) == {"INTERNAL_SECRET", "STRIPE_SECRET_KEY"}


def test_recovery_inventory_requires_internal_secret_and_rejects_legacy_secrets():
    checks = check.validate_secret_names({"INTERNAL_SECRET"})
    assert all(item.status == "PASS" for item in checks)

    checks = check.validate_secret_names(
        {"INTERNAL_SECRET", "STRIPE_SECRET_KEY", "STRIPE_PRICE_ID_PRO", "TINYZKP_DEMO_API_KEY"}
    )
    failure = next(item for item in checks if item.name == "legacy billing/demo secrets")
    assert failure.status == "FAIL"
    assert "STRIPE_PRICE_ID_PRO" in failure.detail


def test_missing_internal_secret_fails():
    checks = check.validate_secret_names(set())
    internal = next(item for item in checks if item.name == "INTERNAL_SECRET")
    assert internal.status == "FAIL"
