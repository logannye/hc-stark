import cloudflare_pages_secret_check as check


def test_parse_secret_names_from_wrangler_output():
    output = """
     ⛅️ wrangler 4.85.0
    The "production" environment has access to:
      - INTERNAL_SECRET: Value Encrypted
      - STRIPE_SECRET_KEY: Value Encrypted
      - STRIPE_PRICE_ID_PILOT: Value Encrypted
      - ignored_lowercase: Value Encrypted
    """

    assert check.parse_secret_names(output) == {
        "INTERNAL_SECRET",
        "STRIPE_SECRET_KEY",
        "STRIPE_PRICE_ID_PILOT",
    }


def test_validate_secret_names_accepts_complete_inventory():
    secrets = {
        "INTERNAL_SECRET",
        "STRIPE_SECRET_KEY",
        "STRIPE_PRICE_ID_TRACE_STEP_METERED",
        "STRIPE_PRICE_ID_DEVELOPER",
        "STRIPE_PRICE_ID_PRO",
        "STRIPE_PRICE_ID_SCALE",
        "STRIPE_PRICE_ID_PILOT",
        "STRIPE_PRICE_ID_METERED",
        "TINYZKP_DEMO_API_KEY",
    }

    checks = check.validate_secret_names(secrets)

    assert not [item for item in checks if item.status == "FAIL"]


def test_validate_secret_names_accepts_inline_pilot_checkout_without_pilot_price():
    secrets = {
        "INTERNAL_SECRET",
        "STRIPE_SECRET_KEY",
        "STRIPE_PRICE_ID_TRACE_STEP_METERED",
        "STRIPE_PRICE_ID_DEVELOPER",
        "STRIPE_PRICE_ID_PRO",
        "STRIPE_PRICE_ID_SCALE",
        "STRIPE_PRICE_ID_METERED",
        "TINYZKP_DEMO_API_KEY",
    }

    checks = check.validate_secret_names(secrets)

    assert not [item for item in checks if item.status == "FAIL"]
