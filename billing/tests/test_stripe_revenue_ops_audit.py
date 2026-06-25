import importlib.util
import argparse
import sys
from pathlib import Path


BILLING_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = BILLING_DIR / "stripe_revenue_ops_audit.py"
sys.path.insert(0, str(BILLING_DIR))
spec = importlib.util.spec_from_file_location("stripe_revenue_ops_audit", MODULE_PATH)
audit = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def _product(name):
    return {"id": "prod_secret", "name": name, "active": True}


def _price(nickname, amount=None, interval=None, usage_type=None, currency="usd"):
    price = {
        "id": "price_secret",
        "nickname": nickname,
        "active": True,
        "currency": currency,
        "unit_amount": amount,
    }
    if interval or usage_type:
        price["recurring"] = {"interval": interval, "usage_type": usage_type}
    return price


def _meter(event_name):
    return {"id": "mtr_secret", "event_name": event_name, "status": "active"}


def test_evaluate_accepts_sellable_inline_pilot_with_catalog_warnings():
    checks = audit.evaluate(
        products_payload={
            "data": [
                _product("TinyZKP Developer"),
                _product("TinyZKP Scale"),
                _product("TinyZKP Proof Generation"),
                _product("TinyZKP Team"),
            ]
        },
        meters_payload={"data": [_meter("proof_usage")]},
        prices_payload={
            "data": [
                _price("Pro Monthly", 19900, "month", "licensed"),
                _price("Researcher Monthly", 4900, "month", "licensed"),
            ]
        },
        secret_names={
            "INTERNAL_SECRET",
            "STRIPE_SECRET_KEY",
            "STRIPE_PRICE_ID_TRACE_STEP_METERED",
            "STRIPE_PRICE_ID_DEVELOPER",
            "STRIPE_PRICE_ID_PRO",
            "STRIPE_PRICE_ID_SCALE",
            "STRIPE_PRICE_ID_METERED",
            "TINYZKP_DEMO_API_KEY",
        },
        pilot_capability={
            "available": True,
            "mode": "payment",
            "amount": 5000,
            "pricing_source": "inline_price_data",
            "catalog_price_configured": False,
        },
    )

    failures = [check for check in checks if check.status == "FAIL"]
    warnings = [check for check in checks if check.status == "WARN"]
    assert failures == []
    assert any(check.category == "Stripe catalog" and check.name == "TinyZKP Pro" for check in warnings)
    assert any(check.category == "Stripe catalog" and check.name == "TinyZKP Team" for check in warnings)
    assert any(check.category == "Stripe meters" and check.name == "trace_step_usage" for check in warnings)
    assert any(check.category == "Cloudflare Pages" and check.name == "STRIPE_PRICE_ID_PILOT" for check in warnings)
    assert any(check.status == "PASS" and check.name == "inline price fallback" for check in checks)


def test_evaluate_fails_missing_required_pages_secret_and_wrong_price_spec():
    products = [_product(name) for name in audit.EXPECTED_PRODUCTS | audit.OPTIONAL_PRODUCTS]
    prices = [
        _price("Developer Monthly v2", 2900, "month", "licensed"),
        _price("Developer Annual v2", 18240, "year", "licensed"),
        _price("Pro Monthly v2", 7900, "month", "licensed"),
        _price("Pro Annual v2", 75840, "year", "licensed"),
        _price("Scale Monthly", 19900, "month", "licensed"),
        _price("Scale Annual", 191040, "year", "licensed"),
        _price("Per-proof usage (cents)", None, "month", "metered"),
        _price("Trace-step usage", None, "month", "metered"),
        _price("Production Pilot", 500000),
    ]

    checks = audit.evaluate(
        products_payload={"data": products},
        meters_payload={"data": [_meter("proof_usage"), _meter("trace_step_usage")]},
        prices_payload={"data": prices},
        secret_names={
            "INTERNAL_SECRET",
            "STRIPE_SECRET_KEY",
            "STRIPE_PRICE_ID_TRACE_STEP_METERED",
            "STRIPE_PRICE_ID_DEVELOPER",
            "STRIPE_PRICE_ID_PRO",
            "STRIPE_PRICE_ID_METERED",
            "TINYZKP_DEMO_API_KEY",
        },
        pilot_capability={
            "available": True,
            "mode": "payment",
            "amount": 5000,
            "pricing_source": "stripe_price",
            "catalog_price_configured": True,
        },
    )

    failed = "\n".join(f"{check.name}: {check.detail}" for check in checks if check.status == "FAIL")
    assert "Developer Monthly v2" in failed
    assert "unit_amount=2900 expected 1900" in failed
    assert "STRIPE_PRICE_ID_SCALE" in failed


def test_redact_removes_stripe_ids_and_emails():
    text = audit.redact("buyer@example.com acct_live_secret price_live_secret prod_live_secret req_live_secret rk_live_secretvalue")

    assert "buyer@example.com" not in text
    assert "acct_live_secret" not in text
    assert "price_live_secret" not in text
    assert "prod_live_secret" not in text
    assert "req_live_secret" not in text
    assert "rk_live_secretvalue" not in text
    assert "[redacted-email]" in text
    assert "[redacted-id]" in text


def test_run_audit_fails_before_stripe_queries_when_account_context_mismatches(monkeypatch):
    def fake_account_check(**_kwargs):
        return audit.stripe_account_context_check.AccountCheckResult(
            "FAIL",
            "account context",
            "configured Stripe CLI display_name 'Galen Health' does not match expected 'TinyZKP'",
        )

    def unexpected_stripe_list(*_args, **_kwargs):
        raise AssertionError("Stripe catalog reads should not run with the wrong account context")

    monkeypatch.setattr(audit.stripe_account_context_check, "run_check", fake_account_check)
    monkeypatch.setattr(audit, "stripe_list", unexpected_stripe_list)

    checks = audit.run_audit(
        argparse.Namespace(
            stripe_bin="/opt/homebrew/bin/stripe",
            expected_stripe_display_name="TinyZKP",
            skip_account_check=False,
            test=False,
            timeout=30,
            project_name="tinyzkp",
            pilot_capability_url="https://tinyzkp.com/api/create-pilot-checkout",
        )
    )

    assert len(checks) == 1
    assert checks[0].status == "FAIL"
    assert checks[0].category == "Stripe CLI"
    assert checks[0].name == "account context"
    assert "Galen Health" in checks[0].detail
