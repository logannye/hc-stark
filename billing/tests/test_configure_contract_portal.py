from types import SimpleNamespace

import configure_contract_portal as portal


def test_portal_plan_allows_invoices_and_payment_methods_not_plan_changes():
    plan = portal.portal_plan()
    assert plan["mode"] == "read_only"
    assert plan["api_version"] == "2026-02-25.clover"
    assert plan["public_checkout"] is False
    assert plan["features"]["invoice_history"]["enabled"] is True
    assert plan["features"]["payment_method_update"]["enabled"] is True
    assert plan["features"]["subscription_update"]["enabled"] is False
    assert plan["features"]["subscription_cancel"]["enabled"] is False


def test_portal_apply_verifies_account_before_write(monkeypatch, capsys):
    calls = []
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_contract")
    monkeypatch.setenv("TINYZKP_ALLOW_PORTAL_CONFIGURATION_WRITE", "1")
    monkeypatch.setattr(
        portal,
        "parse_args",
        lambda: SimpleNamespace(
            apply=True,
            expected_account_id="acct_tinyzkp",
            expected_display_name="LN Holdings",
        ),
    )
    monkeypatch.setattr(
        portal.stripe.Account,
        "retrieve",
        lambda: calls.append("account")
        or {
            "id": "acct_tinyzkp",
            "settings": {"dashboard": {"display_name": "LN Holdings"}},
        },
    )
    monkeypatch.setattr(
        portal.stripe.billing_portal.Configuration,
        "create",
        lambda **kwargs: calls.append(("configuration", kwargs))
        or SimpleNamespace(id="bpc_contract"),
    )

    portal.main()

    assert calls[0] == "account"
    assert calls[1][0] == "configuration"
    assert calls[1][1]["features"]["subscription_update"]["enabled"] is False
    assert '"portal_configuration_id": "bpc_contract"' in capsys.readouterr().out
