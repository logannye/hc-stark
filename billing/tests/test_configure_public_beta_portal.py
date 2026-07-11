from types import SimpleNamespace

import pytest

import configure_public_beta_portal as portal


def configuration(identifier="bpc_beta"):
    return {
        "id": identifier,
        "metadata": {
            "tinyzkp_catalog": portal.CATALOG_NAMESPACE,
            "tinyzkp_purpose": portal.PORTAL_PURPOSE,
        },
        "features": portal.PORTAL_FEATURES,
    }


def test_beta_portal_enables_period_end_cancel_but_not_plan_switching():
    features = portal.portal_plan()["features"]
    assert features["invoice_history"]["enabled"] is True
    assert features["payment_method_update"]["enabled"] is True
    assert features["subscription_cancel"]["mode"] == "at_period_end"
    assert features["subscription_update"]["enabled"] is False


def test_apply_reuses_one_matching_configuration(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_beta")
    monkeypatch.setenv(portal.WRITE_GATE, "1")
    monkeypatch.setattr(
        portal.stripe.Account,
        "retrieve",
        lambda: {
            "id": "acct_tinyzkp",
            "settings": {"dashboard": {"display_name": "LN Holdings"}},
        },
    )
    monkeypatch.setattr(
        portal.stripe.billing_portal.Configuration,
        "list",
        lambda **kwargs: {"data": [configuration()]},
    )
    monkeypatch.setattr(
        portal.stripe.billing_portal.Configuration,
        "create",
        lambda **kwargs: pytest.fail("matching portal must be reused"),
    )
    assert portal.apply_portal("acct_tinyzkp", "LN Holdings") == "bpc_beta"


def test_apply_creates_restricted_configuration(monkeypatch):
    calls = []
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_beta")
    monkeypatch.setenv(portal.WRITE_GATE, "1")
    monkeypatch.setattr(
        portal.stripe.Account,
        "retrieve",
        lambda: {
            "id": "acct_tinyzkp",
            "settings": {"dashboard": {"display_name": "LN Holdings"}},
        },
    )
    monkeypatch.setattr(
        portal.stripe.billing_portal.Configuration,
        "list",
        lambda **kwargs: {"data": []},
    )
    monkeypatch.setattr(
        portal.stripe.billing_portal.Configuration,
        "create",
        lambda **kwargs: calls.append(kwargs) or SimpleNamespace(id="bpc_created"),
    )
    assert portal.apply_portal("acct_tinyzkp", "LN Holdings") == "bpc_created"
    assert calls[0]["features"]["subscription_update"]["enabled"] is False
    assert calls[0]["features"]["subscription_cancel"]["mode"] == "at_period_end"
    assert len(calls[0]["business_profile"]["headline"]) <= 60


def test_existing_configuration_drift_fails_closed(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_beta")
    monkeypatch.setenv(portal.WRITE_GATE, "1")
    monkeypatch.setattr(
        portal.stripe.Account,
        "retrieve",
        lambda: {
            "id": "acct_tinyzkp",
            "settings": {"dashboard": {"display_name": "LN Holdings"}},
        },
    )
    drifted = configuration()
    drifted["features"] = dict(portal.PORTAL_FEATURES)
    drifted["features"]["subscription_update"] = {"enabled": True}
    monkeypatch.setattr(
        portal.stripe.billing_portal.Configuration,
        "list",
        lambda **kwargs: {"data": [drifted]},
    )
    with pytest.raises(RuntimeError, match="drifted"):
        portal.apply_portal("acct_tinyzkp", "LN Holdings")


def test_live_mode_requires_signed_release_authorization(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_beta")
    monkeypatch.setenv(portal.WRITE_GATE, "1")
    monkeypatch.setattr(portal, "_authorization_ready", lambda path: False)
    with pytest.raises(RuntimeError, match="signed exact-SHA"):
        portal.apply_portal("acct_tinyzkp", "LN Holdings")
