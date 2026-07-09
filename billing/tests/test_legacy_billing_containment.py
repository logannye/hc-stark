import json
from pathlib import Path

import pytest

import legacy_billing_containment as containment


def test_account_identity_requires_exact_id_and_name():
    account = {
        "id": "acct_tinyzkp",
        "settings": {"dashboard": {"display_name": "LN Holdings"}},
    }
    containment.verify_account(account, "acct_tinyzkp", "LN Holdings")
    with pytest.raises(RuntimeError, match="account mismatch"):
        containment.verify_account(account, "acct_other", "LN Holdings")


def test_legacy_product_scope_does_not_include_unrelated_business():
    assert containment.is_legacy_product({"name": "TinyZKP Developer"})
    assert containment.is_legacy_product({"name": "Compute"})
    assert not containment.is_legacy_product({"name": "Casino Coach Pro"})


def test_notification_ledger_is_required_before_subscription_pause(tmp_path: Path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        containment.stripe.Subscription,
        "modify",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    subscription = {"id": "sub_legacy"}
    with pytest.raises(RuntimeError, match="refusing to pause"):
        containment.pause_notified_subscriptions([subscription], {})
    assert calls == []

    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "subscriptions": [
                    {
                        "subscription_id": "sub_legacy",
                        "notified_at": "2026-07-09T00:00:00Z",
                        "resolution": "credit",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    ledger = containment.load_notification_ledger(ledger_path)
    containment.pause_notified_subscriptions([subscription], ledger)
    assert calls[0][0] == ("sub_legacy",)
    assert calls[0][1]["pause_collection"] == {"behavior": "void"}
