from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("relative", ["deploy/hetzner/deploy.sh", "deploy/hetzner/setup.sh"])
def test_billing_webhook_is_non_root_and_owner_only(relative):
    text = (ROOT / relative).read_text(encoding="utf-8")
    for marker in (
        "User=tinyzkp-billing",
        "Group=tinyzkp-billing",
        "UMask=0077",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ReadWritePaths=/opt/hc-stark/data",
        "install -d -o tinyzkp-billing -g tinyzkp-billing -m 0700 /opt/hc-stark/data",
    ):
        assert marker in text


@pytest.mark.parametrize("relative", ["deploy/hetzner/deploy.sh", "deploy/hetzner/setup.sh"])
def test_recovery_cron_enforces_application_retention(relative):
    text = (ROOT / relative).read_text(encoding="utf-8")
    assert "evaluation_intake.py" in text
    assert "purge-expired --apply" in text
    assert "lifecycle_nudges.py" not in text
    assert "checkout_recovery.py" not in text
