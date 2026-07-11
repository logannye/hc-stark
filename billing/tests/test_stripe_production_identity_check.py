import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


BILLING_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = BILLING_DIR / "stripe_production_identity_check.py"
spec = importlib.util.spec_from_file_location(
    "stripe_production_identity_check", MODULE_PATH
)
identity = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(identity)


LIVE_KEY = "sk_live_" + "a" * 32
ACCOUNT_ID = "acct_" + "b" * 16


def private_env(tmp_path: Path) -> Path:
    path = tmp_path / "production.env"
    path.write_text(
        f"STRIPE_SECRET_KEY={LIVE_KEY}\n"
        f"STRIPE_EXPECTED_ACCOUNT_ID={ACCOUNT_ID}\n"
        "STRIPE_EXPECTED_DISPLAY_NAME='LN Holdings'\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def tinyzkp_account():
    return {
        "id": ACCOUNT_ID,
        "settings": {"dashboard": {"display_name": "LN Holdings"}},
        "business_profile": {
            "name": "TinyZKP",
            "support_email": "security@tinyzkp.com",
            "support_url": "https://tinyzkp.com/security",
        },
    }


def test_read_only_identity_check_verifies_exact_account_and_public_profile(tmp_path):
    seen = {}

    def client_factory(api_key):
        seen["api_key"] = api_key
        return SimpleNamespace(
            v1=SimpleNamespace(
                accounts=SimpleNamespace(retrieve_current=tinyzkp_account)
            )
        )

    report = identity.run_check(
        private_env(tmp_path), inherited={}, client_factory=client_factory
    )

    assert report == {
        "status": "pass",
        "stripe_account_id_verified": True,
        "stripe_dashboard_identity_verified": True,
        "tinyzkp_customer_facing_identity_verified": True,
        "write_performed": False,
    }
    assert seen["api_key"] == LIVE_KEY


def test_identity_check_rejects_wrong_account_or_customer_facing_brand(tmp_path):
    account = tinyzkp_account()
    account["id"] = "acct_" + "c" * 16
    client = SimpleNamespace(
        v1=SimpleNamespace(accounts=SimpleNamespace(retrieve_current=lambda: account))
    )
    with pytest.raises(RuntimeError, match="Stripe account mismatch"):
        identity.run_check(
            private_env(tmp_path),
            inherited={},
            client_factory=lambda _key: client,
        )

    account = tinyzkp_account()
    account["business_profile"]["name"] = "Unrelated Business"
    client.v1.accounts.retrieve_current = lambda: account
    with pytest.raises(ValueError, match="must identify TinyZKP"):
        identity.run_check(
            private_env(tmp_path),
            inherited={},
            client_factory=lambda _key: client,
        )


def test_identity_check_requires_owner_only_env_and_live_key(tmp_path):
    env_file = private_env(tmp_path)
    env_file.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        identity.run_check(env_file, inherited={}, client_factory=lambda _key: None)

    env_file.chmod(0o600)
    env_file.write_text(
        f"STRIPE_SECRET_KEY=sk_test_{'a' * 32}\n"
        f"STRIPE_EXPECTED_ACCOUNT_ID={ACCOUNT_ID}\n"
        "STRIPE_EXPECTED_DISPLAY_NAME=LN Holdings\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="canonical sk_live_"):
        identity.run_check(env_file, inherited={}, client_factory=lambda _key: None)


def test_identity_check_rejects_conflicting_inherited_account_config(tmp_path):
    with pytest.raises(ValueError, match="STRIPE_EXPECTED_ACCOUNT_ID"):
        identity.run_check(
            private_env(tmp_path),
            inherited={"STRIPE_EXPECTED_ACCOUNT_ID": "acct_" + "c" * 16},
            client_factory=lambda _key: None,
        )


def test_identity_check_does_not_fill_missing_file_values_from_shell(tmp_path):
    env_file = private_env(tmp_path)
    env_file.write_text(
        f"STRIPE_SECRET_KEY={LIVE_KEY}\n"
        f"STRIPE_EXPECTED_ACCOUNT_ID={ACCOUNT_ID}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="STRIPE_EXPECTED_DISPLAY_NAME"):
        identity.run_check(
            env_file,
            inherited={"STRIPE_EXPECTED_DISPLAY_NAME": "LN Holdings"},
            client_factory=lambda _key: None,
        )


def test_cli_failure_redacts_keys_ids_and_email(monkeypatch, capsys, tmp_path):
    def fail(_env_file):
        raise RuntimeError(
            f"{LIVE_KEY} {ACCOUNT_ID} operator@tinyzkp.com must not escape"
        )

    monkeypatch.setattr(identity, "run_check", fail)

    assert identity.main(["--env-file", str(tmp_path / "production.env")]) == 1
    error = capsys.readouterr().err
    assert LIVE_KEY not in error
    assert ACCOUNT_ID not in error
    assert "operator@tinyzkp.com" not in error
    assert "[redacted-key]" in error
    assert "[redacted-id]" in error
    assert "[redacted-email]" in error
