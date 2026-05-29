"""Tests for /provision-free duplicate-email guard (Phase 0.3 Task 1, audit G8)."""

import os
import sys

import pytest

# Add billing/ to sys.path so we can import provision_tenant and tenant_store.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# provision_tenant reads these at module level; set before import.
os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_fake")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test_fake")

import sync_keys
import tenant_store
import provision_tenant


SECRET = "test-internal-secret-abc"
HEADERS = {"X-Internal-Secret": SECRET, "Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def _set_secret(monkeypatch, tmp_path):
    """Point the module at a fresh temp DB and set INTERNAL_SECRET.

    Also stubs out sync_keys.regenerate so tests don't need the production
    api_keys.txt path on disk.
    """
    db_path = str(tmp_path / "ts.sqlite")
    monkeypatch.setattr(provision_tenant, "INTERNAL_SECRET", SECRET)
    monkeypatch.setenv("HC_TENANT_STORE_PATH", db_path)
    real_open = tenant_store.open_db
    monkeypatch.setattr(tenant_store, "open_db", lambda path=None: real_open(db_path))
    monkeypatch.setattr(sync_keys, "regenerate", lambda *a, **kw: 0)
    yield db_path


@pytest.fixture
def client():
    provision_tenant.app.config["TESTING"] = True
    with provision_tenant.app.test_client() as c:
        yield c


class TestProvisionFreeDeduplication:
    def test_first_signup_succeeds(self, client):
        resp = client.post(
            "/provision-free",
            json={"email": "unique-test@example.com"},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "dashboard_token" in data

    def test_second_signup_same_email_returns_409(self, client, _set_secret):
        db_path = _set_secret
        email = "duplicate@example.com"

        # First signup — must succeed.
        resp1 = client.post(
            "/provision-free",
            json={"email": email},
            headers=HEADERS,
        )
        assert resp1.status_code == 200

        # Second signup with same email — must be blocked.
        resp2 = client.post(
            "/provision-free",
            json={"email": email},
            headers=HEADERS,
        )
        assert resp2.status_code == 409
        assert "error" in resp2.get_json()

        # Exactly one tenant must exist for this email — no second tenant minted.
        conn = tenant_store.open_db(db_path)
        rows = conn.execute(
            "SELECT COUNT(*) FROM tenants WHERE email = ?", (email,)
        ).fetchone()
        conn.close()
        assert rows[0] == 1, f"Expected 1 tenant for {email}, got {rows[0]}"
