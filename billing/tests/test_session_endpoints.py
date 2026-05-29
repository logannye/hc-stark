"""Tests for session endpoints in billing/provision_tenant.py (Phase 0.2 Task 2)."""

import hashlib
import os
import sys
import tempfile

import pytest

# Add billing/ to sys.path so we can import provision_tenant and tenant_store.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# provision_tenant reads these at module level; set before import.
os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_fake")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test_fake")

import tenant_store
import provision_tenant


SECRET = "test-internal-secret-abc"
HEADERS = {"X-Internal-Secret": SECRET, "Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def _set_secret(monkeypatch, tmp_path):
    """Point the module at a fresh temp DB and set INTERNAL_SECRET."""
    db_path = str(tmp_path / "ts.sqlite")
    monkeypatch.setattr(provision_tenant, "INTERNAL_SECRET", SECRET)
    monkeypatch.setenv("HC_TENANT_STORE_PATH", db_path)
    # Patch open_db so it always uses the temp path for this test.
    real_open = tenant_store.open_db
    monkeypatch.setattr(tenant_store, "open_db", lambda path=None: real_open(db_path))
    yield db_path


@pytest.fixture
def client():
    provision_tenant.app.config["TESTING"] = True
    with provision_tenant.app.test_client() as c:
        yield c


def _mk_tenant(db_path, tenant_id="t_test", email="test@example.com",
               api_key="tzk_testkey12345678901234567890123456"):
    """Create a tenant in the temp db and return (conn, tenant_id)."""
    conn = tenant_store.open_db(db_path)
    tenant_store.create_tenant(conn, tenant_id, email, api_key, plan="free")
    conn.commit()
    return conn


def _mk_session(conn, tenant_id):
    """Mint a session and return the plaintext 64-hex token."""
    import secrets as _secrets
    tok = _secrets.token_hex(32)
    tenant_store.create_session(conn, hashlib.sha256(tok.encode()).hexdigest(), tenant_id)
    conn.commit()
    return tok


# ---------------------------------------------------------------------------
# /session/resolve
# ---------------------------------------------------------------------------

class TestSessionResolve:
    def test_bogus_token_returns_401(self, client):
        resp = client.post(
            "/session/resolve",
            json={"session_token": "a" * 64},
            headers=HEADERS,
        )
        assert resp.status_code == 401
        assert "error" in resp.get_json()

    def test_valid_session_returns_200_no_api_key(self, client, _set_secret):
        db_path = _set_secret
        conn = _mk_tenant(db_path)
        tok = _mk_session(conn, "t_test")
        conn.close()

        resp = client.post(
            "/session/resolve",
            json={"session_token": tok},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["tenant_id"] == "t_test"
        assert data["email"] == "test@example.com"
        assert data["plan"] == "free"
        assert data["status"] == "active"
        assert "stripe_customer_id" in data
        assert "api_key" not in data  # MUST NOT expose raw key

    def test_no_secret_returns_403(self, client):
        resp = client.post(
            "/session/resolve",
            json={"session_token": "a" * 64},
            headers={"Content-Type": "application/json"},  # no secret
        )
        assert resp.status_code == 403

    def test_short_token_returns_401(self, client):
        resp = client.post(
            "/session/resolve",
            json={"session_token": "tooshort"},
            headers=HEADERS,
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /verify-magic-link (must return session_token, NOT api_key)
# ---------------------------------------------------------------------------

class TestVerifyMagicLink:
    def test_valid_magic_link_returns_session_token_no_api_key(self, client, _set_secret):
        db_path = _set_secret
        conn = _mk_tenant(db_path)

        # Create a magic link token.
        import secrets as _secrets
        ml_token = _secrets.token_hex(32)
        ml_hash = hashlib.sha256(ml_token.encode()).hexdigest()
        tenant_store.create_magic_link(conn, ml_hash, "t_test")
        conn.commit(); conn.close()

        resp = client.post(
            "/verify-magic-link",
            json={"token": ml_token},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "session_token" in data
        assert len(data["session_token"]) == 64
        assert data["tenant_id"] == "t_test"
        assert "api_key" not in data  # MUST NOT expose raw key

    def test_expired_magic_link_returns_401(self, client, _set_secret):
        db_path = _set_secret
        conn = _mk_tenant(db_path)

        import secrets as _secrets
        ml_token = _secrets.token_hex(32)
        ml_hash = hashlib.sha256(ml_token.encode()).hexdigest()
        # TTL of -1 → immediately expired
        tenant_store.create_magic_link(conn, ml_hash, "t_test", ttl_ms=-1)
        conn.commit(); conn.close()

        resp = client.post(
            "/verify-magic-link",
            json={"token": ml_token},
            headers=HEADERS,
        )
        assert resp.status_code == 401

    def test_bogus_magic_link_returns_401(self, client):
        resp = client.post(
            "/verify-magic-link",
            json={"token": "b" * 64},
            headers=HEADERS,
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /logout
# ---------------------------------------------------------------------------

class TestLogout:
    def test_logout_invalidates_session(self, client, _set_secret):
        db_path = _set_secret
        conn = _mk_tenant(db_path)
        tok = _mk_session(conn, "t_test")
        conn.close()

        # Session is valid before logout.
        resp = client.post(
            "/session/resolve", json={"session_token": tok}, headers=HEADERS
        )
        assert resp.status_code == 200

        # Logout.
        resp = client.post(
            "/logout", json={"session_token": tok}, headers=HEADERS
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

        # Session should now be invalid.
        resp = client.post(
            "/session/resolve", json={"session_token": tok}, headers=HEADERS
        )
        assert resp.status_code == 401

    def test_logout_with_no_token_still_returns_200(self, client):
        resp = client.post("/logout", json={}, headers=HEADERS)
        assert resp.status_code == 200

    def test_logout_no_secret_returns_403(self, client):
        resp = client.post(
            "/logout",
            json={"session_token": "a" * 64},
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 403
