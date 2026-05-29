"""Tests for session management in billing/tenant_store.py."""

import hashlib
import os
import sys
import tempfile

# Add billing/ to sys.path so we can import tenant_store directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tenant_store as ts


def _mk():
    fd, path = tempfile.mkstemp(suffix=".sqlite"); os.close(fd)
    conn = ts.open_db(path)
    ts.create_tenant(conn, "t_x", "a@b.co", "tzk_secret123", plan="free")
    return conn

def _h(tok): return hashlib.sha256(tok.encode()).hexdigest()

def test_create_and_validate_session():
    conn = _mk()
    ts.create_session(conn, _h("tok1"), "t_x", ttl_ms=60_000)
    assert ts.validate_session(conn, _h("tok1")) == "t_x"
    assert ts.validate_session(conn, _h("nope")) is None

def test_expired_session_invalid():
    conn = _mk()
    ts.create_session(conn, _h("tok2"), "t_x", ttl_ms=-1)
    assert ts.validate_session(conn, _h("tok2")) is None

def test_suspended_tenant_session_invalid_and_revoked():
    conn = _mk()
    ts.create_session(conn, _h("tok3"), "t_x", ttl_ms=60_000)
    ts.suspend_tenant(conn, "t_x")
    assert ts.validate_session(conn, _h("tok3")) is None

def test_logout_and_delete_for_tenant():
    conn = _mk()
    ts.create_session(conn, _h("a"), "t_x", 60_000)
    ts.create_session(conn, _h("b"), "t_x", 60_000)
    ts.delete_session(conn, _h("a"))
    assert ts.validate_session(conn, _h("a")) is None
    assert ts.validate_session(conn, _h("b")) == "t_x"
    ts.delete_sessions_for_tenant(conn, "t_x")
    assert ts.validate_session(conn, _h("b")) is None
