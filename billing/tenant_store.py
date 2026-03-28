"""SQLite tenant store — replaces tenant_map.json with a proper database.

Provides idempotent tenant creation, suspension, activation, and key rotation.
All writes use implicit transactions via `with conn:`.
"""

import json
import os
import sqlite3
import time
from typing import Optional


DB_PATH = os.environ.get("HC_TENANT_STORE_PATH", "/opt/hc-stark/data/tenant_store.sqlite")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
  tenant_id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  api_key_hash TEXT NOT NULL,
  api_key_prefix TEXT NOT NULL,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT UNIQUE,
  stripe_subscription_item_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  plan TEXT NOT NULL DEFAULT 'standard',
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS processed_events (
  event_id TEXT PRIMARY KEY,
  processed_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS magic_links (
  token_hash TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_magic_links_tenant ON magic_links(tenant_id);
"""


def _now_ms() -> int:
    return int(time.time() * 1000)


def _hash_key(api_key: str) -> str:
    """Hash an API key with SHA-256. Sufficient for API key storage."""
    import hashlib
    return hashlib.sha256(api_key.encode()).hexdigest()


def open_db(path: Optional[str] = None) -> sqlite3.Connection:
    """Open (and initialize) the tenant store database."""
    path = path or DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def create_tenant(
    conn: sqlite3.Connection,
    tenant_id: str,
    email: str,
    api_key: str,
    stripe_customer_id: Optional[str] = None,
    stripe_subscription_id: Optional[str] = None,
    stripe_subscription_item_id: Optional[str] = None,
    plan: str = "standard",
) -> None:
    """Insert a new tenant. Raises IntegrityError on duplicate tenant_id."""
    now = _now_ms()
    with conn:
        conn.execute(
            """INSERT INTO tenants
               (tenant_id, email, api_key_hash, api_key_prefix,
                stripe_customer_id, stripe_subscription_id, stripe_subscription_item_id,
                status, plan, created_at_ms, updated_at_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
            (
                tenant_id, email, _hash_key(api_key), api_key[:8],
                stripe_customer_id, stripe_subscription_id, stripe_subscription_item_id,
                plan, now, now,
            ),
        )


def get_tenant(conn: sqlite3.Connection, tenant_id: str) -> Optional[sqlite3.Row]:
    """Fetch a tenant by ID."""
    return conn.execute(
        "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
    ).fetchone()


def get_by_subscription_id(conn: sqlite3.Connection, subscription_id: str) -> Optional[sqlite3.Row]:
    """Fetch a tenant by Stripe subscription ID."""
    return conn.execute(
        "SELECT * FROM tenants WHERE stripe_subscription_id = ?", (subscription_id,)
    ).fetchone()


def set_status(conn: sqlite3.Connection, tenant_id: str, status: str) -> None:
    """Update tenant status (active | suspended | cancelled)."""
    with conn:
        conn.execute(
            "UPDATE tenants SET status = ?, updated_at_ms = ? WHERE tenant_id = ?",
            (status, _now_ms(), tenant_id),
        )


def suspend_tenant(conn: sqlite3.Connection, tenant_id: str) -> None:
    set_status(conn, tenant_id, "suspended")


def activate_tenant(conn: sqlite3.Connection, tenant_id: str) -> None:
    set_status(conn, tenant_id, "active")


def set_plan(conn: sqlite3.Connection, tenant_id: str, plan: str) -> None:
    """Update tenant plan (free | standard | pro)."""
    with conn:
        conn.execute(
            "UPDATE tenants SET plan = ?, updated_at_ms = ? WHERE tenant_id = ?",
            (plan, _now_ms(), tenant_id),
        )


def update_api_key(conn: sqlite3.Connection, tenant_id: str, new_api_key: str) -> None:
    """Rotate a tenant's API key."""
    with conn:
        conn.execute(
            "UPDATE tenants SET api_key_hash = ?, api_key_prefix = ?, updated_at_ms = ? WHERE tenant_id = ?",
            (_hash_key(new_api_key), new_api_key[:8], _now_ms(), tenant_id),
        )


def list_tenants(conn: sqlite3.Connection, status: Optional[str] = None) -> list:
    """List all tenants, optionally filtered by status."""
    if status:
        return conn.execute(
            "SELECT * FROM tenants WHERE status = ? ORDER BY created_at_ms DESC", (status,)
        ).fetchall()
    return conn.execute("SELECT * FROM tenants ORDER BY created_at_ms DESC").fetchall()


def is_event_processed(conn: sqlite3.Connection, event_id: str) -> bool:
    """Check if a Stripe event has already been processed."""
    row = conn.execute(
        "SELECT 1 FROM processed_events WHERE event_id = ?", (event_id,)
    ).fetchone()
    return row is not None


def mark_event_processed(conn: sqlite3.Connection, event_id: str) -> None:
    """Record that a Stripe event has been processed."""
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO processed_events (event_id, processed_at_ms) VALUES (?, ?)",
            (event_id, _now_ms()),
        )


def get_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    """Fetch a tenant by email address."""
    return conn.execute(
        "SELECT * FROM tenants WHERE email = ?", (email,)
    ).fetchone()


def create_magic_link(conn: sqlite3.Connection, token_hash: str, tenant_id: str, ttl_ms: int = 900_000) -> None:
    """Store a magic link token hash with a 15-minute TTL."""
    now = _now_ms()
    with conn:
        # GC expired tokens on every insert.
        conn.execute("DELETE FROM magic_links WHERE expires_at_ms < ?", (now,))
        conn.execute(
            "INSERT INTO magic_links (token_hash, tenant_id, created_at_ms, expires_at_ms, used) VALUES (?, ?, ?, ?, 0)",
            (token_hash, tenant_id, now, now + ttl_ms),
        )


def verify_magic_link(conn: sqlite3.Connection, token_hash: str) -> Optional[str]:
    """Verify and consume a magic link. Returns tenant_id or None."""
    now = _now_ms()
    row = conn.execute(
        "SELECT tenant_id FROM magic_links WHERE token_hash = ? AND used = 0 AND expires_at_ms > ?",
        (token_hash, now),
    ).fetchone()
    if not row:
        return None
    with conn:
        conn.execute("UPDATE magic_links SET used = 1 WHERE token_hash = ?", (token_hash,))
    return row["tenant_id"]


def migrate_from_tenant_map(conn: sqlite3.Connection, tenant_map_path: str, api_keys_path: str) -> int:
    """One-time migration from tenant_map.json + api_keys.txt into the SQLite store.

    Returns the number of tenants migrated.
    """
    if not os.path.exists(tenant_map_path):
        return 0

    with open(tenant_map_path) as f:
        tenant_map = json.load(f)

    # Build api_key lookup from api_keys.txt.
    api_keys: dict[str, str] = {}
    if os.path.exists(api_keys_path):
        with open(api_keys_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":", 1)
                if len(parts) == 2:
                    api_keys[parts[0]] = parts[1]

    migrated = 0
    for tenant_id, info in tenant_map.items():
        existing = get_tenant(conn, tenant_id)
        if existing:
            continue

        api_key = api_keys.get(tenant_id, "")
        if not api_key:
            continue

        try:
            create_tenant(
                conn,
                tenant_id=tenant_id,
                email=info.get("email", "unknown"),
                api_key=api_key,
                stripe_subscription_item_id=info.get("subscription_item_id"),
            )
            migrated += 1
        except sqlite3.IntegrityError:
            pass

    return migrated
