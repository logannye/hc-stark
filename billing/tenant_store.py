"""SQLite tenant store — replaces tenant_map.json with a proper database.

Provides idempotent tenant creation, suspension, activation, and key rotation.
All writes use implicit transactions via `with conn:`.

When HC_TENANT_PG_URL (or HC_SERVER_AUTH_PG_URL) is set, writes are also
mirrored into the shared Postgres tenant/auth schema used by API and MCP auth.
The SQLite store remains primary unless the operator explicitly changes the
read paths; HC_TENANT_PG_REQUIRED=1 makes mirror failures fail the caller.
"""

import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Optional


DB_PATH = os.environ.get("HC_TENANT_STORE_PATH", "/opt/hc-stark/data/tenant_store.sqlite")
PG_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "crates" / "hc-server" / "sql" / "tenant_auth_pg.sql"
_PG_SCHEMA_READY = False

TENANT_ATTRIBUTION_FIELDS = (
    "source",
    "medium",
    "campaign",
    "platform",
    "use_case",
    "workflow",
    "intent",
    "landing_path",
    "referrer_host",
    "first_seen_at",
)

TENANT_ATTRIBUTION_COLUMNS = tuple(f"attribution_{field}" for field in TENANT_ATTRIBUTION_FIELDS)
_ATTRIBUTION_ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .:/_-")
_ATTRIBUTION_MAX_LEN = 160

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
  attribution_source TEXT,
  attribution_medium TEXT,
  attribution_campaign TEXT,
  attribution_platform TEXT,
  attribution_use_case TEXT,
  attribution_workflow TEXT,
  attribution_intent TEXT,
  attribution_landing_path TEXT,
  attribution_referrer_host TEXT,
  attribution_first_seen_at TEXT,
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

CREATE TABLE IF NOT EXISTS sessions (
  token_hash    TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);

CREATE TABLE IF NOT EXISTS lifecycle_emails (
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  sent_at_ms INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_emails_tenant ON lifecycle_emails(tenant_id);

CREATE TABLE IF NOT EXISTS checkout_recovery_emails (
  stripe_session_id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  plan TEXT,
  sent_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checkout_recovery_emails_email ON checkout_recovery_emails(email);
"""


def _now_ms() -> int:
    return int(time.time() * 1000)


def _hash_key(api_key: str) -> str:
    """Hash an API key with SHA-256. Sufficient for API key storage."""
    import hashlib
    return hashlib.sha256(api_key.encode()).hexdigest()


def _clean_attribution(attribution: Optional[dict[str, str]]) -> dict[str, str]:
    if not isinstance(attribution, dict):
        return {}
    clean: dict[str, str] = {}
    for field, column in zip(TENANT_ATTRIBUTION_FIELDS, TENANT_ATTRIBUTION_COLUMNS):
        value = attribution.get(field)
        if not isinstance(value, str):
            continue
        scrubbed = "".join(ch for ch in value.strip() if ch in _ATTRIBUTION_ALLOWED_CHARS)
        if scrubbed:
            clean[column] = scrubbed[:_ATTRIBUTION_MAX_LEN]
    return clean


_PARTIAL_INDEX_SQL = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_free_tenant_per_email
  ON tenants(email) WHERE plan = 'free';
"""


def _pg_url() -> str:
    return os.environ.get("HC_TENANT_PG_URL") or os.environ.get("HC_SERVER_AUTH_PG_URL") or ""


def _pg_required() -> bool:
    return os.environ.get("HC_TENANT_PG_REQUIRED", "").lower() in {"1", "true", "yes"}


def _open_pg(url: str):
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("psycopg is required for HC_TENANT_PG_URL mirroring") from exc
    return psycopg.connect(url)


def _ensure_pg_schema(pg) -> None:
    global _PG_SCHEMA_READY
    if _PG_SCHEMA_READY:
        return
    pg.execute(PG_SCHEMA_PATH.read_text())
    _PG_SCHEMA_READY = True


def _ensure_sqlite_tenant_columns(conn: sqlite3.Connection) -> None:
    existing = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(tenants)").fetchall()
    }
    for column in TENANT_ATTRIBUTION_COLUMNS:
        if column not in existing:
            conn.execute(f"ALTER TABLE tenants ADD COLUMN {column} TEXT")


def _with_pg_mirror(description: str, callback) -> None:
    url = _pg_url()
    if not url:
        return
    try:
        with _open_pg(url) as pg:
            _ensure_pg_schema(pg)
            callback(pg)
    except Exception as exc:
        if _pg_required():
            raise
        logging.warning("tenant_store: Postgres mirror failed during %s: %s", description, exc)


def open_db(path: Optional[str] = None) -> sqlite3.Connection:
    """Open (and initialize) the tenant store database.

    The partial unique index on tenants(email) WHERE plan='free' is created
    separately from the main schema so that a pre-existing database that
    already has duplicate free rows for an email (from the pre-fix bug) does
    not prevent open_db from succeeding. If the index cannot be created, a
    warning is logged and the database continues to operate without it.
    """
    import logging
    path = path or DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    _ensure_sqlite_tenant_columns(conn)
    try:
        conn.executescript(_PARTIAL_INDEX_SQL)
    except (sqlite3.OperationalError, sqlite3.IntegrityError) as exc:
        # A UNIQUE-constraint violation while building the index (pre-existing
        # duplicate free rows for an email) raises sqlite3.IntegrityError, which
        # is a SIBLING of OperationalError — NOT a subclass — so it must be named
        # explicitly. Missing it here made EVERY open_db() call throw, which 500'd
        # provision_free and the Stripe subscription-updated webhook. The DB stays
        # fully usable without the index; one-free-per-email is still enforced by
        # the application-level get_by_email check in provision_free.
        logging.warning(
            "tenant_store: could not create idx_one_free_tenant_per_email "
            "(pre-existing duplicate free rows?). "
            "De-duplicate manually then reopen. error=%s",
            exc,
        )
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
    attribution: Optional[dict[str, str]] = None,
) -> None:
    """Insert a new tenant. Raises IntegrityError on duplicate tenant_id."""
    now = _now_ms()
    api_key_hash = _hash_key(api_key)
    api_key_prefix = api_key[:8]
    clean_attribution = _clean_attribution(attribution)
    attribution_values = [clean_attribution.get(column) for column in TENANT_ATTRIBUTION_COLUMNS]
    with conn:
        conn.execute(
            """INSERT INTO tenants
               (tenant_id, email, api_key_hash, api_key_prefix,
                stripe_customer_id, stripe_subscription_id, stripe_subscription_item_id,
                status, plan,
                attribution_source, attribution_medium, attribution_campaign,
                attribution_platform, attribution_use_case, attribution_workflow,
                attribution_intent, attribution_landing_path, attribution_referrer_host,
                attribution_first_seen_at,
                created_at_ms, updated_at_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                tenant_id, email, api_key_hash, api_key_prefix,
                stripe_customer_id, stripe_subscription_id, stripe_subscription_item_id,
                plan, *attribution_values, now, now,
            ),
        )
    _with_pg_mirror(
        "create_tenant",
        lambda pg: pg.execute(
            """INSERT INTO tenants
               (tenant_id, email, api_key_hash, api_key_prefix,
                stripe_customer_id, stripe_subscription_id, stripe_subscription_item_id,
                status, plan,
                attribution_source, attribution_medium, attribution_campaign,
                attribution_platform, attribution_use_case, attribution_workflow,
                attribution_intent, attribution_landing_path, attribution_referrer_host,
                attribution_first_seen_at,
                created_at_ms, updated_at_ms)
               VALUES (%s, %s, %s, %s, %s, %s, %s, 'active', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (tenant_id) DO UPDATE SET
                 email = EXCLUDED.email,
                 api_key_hash = EXCLUDED.api_key_hash,
                 api_key_prefix = EXCLUDED.api_key_prefix,
                 stripe_customer_id = EXCLUDED.stripe_customer_id,
                 stripe_subscription_id = EXCLUDED.stripe_subscription_id,
                 stripe_subscription_item_id = EXCLUDED.stripe_subscription_item_id,
                 status = EXCLUDED.status,
                 plan = EXCLUDED.plan,
                 attribution_source = EXCLUDED.attribution_source,
                 attribution_medium = EXCLUDED.attribution_medium,
                 attribution_campaign = EXCLUDED.attribution_campaign,
                 attribution_platform = EXCLUDED.attribution_platform,
                 attribution_use_case = EXCLUDED.attribution_use_case,
                 attribution_workflow = EXCLUDED.attribution_workflow,
                 attribution_intent = EXCLUDED.attribution_intent,
                 attribution_landing_path = EXCLUDED.attribution_landing_path,
                 attribution_referrer_host = EXCLUDED.attribution_referrer_host,
                 attribution_first_seen_at = EXCLUDED.attribution_first_seen_at,
                 updated_at_ms = EXCLUDED.updated_at_ms""",
            (
                tenant_id, email, api_key_hash, api_key_prefix,
                stripe_customer_id, stripe_subscription_id, stripe_subscription_item_id,
                plan, *attribution_values, now, now,
            ),
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
    now = _now_ms()
    with conn:
        conn.execute(
            "UPDATE tenants SET status = ?, updated_at_ms = ? WHERE tenant_id = ?",
            (status, now, tenant_id),
        )
    _with_pg_mirror(
        "set_status",
        lambda pg: pg.execute(
            "UPDATE tenants SET status = %s, updated_at_ms = %s WHERE tenant_id = %s",
            (status, now, tenant_id),
        ),
    )


def suspend_tenant(conn: sqlite3.Connection, tenant_id: str) -> None:
    set_status(conn, tenant_id, "suspended")
    delete_sessions_for_tenant(conn, tenant_id)


def activate_tenant(conn: sqlite3.Connection, tenant_id: str) -> None:
    set_status(conn, tenant_id, "active")


def set_plan(conn: sqlite3.Connection, tenant_id: str, plan: str) -> None:
    """Update tenant plan (free | standard | pro)."""
    now = _now_ms()
    with conn:
        conn.execute(
            "UPDATE tenants SET plan = ?, updated_at_ms = ? WHERE tenant_id = ?",
            (plan, now, tenant_id),
        )
    _with_pg_mirror(
        "set_plan",
        lambda pg: pg.execute(
            "UPDATE tenants SET plan = %s, updated_at_ms = %s WHERE tenant_id = %s",
            (plan, now, tenant_id),
        ),
    )


def update_api_key(conn: sqlite3.Connection, tenant_id: str, new_api_key: str) -> None:
    """Rotate a tenant's API key."""
    now = _now_ms()
    api_key_hash = _hash_key(new_api_key)
    api_key_prefix = new_api_key[:8]
    with conn:
        conn.execute(
            "UPDATE tenants SET api_key_hash = ?, api_key_prefix = ?, updated_at_ms = ? WHERE tenant_id = ?",
            (api_key_hash, api_key_prefix, now, tenant_id),
        )
    _with_pg_mirror(
        "update_api_key",
        lambda pg: pg.execute(
            "UPDATE tenants SET api_key_hash = %s, api_key_prefix = %s, updated_at_ms = %s WHERE tenant_id = %s",
            (api_key_hash, api_key_prefix, now, tenant_id),
        ),
    )


def delete_tenant(conn: sqlite3.Connection, tenant_id: str) -> int:
    """Permanently remove a tenant and any associated magic-link rows.

    Returns the number of tenant rows deleted (0 if tenant_id was not found).
    Used by the /tenant-purge admin endpoint to clean up audit-test tenants.
    """
    with conn:
        conn.execute("DELETE FROM magic_links WHERE tenant_id = ?", (tenant_id,))
        conn.execute("DELETE FROM sessions WHERE tenant_id = ?", (tenant_id,))
        conn.execute("DELETE FROM lifecycle_emails WHERE tenant_id = ?", (tenant_id,))
        cur = conn.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))
        deleted = cur.rowcount
    if deleted:
        _with_pg_mirror(
            "delete_tenant",
            lambda pg: (
                pg.execute("DELETE FROM magic_links WHERE tenant_id = %s", (tenant_id,)),
                pg.execute("DELETE FROM sessions WHERE tenant_id = %s", (tenant_id,)),
                pg.execute("DELETE FROM tenants WHERE tenant_id = %s", (tenant_id,)),
            ),
        )
    return deleted


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
    now = _now_ms()
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO processed_events (event_id, processed_at_ms) VALUES (?, ?)",
            (event_id, now),
        )
    _with_pg_mirror(
        "mark_event_processed",
        lambda pg: pg.execute(
            "INSERT INTO processed_events (event_id, processed_at_ms) VALUES (%s, %s) ON CONFLICT (event_id) DO NOTHING",
            (event_id, now),
        ),
    )


def get_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    """Fetch a tenant by email address."""
    return conn.execute(
        "SELECT * FROM tenants WHERE email = ?", (email,)
    ).fetchone()


def create_magic_link(conn: sqlite3.Connection, token_hash: str, tenant_id: str, ttl_ms: int = 900_000) -> None:
    """Store a magic link token hash with a 15-minute TTL."""
    now = _now_ms()
    expires_at_ms = now + ttl_ms
    with conn:
        # GC expired tokens on every insert.
        conn.execute("DELETE FROM magic_links WHERE expires_at_ms < ?", (now,))
        conn.execute(
            "INSERT INTO magic_links (token_hash, tenant_id, created_at_ms, expires_at_ms, used) VALUES (?, ?, ?, ?, 0)",
            (token_hash, tenant_id, now, expires_at_ms),
        )
    _with_pg_mirror(
        "create_magic_link",
        lambda pg: (
            pg.execute("DELETE FROM magic_links WHERE expires_at_ms < %s", (now,)),
            pg.execute(
                """INSERT INTO magic_links
                   (token_hash, tenant_id, created_at_ms, expires_at_ms, used)
                   VALUES (%s, %s, %s, %s, false)
                   ON CONFLICT (token_hash) DO UPDATE SET
                     tenant_id = EXCLUDED.tenant_id,
                     created_at_ms = EXCLUDED.created_at_ms,
                     expires_at_ms = EXCLUDED.expires_at_ms,
                     used = EXCLUDED.used""",
                (token_hash, tenant_id, now, expires_at_ms),
            ),
        ),
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
    _with_pg_mirror(
        "verify_magic_link",
        lambda pg: pg.execute("UPDATE magic_links SET used = true WHERE token_hash = %s", (token_hash,)),
    )
    return row["tenant_id"]


def create_session(conn: sqlite3.Connection, token_hash: str, tenant_id: str, ttl_ms: int = 86_400_000) -> None:
    """Store a session token hash (default 24h TTL). GCs expired rows."""
    now = _now_ms()
    expires_at_ms = now + ttl_ms
    with conn:
        conn.execute("DELETE FROM sessions WHERE expires_at_ms < ?", (now,))
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token_hash, tenant_id, created_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)",
            (token_hash, tenant_id, now, expires_at_ms),
        )
    _with_pg_mirror(
        "create_session",
        lambda pg: (
            pg.execute("DELETE FROM sessions WHERE expires_at_ms < %s", (now,)),
            pg.execute(
                """INSERT INTO sessions (token_hash, tenant_id, created_at_ms, expires_at_ms)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (token_hash) DO UPDATE SET
                     tenant_id = EXCLUDED.tenant_id,
                     created_at_ms = EXCLUDED.created_at_ms,
                     expires_at_ms = EXCLUDED.expires_at_ms""",
                (token_hash, tenant_id, now, expires_at_ms),
            ),
        ),
    )


def validate_session(conn: sqlite3.Connection, token_hash: str) -> Optional[str]:
    """Return tenant_id for a live session whose tenant is active, else None."""
    now = _now_ms()
    row = conn.execute(
        """SELECT s.tenant_id FROM sessions s
           JOIN tenants t ON t.tenant_id = s.tenant_id
           WHERE s.token_hash = ? AND s.expires_at_ms > ? AND t.status = 'active'""",
        (token_hash, now),
    ).fetchone()
    return row["tenant_id"] if row else None


def delete_session(conn: sqlite3.Connection, token_hash: str) -> None:
    with conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    _with_pg_mirror(
        "delete_session",
        lambda pg: pg.execute("DELETE FROM sessions WHERE token_hash = %s", (token_hash,)),
    )


def delete_sessions_for_tenant(conn: sqlite3.Connection, tenant_id: str) -> None:
    with conn:
        conn.execute("DELETE FROM sessions WHERE tenant_id = ?", (tenant_id,))
    _with_pg_mirror(
        "delete_sessions_for_tenant",
        lambda pg: pg.execute("DELETE FROM sessions WHERE tenant_id = %s", (tenant_id,)),
    )


def is_lifecycle_email_sent(conn: sqlite3.Connection, tenant_id: str, kind: str) -> bool:
    """Return True if a lifecycle email kind has already been sent to a tenant."""
    row = conn.execute(
        "SELECT 1 FROM lifecycle_emails WHERE tenant_id = ? AND kind = ?",
        (tenant_id, kind),
    ).fetchone()
    return row is not None


def mark_lifecycle_email_sent(
    conn: sqlite3.Connection,
    tenant_id: str,
    kind: str,
    sent_at_ms: Optional[int] = None,
) -> None:
    """Persist lifecycle-email delivery so retries do not send duplicates."""
    sent_at = sent_at_ms if sent_at_ms is not None else _now_ms()
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO lifecycle_emails (tenant_id, kind, sent_at_ms) VALUES (?, ?, ?)",
            (tenant_id, kind, sent_at),
        )


def is_checkout_recovery_sent(conn: sqlite3.Connection, stripe_session_id: str) -> bool:
    """Return True if a checkout recovery was already sent for a Stripe session."""
    row = conn.execute(
        "SELECT 1 FROM checkout_recovery_emails WHERE stripe_session_id = ?",
        (stripe_session_id,),
    ).fetchone()
    return row is not None


def last_checkout_recovery_sent_at(conn: sqlite3.Connection, email: str) -> Optional[int]:
    """Return the most recent checkout-recovery send time for an email."""
    row = conn.execute(
        "SELECT MAX(sent_at_ms) AS sent_at_ms FROM checkout_recovery_emails WHERE email = ?",
        (email,),
    ).fetchone()
    if not row or row["sent_at_ms"] is None:
        return None
    return int(row["sent_at_ms"])


def mark_checkout_recovery_sent(
    conn: sqlite3.Connection,
    stripe_session_id: str,
    email: str,
    plan: Optional[str] = None,
    sent_at_ms: Optional[int] = None,
) -> None:
    """Persist checkout recovery delivery so retries do not send duplicates."""
    sent_at = sent_at_ms if sent_at_ms is not None else _now_ms()
    with conn:
        conn.execute(
            """INSERT OR IGNORE INTO checkout_recovery_emails
               (stripe_session_id, email, plan, sent_at_ms)
               VALUES (?, ?, ?, ?)""",
            (stripe_session_id, email.strip().lower(), plan, sent_at),
        )


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
