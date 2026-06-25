-- Postgres schema for TinyZKP tenant/auth state.
--
-- Mirrors billing/tenant_store.py so API/MCP auth can cut over from local
-- tenant_store.sqlite + api_keys.txt to shared Postgres tenant state.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id                   TEXT   PRIMARY KEY,
    email                       TEXT   NOT NULL,
    api_key_hash                TEXT   NOT NULL,
    api_key_prefix              TEXT   NOT NULL,
    stripe_customer_id          TEXT,
    stripe_subscription_id      TEXT   UNIQUE,
    stripe_subscription_item_id TEXT,
    status                      TEXT   NOT NULL DEFAULT 'active',
    plan                        TEXT   NOT NULL DEFAULT 'standard',
    attribution_source          TEXT,
    attribution_medium          TEXT,
    attribution_campaign        TEXT,
    attribution_platform        TEXT,
    attribution_use_case        TEXT,
    attribution_workflow        TEXT,
    attribution_intent          TEXT,
    attribution_landing_path    TEXT,
    attribution_referrer_host   TEXT,
    attribution_first_seen_at   TEXT,
    created_at_ms               BIGINT NOT NULL,
    updated_at_ms               BIGINT NOT NULL
);

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS attribution_source TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS attribution_medium TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS attribution_campaign TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS attribution_platform TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS attribution_use_case TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS attribution_workflow TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS attribution_intent TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS attribution_landing_path TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS attribution_referrer_host TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS attribution_first_seen_at TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_api_key_hash
    ON tenants (api_key_hash);

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_free_tenant_per_email
    ON tenants (email)
    WHERE plan = 'free';

CREATE INDEX IF NOT EXISTS idx_tenants_active_key
    ON tenants (api_key_hash, status)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS processed_events (
    event_id        TEXT   PRIMARY KEY,
    processed_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS magic_links (
    token_hash    TEXT   PRIMARY KEY,
    tenant_id     TEXT   NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    used          INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_magic_links_tenant
    ON magic_links (tenant_id);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash    TEXT   PRIMARY KEY,
    tenant_id     TEXT   NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant
    ON sessions (tenant_id);
