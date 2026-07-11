-- TinyZKP paid public-beta control plane.
-- PostgreSQL is authoritative; R2 and worker scratch are not ledgers.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    email TEXT,
    api_key_hash TEXT,
    api_key_prefix TEXT,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT UNIQUE,
    stripe_subscription_item_id TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    plan TEXT NOT NULL DEFAULT 'sandbox',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

ALTER TABLE tenants ALTER COLUMN email DROP NOT NULL;
ALTER TABLE tenants ALTER COLUMN api_key_hash DROP NOT NULL;
ALTER TABLE tenants ALTER COLUMN api_key_prefix DROP NOT NULL;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS beta_auth_identities (
    provider TEXT NOT NULL CHECK (provider = 'github'),
    provider_user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    provider_login TEXT NOT NULL,
    verified_email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, provider_user_id),
    UNIQUE (tenant_id, provider)
);

-- This tombstone intentionally has no tenant FK. Account deletion must not
-- allow a GitHub identity to receive a second sandbox grant.
CREATE TABLE IF NOT EXISTS beta_sandbox_grants (
    provider TEXT NOT NULL CHECK (provider = 'github'),
    provider_user_id TEXT NOT NULL,
    original_tenant_id TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, provider_user_id)
);

CREATE TABLE IF NOT EXISTS beta_oauth_states (
    state_hash TEXT PRIMARY KEY CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    pkce_verifier_ciphertext BYTEA NOT NULL,
    return_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS beta_sessions (
    session_hash TEXT PRIMARY KEY CHECK (session_hash ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS beta_api_keys (
    api_key_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    key_hash TEXT NOT NULL UNIQUE CHECK (key_hash ~ '^[0-9a-f]{64}$'),
    key_prefix TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS beta_air_packages (
    air_package_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    air_digest_hex TEXT NOT NULL CHECK (air_digest_hex ~ '^[0-9a-f]{64}$'),
    package_json JSONB NOT NULL,
    release_sha TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, air_digest_hex)
);

CREATE TABLE IF NOT EXISTS beta_uploads (
    upload_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    air_package_id UUID NOT NULL REFERENCES beta_air_packages(air_package_id),
    trace_digest_hex TEXT NOT NULL CHECK (trace_digest_hex ~ '^[0-9a-f]{64}$'),
    manifest_json JSONB NOT NULL,
    object_prefix TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending','complete','expired','deleting','deleted')),
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beta_upload_chunks (
    upload_id UUID NOT NULL REFERENCES beta_uploads(upload_id) ON DELETE RESTRICT,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    object_key TEXT NOT NULL UNIQUE,
    compressed_bytes BIGINT NOT NULL CHECK (compressed_bytes > 0),
    uncompressed_bytes BIGINT NOT NULL CHECK (uncompressed_bytes > 0),
    blake3_hex TEXT NOT NULL CHECK (blake3_hex ~ '^[0-9a-f]{64}$'),
    object_etag TEXT,
    verified_at TIMESTAMPTZ,
    PRIMARY KEY (upload_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS beta_idempotency_keys (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    response_status INTEGER,
    response_json JSONB,
    resource_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, operation, idempotency_key)
);

CREATE TABLE IF NOT EXISTS beta_rate_limits (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    scope TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL CHECK (request_count > 0),
    PRIMARY KEY (tenant_id, scope, window_start)
);

CREATE TABLE IF NOT EXISTS beta_credit_accounts (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    subscription_millicredits BIGINT NOT NULL DEFAULT 0 CHECK (subscription_millicredits >= 0),
    purchased_millicredits BIGINT NOT NULL DEFAULT 0 CHECK (purchased_millicredits >= 0),
    reserved_millicredits BIGINT NOT NULL DEFAULT 0 CHECK (reserved_millicredits >= 0),
    subscription_expires_at TIMESTAMPTZ,
    paid_work_frozen BOOLEAN NOT NULL DEFAULT false,
    version BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beta_credit_events (
    event_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'sandbox_grant','subscription_grant','topup_grant','reservation',
        'settlement','reservation_release','platform_refund','expiry','adjustment'
    )),
    subscription_delta_millicredits BIGINT NOT NULL DEFAULT 0,
    purchased_delta_millicredits BIGINT NOT NULL DEFAULT 0,
    reserved_delta_millicredits BIGINT NOT NULL DEFAULT 0,
    job_id UUID,
    stripe_event_id TEXT,
    operation_key TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, operation_key)
);

CREATE TABLE IF NOT EXISTS beta_proof_jobs (
    job_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    air_package_id UUID NOT NULL REFERENCES beta_air_packages(air_package_id),
    upload_id UUID NOT NULL REFERENCES beta_uploads(upload_id),
    status TEXT NOT NULL CHECK (status IN (
        'queued','leased','proving','verifying','completed','cancel_requested',
        'cancelled','platform_failed','customer_failed'
    )),
    estimate_json JSONB NOT NULL,
    public_inputs_json JSONB NOT NULL,
    public_inputs_digest_hex TEXT NOT NULL CHECK (public_inputs_digest_hex ~ '^[0-9a-f]{64}$'),
    reserved_millicredits BIGINT NOT NULL CHECK (reserved_millicredits >= 0),
    reserved_subscription_millicredits BIGINT NOT NULL CHECK (reserved_subscription_millicredits >= 0),
    reserved_purchased_millicredits BIGINT NOT NULL CHECK (reserved_purchased_millicredits >= 0),
    settled_millicredits BIGINT CHECK (settled_millicredits >= 0),
    measured_cost_millicredits BIGINT CHECK (measured_cost_millicredits >= 0),
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    lease_epoch BIGINT NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0 AND attempt <= 3),
    progress_json JSONB,
    checkpoint_identity TEXT,
    release_sha TEXT NOT NULL,
    proof_object_key TEXT,
    proof_digest_hex TEXT CHECK (proof_digest_hex IS NULL OR proof_digest_hex ~ '^[0-9a-f]{64}$'),
    proof_size_bytes BIGINT CHECK (proof_size_bytes IS NULL OR proof_size_bytes > 0),
    verification_succeeded BOOLEAN,
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    retention_expires_at TIMESTAMPTZ NOT NULL,
    cancelled_at TIMESTAMPTZ,
    CHECK (reserved_millicredits = reserved_subscription_millicredits + reserved_purchased_millicredits),
    CHECK (status <> 'completed' OR (verification_succeeded AND settled_millicredits IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS beta_job_attempts (
    job_id UUID NOT NULL REFERENCES beta_proof_jobs(job_id) ON DELETE RESTRICT,
    attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 3),
    lease_epoch BIGINT NOT NULL,
    worker_id TEXT NOT NULL,
    release_sha TEXT NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    result TEXT,
    checkpoint_identity TEXT,
    PRIMARY KEY (job_id, attempt)
);

CREATE TABLE IF NOT EXISTS beta_workers (
    worker_id TEXT PRIMARY KEY,
    credential_hash TEXT NOT NULL CHECK (credential_hash ~ '^[0-9a-f]{64}$'),
    enabled BOOLEAN NOT NULL DEFAULT true,
    max_slots INTEGER NOT NULL CHECK (max_slots BETWEEN 1 AND 4),
    free_scratch_bytes BIGINT NOT NULL DEFAULT 0 CHECK (free_scratch_bytes >= 0),
    release_sha TEXT,
    last_heartbeat_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beta_billing_customers (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    stripe_customer_id TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beta_subscriptions (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    stripe_subscription_id TEXT UNIQUE,
    stripe_price_id TEXT,
    sku TEXT,
    status TEXT,
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beta_stripe_events (
    stripe_event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    payload_json JSONB NOT NULL,
    stripe_created_at TIMESTAMPTZ NOT NULL,
    stripe_customer_id TEXT,
    stripe_object_id TEXT,
    processing_status TEXT NOT NULL CHECK (processing_status IN ('pending','processed','failed')),
    processing_result JSONB,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ,
    processing_error TEXT
);

CREATE TABLE IF NOT EXISTS beta_reconciliation_runs (
    reconciliation_id UUID PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('running','clean','discrepancy','failed')),
    report_json JSONB,
    release_sha TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS beta_retention_deletions (
    deletion_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    object_key TEXT NOT NULL UNIQUE,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('upload','trace','proof')),
    resource_id UUID NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    last_error TEXT,
    attempt INTEGER NOT NULL DEFAULT 0
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'beta_credit_events_job_fk'
    ) THEN
        ALTER TABLE beta_credit_events
            ADD CONSTRAINT beta_credit_events_job_fk
            FOREIGN KEY (job_id) REFERENCES beta_proof_jobs(job_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS beta_api_keys_active ON beta_api_keys (key_hash) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS beta_sessions_active ON beta_sessions (session_hash) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS beta_jobs_claimable ON beta_proof_jobs (created_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS beta_jobs_tenant_created ON beta_proof_jobs (tenant_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS beta_credit_stripe_events ON beta_credit_events (stripe_event_id, event_type) WHERE stripe_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS beta_uploads_expiry ON beta_uploads (expires_at) WHERE status IN ('pending','complete');
CREATE INDEX IF NOT EXISTS beta_jobs_retention_expiry ON beta_proof_jobs (retention_expires_at) WHERE proof_object_key IS NOT NULL;
