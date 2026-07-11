-- TinyZKP paid public-beta control-plane state.
-- PostgreSQL is authoritative; object storage and worker scratch are not ledgers.

BEGIN;

ALTER TABLE tenants ALTER COLUMN email DROP NOT NULL;

CREATE TABLE IF NOT EXISTS beta_auth_identities (
    provider TEXT NOT NULL CHECK (provider = 'github'),
    provider_user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    provider_login TEXT NOT NULL,
    verified_email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, provider_user_id),
    UNIQUE (tenant_id, provider)
);

CREATE TABLE IF NOT EXISTS beta_oauth_states (
    state_hash TEXT PRIMARY KEY CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    pkce_verifier_ciphertext BYTEA NOT NULL,
    return_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS beta_api_keys (
    api_key_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL UNIQUE CHECK (key_hash ~ '^[0-9a-f]{64}$'),
    key_prefix TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS beta_api_keys_active
    ON beta_api_keys (key_hash)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS beta_air_packages (
    air_package_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    air_digest_hex TEXT NOT NULL CHECK (air_digest_hex ~ '^[0-9a-f]{64}$'),
    package_json JSONB NOT NULL,
    release_sha TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, air_digest_hex)
);

CREATE TABLE IF NOT EXISTS beta_uploads (
    upload_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    air_package_id UUID NOT NULL REFERENCES beta_air_packages(air_package_id),
    trace_digest_hex TEXT NOT NULL CHECK (trace_digest_hex ~ '^[0-9a-f]{64}$'),
    manifest_json JSONB NOT NULL,
    object_prefix TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending','complete','expired','deleted')),
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beta_idempotency_keys (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
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

CREATE TABLE IF NOT EXISTS beta_credit_accounts (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE CASCADE,
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
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    release_sha TEXT NOT NULL,
    proof_object_key TEXT,
    proof_digest_hex TEXT CHECK (proof_digest_hex IS NULL OR proof_digest_hex ~ '^[0-9a-f]{64}$'),
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

CREATE TABLE IF NOT EXISTS beta_stripe_events (
    stripe_event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    payload_json JSONB NOT NULL,
    stripe_created_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processing_status TEXT NOT NULL CHECK (processing_status IN ('pending','processed','failed')),
    processed_at TIMESTAMPTZ,
    processing_error TEXT
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

CREATE INDEX IF NOT EXISTS beta_jobs_claimable
    ON beta_proof_jobs (created_at)
    WHERE status = 'queued';
CREATE UNIQUE INDEX IF NOT EXISTS beta_credit_stripe_events
    ON beta_credit_events (stripe_event_id, event_type)
    WHERE stripe_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS beta_jobs_tenant_created
    ON beta_proof_jobs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS beta_uploads_expiry
    ON beta_uploads (expires_at)
    WHERE status IN ('pending','complete');
CREATE INDEX IF NOT EXISTS beta_jobs_retention_expiry
    ON beta_proof_jobs (retention_expires_at)
    WHERE proof_object_key IS NOT NULL;

COMMIT;
