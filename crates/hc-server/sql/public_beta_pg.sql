-- TinyZKP paid public-beta control-plane state.
-- PostgreSQL is authoritative; object storage and worker scratch are not ledgers.

BEGIN;

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
    reserved_millicredits BIGINT NOT NULL CHECK (reserved_millicredits >= 0),
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
    CHECK (status <> 'completed' OR (verification_succeeded AND settled_millicredits IS NOT NULL))
);

ALTER TABLE beta_credit_events
    ADD CONSTRAINT beta_credit_events_job_fk
    FOREIGN KEY (job_id) REFERENCES beta_proof_jobs(job_id) DEFERRABLE INITIALLY DEFERRED;

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
