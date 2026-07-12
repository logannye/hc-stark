ALTER TABLE beta_stripe_events
    ADD COLUMN IF NOT EXISTS livemode BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS stripe_object_type TEXT,
    ADD COLUMN IF NOT EXISTS processing_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS processing_lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;

ALTER TABLE beta_stripe_events
    DROP CONSTRAINT IF EXISTS beta_stripe_events_processing_status_check;
ALTER TABLE beta_stripe_events
    ADD CONSTRAINT beta_stripe_events_processing_status_check
    CHECK (processing_status IN ('pending','processing','processed','failed'));

ALTER TABLE beta_credit_events
    DROP CONSTRAINT IF EXISTS beta_credit_events_event_type_check;
ALTER TABLE beta_credit_events
    ADD CONSTRAINT beta_credit_events_event_type_check CHECK (event_type IN (
        'sandbox_grant','subscription_grant','topup_grant','reservation',
        'settlement','reservation_release','platform_refund','refund_reversal',
        'expiry','adjustment'
    ));

CREATE TABLE IF NOT EXISTS beta_stripe_object_state (
    stripe_object_type TEXT NOT NULL,
    stripe_object_id TEXT NOT NULL,
    last_applied_event_created BIGINT NOT NULL,
    last_applied_event_id TEXT NOT NULL,
    canonical_state JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (stripe_object_type, stripe_object_id)
);

CREATE TABLE IF NOT EXISTS beta_credit_grants (
    grant_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    grant_kind TEXT NOT NULL CHECK (grant_kind IN ('subscription','topup')),
    credit_bucket TEXT NOT NULL CHECK (credit_bucket IN ('subscription','purchased')),
    semantic_key TEXT NOT NULL UNIQUE,
    stripe_invoice_id TEXT,
    stripe_checkout_session_id TEXT,
    stripe_payment_intent_id TEXT,
    stripe_charge_id TEXT,
    stripe_event_id TEXT NOT NULL,
    granted_millicredits BIGINT NOT NULL CHECK (granted_millicredits > 0),
    reversed_millicredits BIGINT NOT NULL DEFAULT 0
        CHECK (reversed_millicredits >= 0 AND reversed_millicredits <= granted_millicredits),
    synthetic_canary BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beta_refunds (
    stripe_refund_id TEXT PRIMARY KEY,
    grant_id UUID REFERENCES beta_credit_grants(grant_id) ON DELETE RESTRICT,
    tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    stripe_payment_intent_id TEXT,
    stripe_charge_id TEXT,
    amount_minor BIGINT NOT NULL CHECK (amount_minor >= 0),
    status TEXT NOT NULL,
    stripe_event_id TEXT NOT NULL,
    stripe_event_created BIGINT NOT NULL,
    reversed_millicredits BIGINT NOT NULL DEFAULT 0 CHECK (reversed_millicredits >= 0),
    applied_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beta_billing_discrepancies (
    discrepancy_id UUID PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    discrepancy_type TEXT NOT NULL,
    semantic_key TEXT NOT NULL UNIQUE,
    details JSONB NOT NULL,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE beta_reconciliation_runs
    ADD COLUMN IF NOT EXISTS report_sha256 TEXT
        CHECK (report_sha256 IS NULL OR report_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN IF NOT EXISTS report_hmac_sha256 TEXT
        CHECK (report_hmac_sha256 IS NULL OR report_hmac_sha256 ~ '^[0-9a-f]{64}$');

CREATE INDEX IF NOT EXISTS beta_stripe_events_pending
    ON beta_stripe_events (stripe_created_at, received_at)
    WHERE processing_status IN ('pending','failed','processing');
CREATE INDEX IF NOT EXISTS beta_credit_grants_payment_intent
    ON beta_credit_grants (stripe_payment_intent_id)
    WHERE stripe_payment_intent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS beta_credit_grants_charge
    ON beta_credit_grants (stripe_charge_id)
    WHERE stripe_charge_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS beta_refunds_grant ON beta_refunds (grant_id);
