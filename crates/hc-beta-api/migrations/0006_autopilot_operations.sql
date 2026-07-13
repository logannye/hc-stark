-- Fail-closed, low-touch operations and business viability controls.

ALTER TABLE beta_workers
    ADD COLUMN IF NOT EXISTS total_scratch_bytes BIGINT NOT NULL DEFAULT 0
        CHECK (total_scratch_bytes >= 0 AND free_scratch_bytes <= total_scratch_bytes);

CREATE TABLE IF NOT EXISTS beta_operational_incidents (
    incident_id UUID PRIMARY KEY,
    release_sha TEXT NOT NULL CHECK (release_sha ~ '^[0-9a-f]{40}$'),
    violations JSONB NOT NULL,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    alerted_at TIMESTAMPTZ,
    recovered_at TIMESTAMPTZ,
    recovery_operation TEXT,
    CHECK (jsonb_typeof(violations) = 'array')
);
CREATE UNIQUE INDEX IF NOT EXISTS beta_one_open_operational_incident
    ON beta_operational_incidents ((true)) WHERE recovered_at IS NULL;

CREATE TABLE IF NOT EXISTS beta_invariant_acknowledgements (
    invariant TEXT PRIMARY KEY CHECK (invariant IN ('official_verifier_rejection')),
    acknowledged_at TIMESTAMPTZ NOT NULL,
    release_sha TEXT NOT NULL CHECK (release_sha ~ '^[0-9a-f]{40}$'),
    operation_key TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS beta_infrastructure_health (
    component TEXT PRIMARY KEY CHECK (component IN ('backup_wal','api_storage')),
    healthy BOOLEAN NOT NULL,
    free_percent INTEGER CHECK (free_percent IS NULL OR free_percent BETWEEN 0 AND 100),
    observed_at TIMESTAMPTZ NOT NULL,
    release_sha TEXT NOT NULL CHECK (release_sha ~ '^[0-9a-f]{40}$')
);

CREATE TABLE IF NOT EXISTS beta_support_minutes (
    support_entry_id UUID PRIMARY KEY,
    category TEXT NOT NULL CHECK (category IN ('onboarding','billing','proof','security','operations','other')),
    minutes INTEGER NOT NULL CHECK (minutes BETWEEN 1 AND 240),
    operation_key TEXT NOT NULL UNIQUE,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beta_business_activation (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    activated_at TIMESTAMPTZ NOT NULL,
    release_sha TEXT NOT NULL CHECK (release_sha ~ '^[0-9a-f]{40}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS beta_viability_reports (
    report_day INTEGER PRIMARY KEY CHECK (report_day IN (30,60,90)),
    release_sha TEXT NOT NULL CHECK (release_sha ~ '^[0-9a-f]{40}$'),
    status TEXT NOT NULL CHECK (status IN ('passed','failed','informational')),
    report_json JSONB NOT NULL,
    report_sha256 TEXT NOT NULL CHECK (report_sha256 ~ '^[0-9a-f]{64}$'),
    report_hmac_sha256 TEXT NOT NULL CHECK (report_hmac_sha256 ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
