-- Low-touch self-service product contract. The environment write switch remains
-- the outer fail-closed gate; these flags allow incident containment without a
-- deploy and can only be re-enabled by an explicit operator action.
CREATE TABLE IF NOT EXISTS beta_operational_flags (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    signup_enabled BOOLEAN NOT NULL DEFAULT true,
    checkout_enabled BOOLEAN NOT NULL DEFAULT true,
    job_submission_enabled BOOLEAN NOT NULL DEFAULT true,
    containment_reason TEXT,
    contained_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO beta_operational_flags (singleton) VALUES (true) ON CONFLICT DO NOTHING;

ALTER TABLE beta_sandbox_grants
    ADD COLUMN IF NOT EXISTS entitlement_state TEXT NOT NULL DEFAULT 'available',
    ADD COLUMN IF NOT EXISTS reserved_job_id UUID,
    ADD COLUMN IF NOT EXISTS reserved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;
ALTER TABLE beta_sandbox_grants
    DROP CONSTRAINT IF EXISTS beta_sandbox_grants_entitlement_state_check;
ALTER TABLE beta_sandbox_grants
    ADD CONSTRAINT beta_sandbox_grants_entitlement_state_check
    CHECK (entitlement_state IN ('available','reserved','consumed'));
ALTER TABLE beta_sandbox_grants
    ADD CONSTRAINT beta_sandbox_grants_state_shape_check CHECK (
        (entitlement_state='available' AND reserved_job_id IS NULL AND reserved_at IS NULL AND consumed_at IS NULL)
        OR (entitlement_state='reserved' AND reserved_job_id IS NOT NULL AND reserved_at IS NOT NULL AND consumed_at IS NULL)
        OR (entitlement_state='consumed' AND consumed_at IS NOT NULL)
    );

ALTER TABLE beta_proof_jobs
    ADD COLUMN IF NOT EXISTS resource_report_json JSONB,
    ADD COLUMN IF NOT EXISTS sandbox_job BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS realized_gross_margin_bps INTEGER
        CHECK (realized_gross_margin_bps IS NULL OR realized_gross_margin_bps BETWEEN -100000 AND 10000);

CREATE INDEX IF NOT EXISTS beta_sandbox_grants_reserved_job
    ON beta_sandbox_grants (reserved_job_id) WHERE reserved_job_id IS NOT NULL;

-- The old candidate represented Sandbox as fungible purchased credit. The
-- self-service contract replaces it with a non-fungible one-run entitlement so
-- a top-up cannot accidentally make the free credit spendable on arbitrary AIR.
INSERT INTO beta_credit_events
    (event_id,tenant_id,event_type,purchased_delta_millicredits,operation_key,metadata)
SELECT md5(a.tenant_id || ':sandbox-credit-retired')::uuid,a.tenant_id,'expiry',-1000,
       'sandbox:credit-retired','{"reason":"non_fungible_sample_entitlement"}'::jsonb
  FROM beta_credit_accounts a
  JOIN beta_auth_identities i ON i.tenant_id=a.tenant_id
  JOIN beta_sandbox_grants g ON g.provider=i.provider AND g.provider_user_id=i.provider_user_id
 WHERE a.purchased_millicredits>=1000
ON CONFLICT (tenant_id,operation_key) DO NOTHING;
UPDATE beta_credit_accounts a SET purchased_millicredits=purchased_millicredits-1000,
       version=version+1,updated_at=now()
 WHERE EXISTS(SELECT 1 FROM beta_credit_events e WHERE e.tenant_id=a.tenant_id
               AND e.operation_key='sandbox:credit-retired');
