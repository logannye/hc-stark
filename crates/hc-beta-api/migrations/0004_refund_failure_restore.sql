ALTER TABLE beta_credit_events
    DROP CONSTRAINT IF EXISTS beta_credit_events_event_type_check;
ALTER TABLE beta_credit_events
    ADD CONSTRAINT beta_credit_events_event_type_check CHECK (event_type IN (
        'sandbox_grant','subscription_grant','topup_grant','reservation',
        'settlement','reservation_release','platform_refund','refund_reversal',
        'refund_failure_restore','expiry','adjustment'
    ));
