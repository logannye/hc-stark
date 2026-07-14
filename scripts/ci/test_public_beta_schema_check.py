import public_beta_schema_check as schema


def test_tracked_schema_retains_all_control_plane_invariants():
    text = schema.schema_text()
    assert schema.check(text) == []


def test_plaintext_keys_and_floating_credit_balances_are_rejected():
    text = schema.schema_text()
    failures = schema.check(text + "\napi_key_plaintext TEXT\ncredit_balance DOUBLE\n")
    assert any("api_key_plaintext" in failure for failure in failures)
    assert any("credit_balance DOUBLE" in failure for failure in failures)


def test_worker_capacity_requires_backfill_before_not_null_constraint():
    text = schema.schema_text()
    unsafe = text.replace(
        "ADD COLUMN IF NOT EXISTS total_scratch_bytes BIGINT;",
        "ADD COLUMN IF NOT EXISTS total_scratch_bytes BIGINT NOT NULL DEFAULT 0;",
    )
    failures = schema.check(unsafe)
    assert any("backfilled before it becomes NOT NULL" in failure for failure in failures)


def test_worker_capacity_upgrade_sequence_is_ordered():
    text = schema.schema_text()
    backfill = schema.WORKER_CAPACITY_UPGRADE[1]
    without_backfill = text.replace(backfill, "")
    failures = schema.check(without_backfill)
    assert any("upgrade-safe backfill contract" in failure for failure in failures)
