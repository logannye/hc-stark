import public_beta_schema_check as schema


def test_tracked_schema_retains_all_control_plane_invariants():
    text = schema.schema_text()
    assert schema.check(text) == []


def test_plaintext_keys_and_floating_credit_balances_are_rejected():
    text = schema.schema_text()
    failures = schema.check(text + "\napi_key_plaintext TEXT\ncredit_balance DOUBLE\n")
    assert any("api_key_plaintext" in failure for failure in failures)
    assert any("credit_balance DOUBLE" in failure for failure in failures)
