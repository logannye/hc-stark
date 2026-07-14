import hashlib
import json
import os
from pathlib import Path

import pytest

import public_beta_stripe_drill as drill


SHA = "a" * 40


def evidence() -> dict:
    cases = [
        {
            "id": case,
            "status": "passed",
            "object_ids": [f"cus_{index}"],
            "event_ids": [f"evt_{index}"],
            "assertions": {"exactly_once": True},
        }
        for index, case in enumerate(drill.CASE_IDS)
    ]
    return {
        "schema_version": drill.SCHEMA,
        "status": "passed",
        "release_sha": SHA,
        "stripe_api_version": drill.STRIPE_API_VERSION,
        "stripe_cli": drill.STRIPE_CLI_VERSION,
        "livemode": False,
        "database": drill.DATABASE_PREFIX + SHA[:12],
        "started_at": "2026-07-12T00:00:00Z",
        "completed_at": "2026-07-12T01:00:00Z",
        "cases": cases,
        "reconciliation": {
            "status": "passed",
            "unexplained_differences": 0,
            "ledger_mismatches": 0,
            "report_sha256": "b" * 64,
            "report_hmac_sha256": "c" * 64,
        },
        "operation_digest": hashlib.sha256(drill.canonical(cases)).hexdigest(),
    }


def test_accepts_complete_secret_free_evidence():
    assert drill.validate_evidence(evidence(), SHA)["status"] == "passed"


def test_accepts_clover_payment_record_refund_identifier():
    value = evidence()
    value["cases"][6]["object_ids"] = ["pyr_1TinyZkpCloverRefund"]

    assert drill.validate_evidence(value, SHA)["cases"][6]["object_ids"] == [
        "pyr_1TinyZkpCloverRefund"
    ]


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda value: value["cases"].pop(), "case set"),
        (lambda value: value["cases"][0]["assertions"].update(exactly_once=False), "assertions"),
        (lambda value: value.update(livemode=True), "test mode"),
        (lambda value: value["reconciliation"].update(unexplained_differences=1), "not clean"),
        (lambda value: value.update(release_sha="b" * 40), "does not match"),
    ],
)
def test_rejects_incomplete_or_mismatched_evidence(mutation, match):
    value = evidence()
    mutation(value)
    with pytest.raises(ValueError, match=match):
        drill.validate_evidence(value, SHA)


def test_rejects_secret_values_and_bearer_urls():
    value = evidence()
    value["cases"][0]["object_ids"][0] = "cus_sk_test_not_allowed"
    with pytest.raises(ValueError, match="secret-like"):
        drill.validate_evidence(value, SHA)
    value = evidence()
    value["cases"][0]["assertions"]["https://example.com/?X-Amz-Signature=bad"] = True
    with pytest.raises(ValueError, match="secret-like"):
        drill.validate_evidence(value, SHA)


def test_private_json_requires_owner_only_file(tmp_path: Path):
    path = tmp_path / "record.json"
    path.write_text(json.dumps(evidence()), encoding="utf-8")
    os.chmod(path, 0o644)
    with pytest.raises(ValueError, match="owner-only"):
        drill.read_private_json(path)
    os.chmod(path, 0o600)
    assert drill.read_private_json(path)["status"] == "passed"


@pytest.mark.parametrize("name", ["postgres", "tinyzkp_beta_stripe_drill_x", "tinyzkp_beta_stripe_drill_aaaaaaaaaaaa_extra"])
def test_database_name_is_strict(name):
    assert drill.SAFE_DATABASE.fullmatch(name) is None


def test_migration_identity_matches_sqlx_contract(tmp_path: Path):
    migration = tmp_path / "0005_self_service_contract.sql"
    content = b"SELECT 1;\n"
    migration.write_bytes(content)

    version, description, checksum = drill.migration_identity(migration)

    assert version == 5
    assert description == "self service contract"
    assert checksum == hashlib.sha384(content).digest()


@pytest.mark.parametrize(
    "name",
    [
        "self_service.sql",
        "0005-self-service.sql",
        "0005_SELF_SERVICE.sql",
        "0005_self service.sql",
    ],
)
def test_migration_identity_rejects_non_sqlx_names(tmp_path: Path, name: str):
    migration = tmp_path / name
    migration.write_text("SELECT 1;\n", encoding="utf-8")

    with pytest.raises(ValueError, match="migration filename"):
        drill.migration_identity(migration)
