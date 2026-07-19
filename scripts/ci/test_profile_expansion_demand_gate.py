from __future__ import annotations

import ast
import copy
import importlib.util
import json
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).with_name("profile_expansion_demand_gate.py")
SPEC = importlib.util.spec_from_file_location("profile_expansion_demand_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def record(
    index: int,
    *,
    proposed_profile_id: str = "tinyzkp-p3-babybear-v1",
    rejection_reason: str = "unsupported_profile",
    accepts_price: bool = False,
) -> dict[str, object]:
    return {
        "organization_id": f"org-{index:032x}",
        "qualification": "technically_qualified",
        "proposed_profile_id": proposed_profile_id,
        "rejection_reason": rejection_reason,
        "conditional_annual_price_usd": (
            gate.STANDARD_ANNUAL_PRICE_USD if accepts_price else None
        ),
    }


def input_with(records: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "current_profile": gate.CURRENT_PROFILE,
        "records": records,
    }


def encoded(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def default_schema_raw() -> bytes:
    _, raw = gate.load_schema()
    return raw


def test_repository_status_is_exactly_generated_blocked_and_empty() -> None:
    schema, schema_raw = gate.load_schema()
    value, input_raw = gate.load_input()
    status, _ = gate.load_status()
    assert schema == gate.expected_input_schema()
    assert gate.validate_input(value) == []
    assert gate.validate_status(status, value, input_raw, schema_raw) == []
    assert status["current_profile"] == "tinyzkp-p3-goldilocks-v1"
    assert status["status"] == "blocked"
    assert status["qualification_window_eligible"] is False
    assert status["distinct_qualified_organizations"] == 0
    assert status["conditional_standard_annual_acceptances"] == 0
    assert status["proposed_profile_id"] is None
    assert status["rejection_reason"] is None
    assert value["records"] == []

    compatibility = json.loads(
        (gate.ROOT / "release" / "plonky3-compatibility-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert compatibility["profile_id"] == gate.CURRENT_PROFILE


def test_exactly_five_organizations_and_three_acceptances_becomes_eligible() -> None:
    records = [record(index, accepts_price=index < 3) for index in range(5)]
    value = input_with(records)
    status = gate.build_status(value, encoded(value), default_schema_raw())
    assert status["status"] == "eligible"
    assert status["qualification_window_eligible"] is True
    assert status["distinct_qualified_organizations"] == 5
    assert status["conditional_standard_annual_acceptances"] == 3
    assert status["proposed_profile_id"] == "tinyzkp-p3-babybear-v1"
    assert status["rejection_reason"] == "unsupported_profile"

    serialized = json.dumps(status, sort_keys=True)
    assert all(item["organization_id"] not in serialized for item in records)
    assert "records" not in status
    assert status["organization_identifiers_included"] is False
    assert status["records_included"] is False


def test_more_than_five_distinct_organizations_can_satisfy_the_same_gate() -> None:
    value = input_with(
        [record(index, accepts_price=index < 4) for index in range(6)]
    )
    status = gate.build_status(value, encoded(value), default_schema_raw())
    assert status["qualification_window_eligible"] is True
    assert status["distinct_qualified_organizations"] == 6
    assert status["conditional_standard_annual_acceptances"] == 4


@pytest.mark.parametrize(
    ("organization_count", "acceptance_count"),
    [(0, 0), (4, 3), (5, 2)],
)
def test_thresholds_fail_closed(
    organization_count: int, acceptance_count: int
) -> None:
    value = input_with(
        [
            record(index, accepts_price=index < acceptance_count)
            for index in range(organization_count)
        ]
    )
    status = gate.build_status(value, encoded(value), default_schema_raw())
    assert status["status"] == "blocked"
    assert status["qualification_window_eligible"] is False


def test_duplicate_or_unsorted_organization_ids_are_rejected() -> None:
    duplicate = [record(1), record(1)]
    assert "organization_id values must be distinct" in gate.validate_input(
        input_with(duplicate)
    )

    unsorted = [record(2), record(1)]
    assert "records must be sorted by organization_id" in gate.validate_input(
        input_with(unsorted)
    )


def test_mixed_profile_and_reason_records_are_rejected() -> None:
    mixed_profile = [
        record(1),
        record(2, proposed_profile_id="tinyzkp-p3-mersenne31-v1"),
    ]
    assert "all records must share one proposed_profile_id" in gate.validate_input(
        input_with(mixed_profile)
    )

    mixed_reason = [
        record(1),
        record(2, rejection_reason="unsupported_air_feature"),
    ]
    assert "all records must share one rejection_reason" in gate.validate_input(
        input_with(mixed_reason)
    )


@pytest.mark.parametrize(
    "reason",
    [
        "checkpoint_corrupt",
        "ram_budget_insufficient",
        "custom_field_requested",
        "other",
        "",
    ],
)
def test_only_existing_incompatibility_reason_vocabulary_is_accepted(
    reason: str,
) -> None:
    errors = gate.validate_input(input_with([record(1, rejection_reason=reason)]))
    assert any("existing incompatibility vocabulary" in error for error in errors)
    assert gate.SUPPORTED_REJECTION_REASONS == {
        "unsupported_air_feature",
        "unsupported_platform",
        "unsupported_profile",
    }


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "name",
        "email",
        "contact",
        "notes",
        "free_text",
        "witness",
        "witness_data",
        "raw_report",
        "compatibility_report",
    ],
)
def test_pii_witness_raw_report_and_free_text_fields_are_rejected(
    forbidden_field: str,
) -> None:
    item = record(1)
    item[forbidden_field] = "forbidden"
    errors = gate.validate_input(input_with([item]))
    assert any("five privacy-minimal fields" in error for error in errors)

    top_level = input_with([])
    top_level[forbidden_field] = "forbidden"
    errors = gate.validate_input(top_level)
    assert any("must contain exactly" in error for error in errors)


@pytest.mark.parametrize(
    "organization_id",
    [
        "alice@example.com",
        "Acme Corp",
        "org-1",
        "partner-00000000000000000000000000000001",
        "org-0000000000000000000000000000000G",
    ],
)
def test_organization_identifier_must_be_opaque(organization_id: str) -> None:
    item = record(1)
    item["organization_id"] = organization_id
    errors = gate.validate_input(input_with([item]))
    assert any("opaque org-<32 hex>" in error for error in errors)


def test_only_qualified_records_and_the_exact_standard_price_are_accepted() -> None:
    item = record(1)
    item["qualification"] = "prospect"
    assert any(
        "technically_qualified" in error
        for error in gate.validate_input(input_with([item]))
    )

    for invalid_price in [True, False, 499, 5_000, "4990"]:
        item = record(1)
        item["conditional_annual_price_usd"] = invalid_price
        assert any(
            "must be null or 4990" in error
            for error in gate.validate_input(input_with([item]))
        )


def test_current_profile_cannot_be_changed_or_proposed() -> None:
    changed = input_with([])
    changed["current_profile"] = "tinyzkp-p3-babybear-v1"
    assert any("current_profile must remain" in error for error in gate.validate_input(changed))

    current_as_proposed = input_with(
        [record(1, proposed_profile_id=gate.CURRENT_PROFILE)]
    )
    assert any(
        "non-v1 structured profile ID" in error
        for error in gate.validate_input(current_as_proposed)
    )


def test_status_rejects_input_schema_and_aggregate_tampering() -> None:
    value = input_with([record(index, accepts_price=index < 3) for index in range(5)])
    input_raw = encoded(value)
    schema_raw = default_schema_raw()
    status = gate.build_status(value, input_raw, schema_raw)

    tampered_digest = copy.deepcopy(status)
    tampered_digest["source"]["input_sha256"] = "0" * 64
    errors = gate.validate_status(tampered_digest, value, input_raw, schema_raw)
    assert "generated status source/digest does not match input and schema" in errors

    altered_source_bytes = input_raw + b" "
    errors = gate.validate_status(status, value, altered_source_bytes, schema_raw)
    assert "generated status source/digest does not match input and schema" in errors

    altered_schema_bytes = schema_raw + b" "
    errors = gate.validate_status(status, value, input_raw, altered_schema_bytes)
    assert "generated status source/digest does not match input and schema" in errors

    tampered_aggregate = copy.deepcopy(status)
    tampered_aggregate["qualification_window_eligible"] = False
    errors = gate.validate_status(tampered_aggregate, value, input_raw, schema_raw)
    assert "generated status differs from the exact aggregate" in errors


def test_generate_then_check_is_local_and_source_bound(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    value = input_with([record(index, accepts_price=index < 3) for index in range(5)])
    input_path = tmp_path / "input.json"
    status_path = tmp_path / "status.json"
    input_path.write_bytes(encoded(value))
    assert (
        gate.main(
            [
                "--input",
                str(input_path),
                "--status",
                str(status_path),
                "--generate",
                "--require-eligible",
            ]
        )
        == 0
    )
    assert gate.main(["--input", str(input_path), "--status", str(status_path)]) == 0

    input_path.write_bytes(input_path.read_bytes() + b" ")
    assert gate.main(["--input", str(input_path), "--status", str(status_path)]) == 1
    assert "source/digest" in capsys.readouterr().err


def test_strict_loader_rejects_duplicate_keys_and_non_object_input(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":1,"schema_version":1,'
        '"current_profile":"tinyzkp-p3-goldilocks-v1","records":[]}',
        encoding="utf-8",
    )
    with pytest.raises(gate.GateError, match="duplicate JSON object key"):
        gate.load_input(duplicate)

    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")
    with pytest.raises(gate.GateError, match="must be a JSON object"):
        gate.load_input(array)


def test_gate_has_no_network_or_crm_dependency() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.split(".", 1)[0])
    assert imported_roots.isdisjoint(
        {"boto3", "http", "requests", "socket", "stripe", "urllib"}
    )


def test_ci_validates_the_gate_and_generated_status() -> None:
    workflow = (gate.ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    assert "scripts/ci/test_profile_expansion_demand_gate.py" in workflow
    assert "python3 scripts/ci/profile_expansion_demand_gate.py" in workflow
