from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

import legacy_billing_containment_status as status


ACCOUNT_ID = "acct_1234567890ABCDEF"
DISPLAY_NAME = "LN Holdings"
RELEASE = "a" * 40
DEPLOYMENT = "tinyzkp-production-primary"


def inventory(*, contained: bool = False, unknown: bool = False) -> dict[str, object]:
    legacy_product = {
        "id": "prod_legacy",
        "name": "TinyZKP legacy",
        "active": True,
        "metadata": {"tinyzkp": "legacy"},
    }
    unrelated_product = {
        "id": "prod_unrelated",
        "name": "Unrelated business",
        "active": True,
        "metadata": {},
    }
    objects: dict[str, list[dict[str, object]]] = {
        "products": [legacy_product, unrelated_product],
        "prices": [
            {
                "id": "price_legacy",
                "product_id": "prod_legacy",
                "active": True,
                "currency": "usd",
                "lookup_key": "",
                "metadata": {},
            },
            {
                "id": "price_unrelated",
                "product_id": "prod_unrelated",
                "active": True,
                "currency": "usd",
                "lookup_key": "",
                "metadata": {},
            },
        ],
        "payment_links": [
            {"id": "plink_legacy", "active": True, "product_ids": ["prod_legacy"]},
            {
                "id": "plink_unrelated",
                "active": True,
                "product_ids": ["prod_unrelated"],
            },
        ],
        "subscriptions": [
            {
                "id": "sub_legacy",
                "customer_id": "cus_legacy",
                "status": "active",
                "pause_collection_behavior": "",
                "product_ids": ["prod_legacy"],
            },
            {
                "id": "sub_unrelated",
                "customer_id": "cus_unrelated",
                "status": "active",
                "pause_collection_behavior": "",
                "product_ids": ["prod_unrelated"],
            },
        ],
        "meters": [
            {"id": "mtr_legacy", "event_name": "legacy", "status": "active"},
            {"id": "mtr_unrelated", "event_name": "other", "status": "active"},
        ],
        "open_invoices": [
            {
                "id": "in_legacy",
                "customer_id": "cus_legacy",
                "subscription_id": "sub_legacy",
                "status": "open",
                "amount_remaining": 1000,
                "currency": "usd",
            },
            {
                "id": "in_unrelated",
                "customer_id": "cus_unrelated",
                "subscription_id": "sub_unrelated",
                "status": "open",
                "amount_remaining": 2000,
                "currency": "usd",
            },
        ],
    }
    if contained:
        legacy_ids = {
            "products": "prod_legacy",
            "prices": "price_legacy",
            "payment_links": "plink_legacy",
            "subscriptions": "sub_legacy",
            "meters": "mtr_legacy",
            "open_invoices": "in_legacy",
        }
        for group, object_id in legacy_ids.items():
            objects[group] = [record for record in objects[group] if record["id"] != object_id]
    if unknown:
        objects["products"].append(
            {
                "id": "prod_unknown",
                "name": "Unreviewed product",
                "active": True,
                "metadata": {},
            }
        )
    for records in objects.values():
        records.sort(key=lambda record: str(record["id"]))
    document: dict[str, object] = {
        "schema_version": 1,
        "stripe_account_id": ACCOUNT_ID,
        "stripe_display_name": DISPLAY_NAME,
        "objects": objects,
    }
    return {**document, "inventory_sha256": status._inventory_digest(document)}


def write_inputs(
    tmp_path: Path,
    *,
    current_contained: bool = True,
    current_unknown: bool = False,
) -> tuple[Path, Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    baseline_value = inventory()
    current_value = inventory(contained=current_contained, unknown=current_unknown)
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    scope = tmp_path / "scope.json"
    ledger = tmp_path / "ledger.json"
    baseline.write_text(json.dumps(baseline_value), encoding="utf-8")
    current.write_text(json.dumps(current_value), encoding="utf-8")
    scope.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "stripe_account_id": ACCOUNT_ID,
                "stripe_display_name": DISPLAY_NAME,
                "inventory_sha256": baseline_value["inventory_sha256"],
                "selections": {
                    "product_ids": ["prod_legacy"],
                    "price_ids": ["price_legacy"],
                    "payment_link_ids": ["plink_legacy"],
                    "meter_ids": ["mtr_legacy"],
                    "subscription_ids": ["sub_legacy"],
                    "open_invoice_ids": ["in_legacy"],
                },
            }
        ),
        encoding="utf-8",
    )
    ledger.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "stripe_account_id": ACCOUNT_ID,
                "inventory_sha256": baseline_value["inventory_sha256"],
                "subscriptions": [
                    {
                        "subscription_id": "sub_legacy",
                        "customer_id": "cus_legacy",
                        "notified_at": "2026-07-10T12:00:00Z",
                        "notification_channel": "signal",
                        "notification_evidence_sha256": "b" * 64,
                        "resolution": "credit",
                        "resolution_object_id": "cn_legacy",
                        "resolution_amount": 1000,
                        "currency": "usd",
                        "resolution_evidence_sha256": "c" * 64,
                        "approved_open_invoice_ids": ["in_legacy"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return baseline, current, scope, ledger


def capture(tmp_path: Path, now: datetime) -> Path:
    baseline, current, scope, ledger = write_inputs(tmp_path)
    output = tmp_path / "status.json"
    report = status.capture_evidence(
        baseline_inventory_path=baseline,
        current_inventory_path=current,
        scope_manifest_path=scope,
        notification_ledger_path=ledger,
        output=output,
        release_sha=RELEASE,
        deployment_id=DEPLOYMENT,
        expected_account_id=ACCOUNT_ID,
        expected_display_name=DISPLAY_NAME,
        observed_at=now,
        now=now,
    )
    assert report["status"] == "contained"
    assert output.stat().st_mode & 0o777 == 0o600
    return output


def test_capture_and_verify_exact_legacy_containment(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    output = capture(tmp_path, now)

    report = status.validate_evidence(
        output,
        expected_release_sha=RELEASE,
        expected_deployment_id=DEPLOYMENT,
        expected_account_id=ACCOUNT_ID,
        expected_display_name=DISPLAY_NAME,
        now=now,
        enforce_fixed_path=False,
    )

    assert report["status"] == "contained"
    assert len(report["current_inventory_sha256"]) == 64
    assert len(report["evidence_identity_sha256"]) == 64


def test_selected_subscription_may_remain_only_with_void_pause(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    baseline, current, scope, ledger = write_inputs(tmp_path)
    current_value = json.loads(current.read_text(encoding="utf-8"))
    current_value["objects"]["subscriptions"].append(
        {
            "id": "sub_legacy",
            "customer_id": "cus_legacy",
            "status": "active",
            "pause_collection_behavior": "void",
            "product_ids": ["prod_legacy"],
        }
    )
    current_value["objects"]["subscriptions"].sort(key=lambda item: item["id"])
    document = {
        key: value
        for key, value in current_value.items()
        if key != "inventory_sha256"
    }
    current_value["inventory_sha256"] = status._inventory_digest(document)
    current.write_text(json.dumps(current_value), encoding="utf-8")

    report = status.capture_evidence(
        baseline_inventory_path=baseline,
        current_inventory_path=current,
        scope_manifest_path=scope,
        notification_ledger_path=ledger,
        output=tmp_path / "paused-status.json",
        release_sha=RELEASE,
        deployment_id=DEPLOYMENT,
        expected_account_id=ACCOUNT_ID,
        expected_display_name=DISPLAY_NAME,
        observed_at=now,
        now=now,
    )

    assert report["status"] == "contained"


def test_rejects_selected_or_unreviewed_active_objects(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    baseline, current, scope, ledger = write_inputs(
        tmp_path / "selected", current_contained=False
    )
    with pytest.raises(status.EvidenceError, match="remains active"):
        status.capture_evidence(
            baseline_inventory_path=baseline,
            current_inventory_path=current,
            scope_manifest_path=scope,
            notification_ledger_path=ledger,
            output=tmp_path / "selected-status.json",
            release_sha=RELEASE,
            deployment_id=DEPLOYMENT,
            expected_account_id=ACCOUNT_ID,
            expected_display_name=DISPLAY_NAME,
            observed_at=now,
            now=now,
        )

    baseline, current, scope, ledger = write_inputs(
        tmp_path / "unknown", current_unknown=True
    )
    with pytest.raises(status.EvidenceError, match="unreviewed active object"):
        status.capture_evidence(
            baseline_inventory_path=baseline,
            current_inventory_path=current,
            scope_manifest_path=scope,
            notification_ledger_path=ledger,
            output=tmp_path / "unknown-status.json",
            release_sha=RELEASE,
            deployment_id=DEPLOYMENT,
            expected_account_id=ACCOUNT_ID,
            expected_display_name=DISPLAY_NAME,
            observed_at=now,
            now=now,
        )


def test_rejects_missing_or_incomplete_notification_resolution(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    baseline, current, scope, ledger = write_inputs(tmp_path)
    with pytest.raises(status.EvidenceError, match="notification-resolution ledger"):
        status.capture_evidence(
            baseline_inventory_path=baseline,
            current_inventory_path=current,
            scope_manifest_path=scope,
            notification_ledger_path=None,
            output=tmp_path / "missing.json",
            release_sha=RELEASE,
            deployment_id=DEPLOYMENT,
            expected_account_id=ACCOUNT_ID,
            expected_display_name=DISPLAY_NAME,
            observed_at=now,
            now=now,
        )

    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["subscriptions"][0]["approved_open_invoice_ids"] = []
    ledger.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(status.EvidenceError, match="approve selected invoices"):
        status.capture_evidence(
            baseline_inventory_path=baseline,
            current_inventory_path=current,
            scope_manifest_path=scope,
            notification_ledger_path=ledger,
            output=tmp_path / "incomplete.json",
            release_sha=RELEASE,
            deployment_id=DEPLOYMENT,
            expected_account_id=ACCOUNT_ID,
            expected_display_name=DISPLAY_NAME,
            observed_at=now,
            now=now,
        )


def test_verifier_rejects_inventory_or_tool_tampering(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    output = capture(tmp_path, now)
    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["allowed_active_ids"]["product_ids"].append("prod_unknown")
    payload["allowed_active_ids"]["product_ids"].sort()
    payload["subject_sha256"] = status._sha256(status._subject(payload))
    output.write_bytes(status._canonical(payload))
    with pytest.raises(status.EvidenceError, match="classifications"):
        status.validate_evidence(
            output,
            expected_release_sha=RELEASE,
            expected_deployment_id=DEPLOYMENT,
            expected_account_id=ACCOUNT_ID,
            expected_display_name=DISPLAY_NAME,
            now=now,
            enforce_fixed_path=False,
        )

    output = capture(tmp_path / "tool", now)
    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["source"]["status_tool_sha256"] = "0" * 64
    payload["subject_sha256"] = status._sha256(status._subject(payload))
    output.write_bytes(status._canonical(payload))
    with pytest.raises(status.EvidenceError, match="tool hashes"):
        status.validate_evidence(
            output,
            expected_release_sha=RELEASE,
            expected_deployment_id=DEPLOYMENT,
            expected_account_id=ACCOUNT_ID,
            expected_display_name=DISPLAY_NAME,
            now=now,
            enforce_fixed_path=False,
        )


def test_rejects_stale_status_and_account_mismatch(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    output = capture(tmp_path, now)
    with pytest.raises(status.EvidenceError, match="stale"):
        status.validate_evidence(
            output,
            expected_release_sha=RELEASE,
            expected_deployment_id=DEPLOYMENT,
            expected_account_id=ACCOUNT_ID,
            expected_display_name=DISPLAY_NAME,
            now=now + timedelta(minutes=16),
            enforce_fixed_path=False,
        )
    with pytest.raises(status.EvidenceError, match="identity mismatch"):
        status.validate_evidence(
            output,
            expected_release_sha=RELEASE,
            expected_deployment_id=DEPLOYMENT,
            expected_account_id="acct_0000000000000000",
            expected_display_name=DISPLAY_NAME,
            now=now,
            enforce_fixed_path=False,
        )
