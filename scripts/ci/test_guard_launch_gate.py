import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import guard_launch_gate as gate  # noqa: E402


IDENTITY = {
    "guard_release": "tinyzkp-guard-v1",
    "guard_version": "1.0.0",
    "guard_source_sha": "a" * 40,
    "engine_source_sha": "b" * 40,
    "compatibility_profile": gate.PROFILE_ID,
}
ISSUED_AT = "2026-07-17T12:00:00Z"
EXPIRES_AT = "2026-07-20T12:00:00Z"
EVALUATED_AT = "2026-07-18T12:00:00Z"
NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)
SIGNER_ID = "test-reviewer"
WORKFLOW_SOURCE_SHA = "1" * 40
COSIGN = Path("/opt/tinyzkp-test/cosign")
CURRENT_SIGNED_IDENTITY = (
    f"tinyzkp-guard/{IDENTITY['guard_version']}"
    f"+guard.{IDENTITY['guard_source_sha']}"
    f".engine.{IDENTITY['engine_source_sha']}"
    f".artifact.{'c' * 64}"
)
CURRENT_RELEASE_BASE = (
    "https://github.com/logannye/hc-stark/releases/download/"
    f"guard-v{IDENTITY['guard_version']}"
)
INDEX_RAW = gate.canonical_bytes(
    {
        "schema_version": 1,
        "product": "tinyzkp-guard",
        "current_release_identity": CURRENT_SIGNED_IDENTITY,
        "releases": [
            {
                "guard_version": IDENTITY["guard_version"],
                "release_identity": CURRENT_SIGNED_IDENTITY,
                "compatibility_profile": gate.PROFILE_ID,
                "release_date": "2026-07-18",
                "channel_url": f"{CURRENT_RELEASE_BASE}/guard-channel-v1.json",
                "channel_sha256": "e" * 64,
                "artifacts": [
                    {
                        "name": "tinyzkp-guard-1.0.0-linux-x86_64.tar.gz",
                        "url": (
                            f"{CURRENT_RELEASE_BASE}/"
                            "tinyzkp-guard-1.0.0-linux-x86_64.tar.gz"
                        ),
                        "sha256": "c" * 64,
                    }
                ],
                "state": "current",
                "successor_release_identity": None,
                "advisory_url": None,
            }
        ],
    }
)
INDEX_SIGNATURE_RAW = b"test-guard-release-index-signature\n"
INDEX_SHA256 = hashlib.sha256(INDEX_RAW).hexdigest()
INDEX_SIGNATURE_SHA256 = hashlib.sha256(INDEX_SIGNATURE_RAW).hexdigest()
MERCHANT_ID_FIELDS = (
    "store_id",
    "product_id",
    "monthly_variant_id",
    "annual_variant_id",
)
TEST_CONFIG = {
    "store_id": "101",
    "product_id": "201",
    "monthly_variant_id": "301",
    "annual_variant_id": "302",
    "monthly_checkout_url": (
        "https://lnholdings.lemonsqueezy.com/checkout/buy/monthly-test?"
        "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-18&"
        "checkout%5Bcustom%5D%5Bguard_version%5D=1.0.0"
    ),
    "annual_checkout_url": (
        "https://lnholdings.lemonsqueezy.com/checkout/buy/annual-test?"
        "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-18&"
        "checkout%5Bcustom%5D%5Bguard_version%5D=1.0.0"
    ),
    "portal_url": "https://lnholdings.lemonsqueezy.com/billing",
}
LIVE_CONFIG = {
    "store_id": "102",
    "product_id": "202",
    "monthly_variant_id": "401",
    "annual_variant_id": "402",
    "monthly_checkout_url": (
        "https://lnholdings.lemonsqueezy.com/checkout/buy/monthly-live?"
        "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-18&"
        "checkout%5Bcustom%5D%5Bguard_version%5D=1.0.0"
    ),
    "annual_checkout_url": (
        "https://lnholdings.lemonsqueezy.com/checkout/buy/annual-live?"
        "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-18&"
        "checkout%5Bcustom%5D%5Bguard_version%5D=1.0.0"
    ),
    "portal_url": "https://lnholdings.lemonsqueezy.com/billing",
}

CLAIMS = {
    "engine_release_ready": {
        "backend_gate_status": "qualified",
        "engine_release_tag": "backend-v1.0.0",
        "official_verifier_acceptance": True,
        "proof_byte_equality": True,
        "resource_1m_target": True,
        "resource_16m_target": True,
        "fixed_host_matrix": True,
        "durable_recovery_matrix": True,
        "enospc_recovery": True,
        "fuzzing": True,
        "cli_smoke": True,
        "oci_smoke": True,
        "signed_artifacts": True,
        "checksums": True,
        "sbom": True,
        "provenance": True,
        "immutable_source_identity": True,
        "artifact_identity_bound": True,
        "engine_artifact_sha256": "1" * 64,
        "engine_oci_digest": "sha256:" + "2" * 64,
    },
    "guard_release_ready": {
        "guard_channel_status": "qualified",
        "supervisor_protocol": True,
        "stdout_stderr_framing": True,
        "release_identity_enforcement": True,
        "signal_supervision": True,
        "orphan_prevention": True,
        "atomic_state": True,
        "canonical_doctor_plan_consumption": True,
        "diagnostics_redaction": True,
        "exact_release_checkpoint_lifecycle": True,
        "side_by_side_old_release_resume": True,
        "release_scoped_activation": True,
        "activated_release_offline": True,
        "cancelled_release_offline": True,
        "non_root_oci": True,
        "read_only_root": True,
        "network_none_after_activation": True,
        "ci_policy_operations": True,
        "signed_static_channel": True,
        "signed_release_index": True,
        "package_identity_parity": True,
        "artifact_identity_bound": True,
        "artifact_published": False,
        "artifact_url": (
            f"{CURRENT_RELEASE_BASE}/tinyzkp-guard-1.0.0-linux-x86_64.tar.gz"
        ),
        "artifact_sha256": "c" * 64,
        "oci_digest": "sha256:" + "d" * 64,
        "channel_url": f"{CURRENT_RELEASE_BASE}/guard-channel-v1.json",
        "channel_identity_sha256": "e" * 64,
        "release_index_url": f"{CURRENT_RELEASE_BASE}/guard-release-index-v1.json",
        "release_index_sha256": INDEX_SHA256,
        "release_index_signature_url": (
            f"{CURRENT_RELEASE_BASE}/guard-release-index-v1.json.sig"
        ),
        "release_index_signature_sha256": INDEX_SIGNATURE_SHA256,
        "channel_release_identity": CURRENT_SIGNED_IDENTITY,
        "channel_guard_version": IDENTITY["guard_version"],
        "channel_guard_source_sha": IDENTITY["guard_source_sha"],
        "channel_engine_source_sha": IDENTITY["engine_source_sha"],
        "channel_release_change_class": "proof_critical",
        "channel_prior_qualified_release_identity": None,
        "channel_prior_release_index_sha256": None,
        "public_candidate_authorization_commit": "f" * 40,
        "channel_compatibility_profile": IDENTITY["compatibility_profile"],
        "channel_artifact_sha256": "c" * 64,
        "channel_oci_digest": "sha256:" + "d" * 64,
        "embedded_merchant_mode": "live",
        "embedded_store_id": LIVE_CONFIG["store_id"],
        "embedded_product_id": LIVE_CONFIG["product_id"],
        "embedded_monthly_variant_id": LIVE_CONFIG["monthly_variant_id"],
        "embedded_annual_variant_id": LIVE_CONFIG["annual_variant_id"],
        "embedded_catalog_policy": copy.deepcopy(gate.MERCHANT_CATALOG_POLICY),
        "embedded_release_date": "2026-07-18",
        "embedded_eula_sha256": "8" * 64,
        "embedded_notices_sha256": "9" * 64,
    },
    "three_external_workloads": {
        "organizations": 3,
        "workloads": 3,
        "customer_specific_branches": 0,
        "max_assistance_minutes": 240,
        "max_workloads_per_organization": 1,
        "public_adapter": True,
        "public_job_contract": True,
        "witness_data_transferred": False,
        "organizations_with_real_failure_problem": 3,
        "minimum_documented_failure_cost_usd": 6000,
        "written_annual_price_acceptances": 2,
    },
    "two_standard_annual_customers": {
        "ordinary_paid_annual_subscriptions": 2,
        "annual_price_usd": 4990,
        "ordinary_checkout": True,
        "cadence": "annual",
        "catalog_policy": copy.deepcopy(gate.MERCHANT_CATALOG_POLICY),
        **{key: LIVE_CONFIG[key] for key in MERCHANT_ID_FIELDS},
    },
    "five_unaided_installs": {
        "clean_machines": 5,
        "verified_under_60_minutes": 4,
        "median_minutes": 29,
        "ordinary_purchase": True,
        "license_received": True,
        "artifact_downloaded": True,
        "artifact_signature_verified": True,
        "release_activated": True,
        "proof_produced": True,
        "official_verifier_accepted": True,
        "interruption_resumed": True,
        "ci_policy_passed": True,
        "portal_cancelled": True,
    },
    "legal_terms_approved": {
        "seller_confirmed": True,
        "owner_approved": True,
        "eula": True,
        "third_party_notices": True,
        "privacy": True,
        "terms": True,
        "refunds": True,
        "release_date": "2026-07-18",
        "eula_sha256": "8" * 64,
        "notices_sha256": "9" * 64,
        "terms_sha256": "6" * 64,
        "privacy_sha256": "7" * 64,
        "refunds_sha256": "5" * 64,
    },
    "merchant_sandbox_lifecycle_passed": {
        "monthly": True,
        "annual": True,
        "decline": True,
        "renewal": True,
        "dunning": True,
        "portal": True,
        "cancellation": True,
        "resumption": True,
        "refund": True,
        "expiry": True,
        "receipt_delivered": True,
        "license_key_delivered": True,
        "terms_presented_before_payment": True,
        "terms_acceptance_required": True,
        "receipt_legal_binding_verified": True,
        "receipt_download_url": gate.RECEIPT_DOWNLOAD_URL,
        "eula_url": gate._eula_url("8" * 64),
        "eula_sha256": "8" * 64,
        "terms_version": "2026-07-18",
        "mode": "test",
        "catalog_policy": copy.deepcopy(gate.MERCHANT_CATALOG_POLICY),
        **TEST_CONFIG,
        "store_hostname": "lnholdings.lemonsqueezy.com",
    },
    "merchant_live_owner_smoke_passed": {
        "monthly_variant_active": True,
        "annual_variant_active": True,
        "monthly_price_rendered": True,
        "annual_price_rendered": True,
        "checkout_rendered": True,
        "portal_configured": True,
        "license_keys_enabled": True,
        "receipt_delivery_configured": True,
        "license_key_delivery_configured": True,
        "terms_presented_before_payment": True,
        "terms_acceptance_required": True,
        "receipt_legal_binding_configured": True,
        "support_mailbox_configured": True,
        "support_delivery_verified": True,
        "support_owner_access_verified": True,
        "support_retention_configured": True,
        "support_intake_private": True,
        "support_contact": "support@tinyzkp.com",
        "receipt_download_url": gate.RECEIPT_DOWNLOAD_URL,
        "eula_url": gate._eula_url("8" * 64),
        "eula_sha256": "8" * 64,
        "terms_version": "2026-07-18",
        "mode": "live",
        "catalog_policy": copy.deepcopy(gate.MERCHANT_CATALOG_POLICY),
        **LIVE_CONFIG,
        "store_hostname": "lnholdings.lemonsqueezy.com",
    },
    "legacy_obligations_resolved": {
        "identified_free_tenant_accounts": 10,
        "external_free_tenant_accounts": 0,
        "synthetic_test_tenant_accounts": 10,
        "accounts_with_api_usage": 2,
        "external_api_usage_accounts": 0,
        "synthetic_api_usage_accounts": 2,
        "external_accounts_with_billed_usage": 0,
        "owner_only_legacy_tinyzkp_subscriptions_identified": 2,
        "owner_only_legacy_tinyzkp_subscriptions_resolved": 2,
        "owner_only_legacy_tinyzkp_price_usd": 19,
        "owner_only_legacy_catalog_objects_disabled": True,
        "unrelated_stripe_catalog_objects_untouched": True,
        "synthetic_test_data_disposition_documented": True,
        "retirement_notices_required": 0,
        "retirement_notices_sent": 0,
        "external_api_usage_exports_resolved": 0,
        "open_export_requests": 0,
        "open_refund_or_credit_obligations": 0,
        "customer_artifacts_pending_disposition": 0,
        "unresolved_obligations": 0,
        "statutory_records_retained": True,
        "retained_record_disposition_documented": True,
        "retirement_notice_template_sha256": "4" * 64,
    },
    "hosted_infrastructure_decommissioned": {
        "production_servers": 0,
        "databases": 0,
        "queues": 0,
        "workers": 0,
        "pagers": 0,
        "monitoring_services": 0,
        "alerting_services": 0,
        "backup_jobs": 0,
        "unused_r2_buckets": 0,
        "customer_artifacts_pending_deletion": 0,
        "active_oauth_apps": 0,
        "active_legacy_credentials": 0,
        "retired_hosts": [
            "api.tinyzkp.com",
            "mcp.tinyzkp.com",
            "webhook.tinyzkp.com",
        ],
        "retired_hosts_return_410": True,
        "writes_disabled": True,
        "jobs_disabled": True,
        "credentials_revoked": True,
        "records_retained": True,
        "observation_period_days_planned": 90,
    },
    "release_rehearsal_within_budget": {
        "qualification_completed": True,
        "build_validation_passed": True,
        "deployment_rehearsed": True,
        "rollback_rehearsed": True,
        "release_artifact_identity_verified": True,
        "change_class": "proof_critical",
    },
}


def successful_cosign(*args, **kwargs):
    return subprocess.CompletedProcess(args[0], 0, stdout="verified", stderr="")


def blocked_source() -> dict:
    return gate.load_json(gate.DEFAULT_SOURCE, "source")


def write_trust(root: Path, source: dict) -> None:
    trust = {
        "schema_version": 1,
        "document_type": "GuardLaunchTrustV1",
        "signers": [
            {
                "id": SIGNER_ID,
                "purposes": sorted(gate.GATE_PURPOSES.values()),
                "certificate_identity_regexp": "^https://reviewer.example/identity$",
                "oidc_issuer": "https://issuer.example",
            },
            {
                "id": "tinyzkp-artifact-publication-main",
                "purposes": [gate.ARTIFACT_PUBLICATION_PURPOSE],
                "certificate_identity_regexp": "^https://publisher.example/identity$",
                "oidc_issuer": "https://issuer.example",
            },
            {
                "id": gate.SALES_FREEZE_SIGNER_ID,
                "purposes": [gate.SALES_FREEZE_PURPOSE],
                "certificate_identity_regexp": "^https://freezer.example/identity$",
                "oidc_issuer": "https://issuer.example",
            },
        ],
    }
    raw = gate.canonical_bytes(trust)
    path = root / "release" / "guard-launch-trust-v1.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    source["trust_policy"] = {
        "path": "release/guard-launch-trust-v1.json",
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def write_signing_trust(root: Path, *, configured: bool = True) -> str:
    key_raw = (
        b"-----BEGIN PUBLIC KEY-----\n"
        b"dGlueXprcC10ZXN0LXB1YmxpYy1rZXk=\n"
        b"-----END PUBLIC KEY-----\n"
    )
    key_digest = hashlib.sha256(key_raw).hexdigest()
    if configured:
        key_path = root / gate.SIGNING_PUBLIC_KEY_PATH
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key_raw)
    trust = {
        "schema_version": 1,
        "document_type": "GuardSigningTrustV1",
        "status": "configured" if configured else "unconfigured",
        "public_key_path": gate.SIGNING_PUBLIC_KEY_PATH,
        "public_key_sha256": key_digest if configured else None,
    }
    raw = gate.canonical_bytes(trust)
    path = root / gate.SIGNING_TRUST_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def qualified_source(root: Path) -> dict:
    source = blocked_source()
    source["evaluated_at"] = EVALUATED_AT
    source["release_identity"] = copy.deepcopy(IDENTITY)
    source["requested_commerce_state"] = "public_live"
    source["merchant"] = {
        "provider": "lemon_squeezy",
        "approval_status": "approved",
        "portal_state": "live",
        "portal_url": "https://lnholdings.lemonsqueezy.com/billing",
        "catalog_policy": copy.deepcopy(gate.MERCHANT_CATALOG_POLICY),
        "test_configuration": copy.deepcopy(TEST_CONFIG),
        "live_configuration": copy.deepcopy(LIVE_CONFIG),
    }
    legal_dir = root / "legal"
    site_dir = root / "site"
    legal_dir.mkdir(parents=True, exist_ok=True)
    site_dir.mkdir(parents=True, exist_ok=True)
    (legal_dir / "EULA.txt").write_text(
        "TinyZKP Guard test EULA — final fixture bytes.\n"
        "Effective Date: 2026-07-18\n",
        encoding="utf-8",
    )
    (legal_dir / "THIRD-PARTY-NOTICES.txt").write_text(
        "TinyZKP Guard test third-party notices — final fixture bytes.\n",
        encoding="utf-8",
    )
    for name in ("terms", "privacy", "refunds"):
        document = site_dir / f"{name}.html"
        if not document.exists():
            document.write_text(
                f"<!doctype html><html><body><p>{name} fixture</p></body></html>\n",
                encoding="utf-8",
            )
    legal_hashes = {
        field: gate._legal_document_sha256(root, field)
        for field in gate.LEGAL_DOCUMENT_PATHS
    }
    source["legal"] = {
        "seller_status": "confirmed",
        "owner_approval_status": "approved",
        "release_date": "2026-07-18",
        **legal_hashes,
    }
    write_trust(root, source)
    write_signing_trust(root)
    evidence_dir = root / "release" / "evidence" / "guard-launch-v2"
    evidence_dir.mkdir(parents=True)
    for gate_name in gate.REQUIRED_GATES:
        kind, _max_age = gate.GATE_POLICIES[gate_name]
        claims = copy.deepcopy(CLAIMS[gate_name])
        if gate_name == "legal_terms_approved":
            claims.update(legal_hashes)
        elif gate_name == "legacy_obligations_resolved":
            notice_path = root / gate.LEGACY_RETIREMENT_NOTICE_PATH
            notice_path.parent.mkdir(parents=True, exist_ok=True)
            if not notice_path.exists():
                notice_path.write_text(
                    "Fixture legacy retirement notice.\n", encoding="utf-8"
                )
            claims["retirement_notice_template_sha256"] = hashlib.sha256(
                notice_path.read_bytes()
            ).hexdigest()
        elif gate_name == "guard_release_ready":
            claims.update(
                {
                    "embedded_eula_sha256": legal_hashes["eula_sha256"],
                    "embedded_notices_sha256": legal_hashes["notices_sha256"],
                }
            )
        elif gate_name in {
            "merchant_sandbox_lifecycle_passed",
            "merchant_live_owner_smoke_passed",
        }:
            claims.update(
                {
                    "receipt_download_url": gate.RECEIPT_DOWNLOAD_URL,
                    "eula_url": gate._eula_url(legal_hashes["eula_sha256"]),
                    "eula_sha256": legal_hashes["eula_sha256"],
                    "terms_version": source["legal"]["release_date"],
                }
            )
        envelope = {
            "schema_version": 1,
            "document_type": "GuardGateEvidenceV1",
            "authorization_policy": gate.AUTHORIZATION_POLICY,
            "qualification_basis": gate.QUALIFICATION_BASIS,
            "evidence_kind": kind,
            "gate": gate_name,
            "result": "passed",
            "issued_at": ISSUED_AT,
            "expires_at": EXPIRES_AT,
            "workflow_source_sha": WORKFLOW_SOURCE_SHA,
            "release_identity": copy.deepcopy(IDENTITY),
            "claims": claims,
        }
        raw = gate.canonical_bytes(envelope)
        relative = f"release/evidence/guard-launch-v2/{gate_name}.json"
        (root / relative).write_bytes(raw)
        signature_relative = (
            f"release/evidence/guard-launch-v2/{gate_name}.sigstore.json"
        )
        signature_raw = gate.canonical_bytes(
            {"test_bundle_for_claim_sha256": hashlib.sha256(raw).hexdigest()}
        )
        (root / signature_relative).write_bytes(signature_raw)
        source["gates"][gate_name] = {
            "status": "passed",
            "reason_code": None,
            "evidence": [
                {
                    "path": relative,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "signature_path": signature_relative,
                    "signature_sha256": hashlib.sha256(signature_raw).hexdigest(),
                    "signer_id": SIGNER_ID,
                    "purpose": gate.GATE_PURPOSES[gate_name],
                }
            ],
        }
    stable_index = root / "site" / gate.RELEASE_INDEX_NAME
    stable_signature = root / "site" / gate.RELEASE_INDEX_SIGNATURE_NAME
    revision_root = root / "site" / "release-index-revisions" / INDEX_SHA256
    revision_root.mkdir(parents=True, exist_ok=True)
    stable_index.parent.mkdir(parents=True, exist_ok=True)
    stable_index.write_bytes(INDEX_RAW)
    stable_signature.write_bytes(INDEX_SIGNATURE_RAW)
    (revision_root / gate.RELEASE_INDEX_NAME).write_bytes(INDEX_RAW)
    (revision_root / gate.RELEASE_INDEX_SIGNATURE_NAME).write_bytes(
        INDEX_SIGNATURE_RAW
    )
    publication = {
        "schema_version": 1,
        "document_type": "GuardArtifactPublicationV1",
        "authorization_policy": gate.AUTHORIZATION_POLICY,
        "qualification_basis": gate.QUALIFICATION_BASIS,
        "signer_id": "tinyzkp-artifact-publication-main",
        "purpose": gate.ARTIFACT_PUBLICATION_PURPOSE,
        "publication_kind": "initial_ga",
        "promotion_repository": "logannye/hc-stark",
        "promotion_workflow": ".github/workflows/promote-guard-release.yml",
        "promotion_run_id": "123456789",
        "promotion_run_attempt": 1,
        "promotion_source_sha": "1" * 40,
        "workflow_source_sha": WORKFLOW_SOURCE_SHA,
        "prior_release_index_sha256": None,
        "published_at": EVALUATED_AT,
        "release_identity": copy.deepcopy(IDENTITY),
        "guard_release_tag": f"guard-v{IDENTITY['guard_version']}",
        "artifact_url": CLAIMS["guard_release_ready"]["artifact_url"],
        "artifact_sha256": CLAIMS["guard_release_ready"]["artifact_sha256"],
        "channel_url": CLAIMS["guard_release_ready"]["channel_url"],
        "channel_sha256": CLAIMS["guard_release_ready"][
            "channel_identity_sha256"
        ],
        "release_index_url": CLAIMS["guard_release_ready"]["release_index_url"],
        "release_index_sha256": INDEX_SHA256,
        "release_index_signature_url": CLAIMS["guard_release_ready"][
            "release_index_signature_url"
        ],
        "release_index_signature_sha256": INDEX_SIGNATURE_SHA256,
        "guard_oci_reference": (
            "ghcr.io/logannye/tinyzkp-guard@"
            + CLAIMS["guard_release_ready"]["oci_digest"]
        ),
        "guard_oci_digest": CLAIMS["guard_release_ready"]["oci_digest"],
        "engine_oci_reference": (
            "ghcr.io/logannye/tinyzkp-engine@"
            + CLAIMS["engine_release_ready"]["engine_oci_digest"]
        ),
        "engine_oci_digest": CLAIMS["engine_release_ready"][
            "engine_oci_digest"
        ],
        "anonymous_checks": {
            "github_release_artifact": True,
            "github_release_channel": True,
            "github_release_index": True,
            "guard_oci_manifest": True,
            "engine_oci_manifest": True,
        },
    }
    publication_raw = gate.canonical_bytes(publication)
    (root / "site" / gate.ARTIFACT_PUBLICATION_NAME).write_bytes(publication_raw)
    (root / "site" / gate.ARTIFACT_PUBLICATION_BUNDLE_NAME).write_bytes(
        gate.canonical_bytes(
            {"test_bundle_for_claim_sha256": hashlib.sha256(publication_raw).hexdigest()}
        )
    )
    publication_sha = hashlib.sha256(publication_raw).hexdigest()
    immutable_publication = root / "site/artifact-publications" / publication_sha
    immutable_publication.mkdir(parents=True)
    (immutable_publication / gate.ARTIFACT_PUBLICATION_NAME).write_bytes(
        publication_raw
    )
    (immutable_publication / gate.ARTIFACT_PUBLICATION_BUNDLE_NAME).write_bytes(
        (root / "site" / gate.ARTIFACT_PUBLICATION_BUNDLE_NAME).read_bytes()
    )
    return source


def remove_published_index(root: Path) -> None:
    for name in (
        gate.RELEASE_INDEX_NAME,
        gate.RELEASE_INDEX_SIGNATURE_NAME,
        gate.RELEASE_INDEX_HANDOFF_NAME,
        gate.ARTIFACT_PUBLICATION_NAME,
        gate.ARTIFACT_PUBLICATION_BUNDLE_NAME,
    ):
        path = root / "site" / name
        if path.exists() or path.is_symlink():
            path.unlink()
    shutil.rmtree(root / "site" / "release-index-revisions", ignore_errors=True)
    shutil.rmtree(root / "site" / "artifact-publications", ignore_errors=True)


def rewrite_publication(
    root: Path,
    *,
    publication_kind: str,
    prior_index_sha256: str | None,
    release_index_sha256: str | None = None,
) -> None:
    record_path = root / "site" / gate.ARTIFACT_PUBLICATION_NAME
    bundle_path = root / "site" / gate.ARTIFACT_PUBLICATION_BUNDLE_NAME
    record = gate.load_json(record_path, "publication")
    record["publication_kind"] = publication_kind
    record["prior_release_index_sha256"] = prior_index_sha256
    if release_index_sha256 is not None:
        record["release_index_sha256"] = release_index_sha256
    raw = gate.canonical_bytes(record)
    bundle = gate.canonical_bytes(
        {"test_bundle_for_claim_sha256": hashlib.sha256(raw).hexdigest()}
    )
    record_path.write_bytes(raw)
    bundle_path.write_bytes(bundle)
    immutable = root / "site/artifact-publications" / hashlib.sha256(raw).hexdigest()
    immutable.mkdir(parents=True)
    (immutable / gate.ARTIFACT_PUBLICATION_NAME).write_bytes(raw)
    (immutable / gate.ARTIFACT_PUBLICATION_BUNDLE_NAME).write_bytes(bundle)


def write_prior_release_evidence(
    root: Path,
    source: dict,
    prior_identity: dict,
    *,
    prior_index_sha256: str = "d" * 64,
) -> None:
    gate_name = gate.PRIOR_QUALIFIED_RELEASE_GATE
    kind, _max_age = gate.GATE_POLICIES[gate_name]
    claims = {
        "prior_launch_state": "qualified",
        "prior_commerce_state": "public_live",
        "prior_artifact_published": True,
        "prior_release_identity": copy.deepcopy(prior_identity),
        "prior_qualified_release_identity": gate._expected_guard_release_identity(
            prior_identity, "e" * 64
        ),
        "prior_engine_artifact_sha256": "e" * 64,
        "prior_release_tag": f"guard-v{prior_identity['guard_version']}",
        "prior_qualified_at": "2026-01-01T12:00:00Z",
        "prior_launch_evidence_sha256": "a" * 64,
        "prior_guard_channel_sha256": "b" * 64,
        "prior_guard_artifact_sha256": "c" * 64,
        "prior_release_index_sha256": prior_index_sha256,
        "prior_channel_url": (
            "https://github.com/example/tinyzkp/releases/download/"
            f"guard-v{prior_identity['guard_version']}/guard-channel-v1.json"
        ),
    }
    envelope = {
        "schema_version": 1,
        "document_type": "GuardGateEvidenceV1",
        "authorization_policy": gate.AUTHORIZATION_POLICY,
        "qualification_basis": gate.QUALIFICATION_BASIS,
        "evidence_kind": kind,
        "gate": gate_name,
        "result": "passed",
        "issued_at": ISSUED_AT,
        "expires_at": "2027-07-17T12:00:00Z",
        "workflow_source_sha": WORKFLOW_SOURCE_SHA,
        "release_identity": copy.deepcopy(IDENTITY),
        "claims": claims,
    }
    raw = gate.canonical_bytes(envelope)
    relative = f"release/evidence/guard-launch-v2/{gate_name}.json"
    (root / relative).write_bytes(raw)
    signature_relative = (
        f"release/evidence/guard-launch-v2/{gate_name}.sigstore.json"
    )
    signature_raw = gate.canonical_bytes(
        {"test_bundle_for_claim_sha256": hashlib.sha256(raw).hexdigest()}
    )
    (root / signature_relative).write_bytes(signature_raw)
    source["prior_qualified_release"] = {
        "status": "passed",
        "reason_code": None,
        "evidence": [
            {
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "signature_path": signature_relative,
                "signature_sha256": hashlib.sha256(signature_raw).hexdigest(),
                "signer_id": SIGNER_ID,
                "purpose": gate.GATE_PURPOSES[gate_name],
            }
        ],
    }


def install_successor_index(root: Path, prior_identity: dict) -> tuple[str, str]:
    prior_signed_identity = gate._expected_guard_release_identity(
        prior_identity, "e" * 64
    )
    prior_base = (
        "https://github.com/logannye/hc-stark/releases/download/"
        f"guard-v{prior_identity['guard_version']}"
    )
    prior_entry = {
        "guard_version": prior_identity["guard_version"],
        "release_identity": prior_signed_identity,
        "compatibility_profile": gate.PROFILE_ID,
        "release_date": "2026-01-01",
        "channel_url": f"{prior_base}/guard-channel-v1.json",
        "channel_sha256": "b" * 64,
        "artifacts": [
            {
                "name": "tinyzkp-guard-0.9.0-linux-x86_64.tar.gz",
                "url": f"{prior_base}/tinyzkp-guard-0.9.0-linux-x86_64.tar.gz",
                "sha256": "c" * 64,
            }
        ],
        "state": "current",
        "successor_release_identity": None,
        "advisory_url": None,
    }
    prior_index = {
        "schema_version": 1,
        "product": "tinyzkp-guard",
        "current_release_identity": prior_signed_identity,
        "releases": [prior_entry],
    }
    prior_raw = gate.canonical_bytes(prior_index)
    prior_sha = hashlib.sha256(prior_raw).hexdigest()
    current_index = json.loads(INDEX_RAW)
    revised_index = {
        **current_index,
        "releases": [
            {
                **prior_entry,
                "state": "superseded",
                "successor_release_identity": CURRENT_SIGNED_IDENTITY,
            },
            current_index["releases"][0],
        ],
    }
    revised_raw = gate.canonical_bytes(revised_index)
    revised_sha = hashlib.sha256(revised_raw).hexdigest()
    site = root / "site"
    (site / gate.RELEASE_INDEX_NAME).write_bytes(revised_raw)
    revision_root = site / "release-index-revisions"
    for index_sha, index_raw in (
        (prior_sha, prior_raw),
        (revised_sha, revised_raw),
    ):
        revision = revision_root / index_sha
        revision.mkdir(parents=True, exist_ok=True)
        (revision / gate.RELEASE_INDEX_NAME).write_bytes(index_raw)
        (revision / gate.RELEASE_INDEX_SIGNATURE_NAME).write_bytes(
            INDEX_SIGNATURE_RAW
        )
    return prior_sha, revised_sha


def engine_only_source(root: Path) -> dict:
    source = qualified_source(root)
    remove_published_index(root)
    blocked = blocked_source()
    for gate_name in gate.REQUIRED_GATES - {"engine_release_ready"}:
        source["gates"][gate_name] = copy.deepcopy(blocked["gates"][gate_name])
    source["requested_commerce_state"] = "unconfigured"
    source["merchant"] = copy.deepcopy(blocked["merchant"])
    source["legal"] = copy.deepcopy(blocked["legal"])
    return source


def derive_qualified(source: dict, root: Path):
    signing_policy_sha256 = hashlib.sha256(
        (root / gate.SIGNING_TRUST_PATH).read_bytes()
    ).hexdigest()
    return gate.derive(
        source,
        root=root,
        signature_runner=successful_cosign,
        cosign_path=COSIGN,
        trusted_policy_sha256=source["trust_policy"]["sha256"],
        trusted_signing_policy_sha256=signing_policy_sha256,
    )


def attach_signed_sales_freeze(root: Path, source: dict) -> dict:
    prior_source_sha256 = gate.sha256_bytes(gate.canonical_bytes(source))
    envelope = {
        "schema_version": 1,
        "document_type": "GuardSalesFreezeEvidenceV1",
        "authorization_policy": gate.AUTHORIZATION_POLICY,
        "qualification_basis": gate.QUALIFICATION_BASIS,
        "signer_id": gate.SALES_FREEZE_SIGNER_ID,
        "purpose": gate.SALES_FREEZE_PURPOSE,
        "issued_at": EVALUATED_AT,
        "workflow_source_sha": WORKFLOW_SOURCE_SHA,
        "prior_source_sha256": prior_source_sha256,
        "release_identity": copy.deepcopy(source["release_identity"]),
        "prior_commerce_state": "public_live",
        "requested_commerce_state": "sales_frozen",
        "checkout_enabled": False,
        "preserve_customer_portal": True,
        "preserve_published_artifacts": True,
        "reason": "owner_emergency_sales_freeze",
    }
    evidence_path = root / "release/evidence/guard-launch-v2/sales-freeze.json"
    bundle_path = evidence_path.with_name("sales-freeze.sigstore.json")
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_raw = gate.canonical_bytes(envelope)
    bundle_raw = gate.canonical_bytes(
        {"test_bundle_for_claim_sha256": hashlib.sha256(evidence_raw).hexdigest()}
    )
    evidence_path.write_bytes(evidence_raw)
    bundle_path.write_bytes(bundle_raw)
    source["requested_commerce_state"] = "sales_frozen"
    source["sales_freeze"] = {
        "status": "passed",
        "reason_code": None,
        "evidence": [
            {
                "path": evidence_path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(evidence_raw).hexdigest(),
                "signature_path": bundle_path.relative_to(root).as_posix(),
                "signature_sha256": hashlib.sha256(bundle_raw).hexdigest(),
                "signer_id": gate.SALES_FREEZE_SIGNER_ID,
                "purpose": gate.SALES_FREEZE_PURPOSE,
            }
        ],
    }
    return source


def mutate_claim(root: Path, source: dict, gate_name: str, mutator) -> None:
    reference = source["gates"][gate_name]["evidence"][0]
    path = root / reference["path"]
    envelope = json.loads(path.read_text())
    mutator(envelope)
    raw = gate.canonical_bytes(envelope)
    path.write_bytes(raw)
    reference["sha256"] = hashlib.sha256(raw).hexdigest()


def guard_package_source(root: Path) -> dict:
    source = qualified_source(root)
    source["release_change_class"] = "guard_package_only"
    prior_identity = {
        **IDENTITY,
        "guard_version": "0.9.0",
        "guard_source_sha": "7" * 40,
    }
    prior_index_sha, successor_index_sha = install_successor_index(
        root, prior_identity
    )
    write_prior_release_evidence(
        root,
        source,
        prior_identity,
        prior_index_sha256=prior_index_sha,
    )
    rewrite_publication(
        root,
        publication_kind="successor_ga",
        prior_index_sha256=prior_index_sha,
        release_index_sha256=successor_index_sha,
    )
    mutate_claim(
        root,
        source,
        "guard_release_ready",
        lambda envelope: envelope["claims"].update(
            {
                "channel_release_change_class": "guard_package_only",
                "channel_prior_qualified_release_identity": (
                    gate._expected_guard_release_identity(
                        prior_identity, "e" * 64
                    )
                ),
                "channel_prior_release_index_sha256": prior_index_sha,
                "release_index_sha256": successor_index_sha,
            }
        ),
    )
    mutate_claim(
        root,
        source,
        "release_rehearsal_within_budget",
        lambda envelope: envelope["claims"].__setitem__(
            "change_class", "guard_package_only"
        ),
    )
    for gate_name in (
        gate.REQUIRED_GATES
        - gate.CHANGE_CLASS_FRESH_GATES["guard_package_only"]
    ):
        mutate_claim(
            root,
            source,
            gate_name,
            lambda envelope: envelope["release_identity"].update(
                {"guard_version": "0.9.0", "guard_source_sha": "7" * 40}
            ),
        )
    return source


def proof_successor_source(root: Path) -> tuple[dict, str]:
    source = qualified_source(root)
    prior_identity = {
        **IDENTITY,
        "guard_version": "0.9.0",
        "guard_source_sha": "7" * 40,
    }
    prior_index_sha, successor_index_sha = install_successor_index(
        root, prior_identity
    )
    write_prior_release_evidence(
        root,
        source,
        prior_identity,
        prior_index_sha256=prior_index_sha,
    )
    rewrite_publication(
        root,
        publication_kind="successor_ga",
        prior_index_sha256=prior_index_sha,
        release_index_sha256=successor_index_sha,
    )
    mutate_claim(
        root,
        source,
        "guard_release_ready",
        lambda envelope: envelope["claims"].update(
            {
                "channel_prior_qualified_release_identity": (
                    gate._expected_guard_release_identity(
                        prior_identity, "e" * 64
                    )
                ),
                "channel_prior_release_index_sha256": prior_index_sha,
                "release_index_sha256": successor_index_sha,
            }
        ),
    )
    return source, prior_index_sha


def site_legal_pricing_source(root: Path) -> dict:
    shutil.copytree(gate.ROOT / "site", root / "site")
    for relative in (
        ".github/workflows/deploy-site.yml",
        "scripts/deploy/cloudflare_pages_release.py",
        "docs/runbooks/cloudflare_pages_release.md",
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(gate.ROOT / relative, destination)
    source = qualified_source(root)
    source["release_change_class"] = "site_legal_pricing"
    write_prior_release_evidence(root, source, IDENTITY)
    site_legal_hashes = {
        field: gate.sha256_bytes(
            gate._normalized_site_file(root / "site" / f"{name}.html")
        )
        for field, name in (
            ("terms_sha256", "terms"),
            ("privacy_sha256", "privacy"),
            ("refunds_sha256", "refunds"),
        )
    }
    source["legal"].update(site_legal_hashes)
    mutate_claim(
        root,
        source,
        "legal_terms_approved",
        lambda envelope: envelope["claims"].update(site_legal_hashes),
    )
    rehearsal_hashes = {
        "site_bundle_sha256": gate._site_bundle_sha256(root),
        "deployment_plan_sha256": gate._reviewed_file_set_sha256(
            root,
            (
                ".github/workflows/deploy-site.yml",
                "scripts/deploy/cloudflare_pages_release.py",
                "docs/runbooks/cloudflare_pages_release.md",
            ),
            domain="tinyzkp-pages-deployment-v1",
        ),
        "rollback_plan_sha256": gate._reviewed_file_set_sha256(
            root,
            (
                "scripts/deploy/cloudflare_pages_release.py",
                "docs/runbooks/cloudflare_pages_release.md",
            ),
            domain="tinyzkp-pages-rollback-v1",
        ),
    }
    mutate_claim(
        root,
        source,
        "release_rehearsal_within_budget",
        lambda envelope: envelope["claims"].update(
            {
                "change_class": "site_legal_pricing",
                "site_contract_tests_passed": True,
                "site_accessibility_tests_passed": True,
                **rehearsal_hashes,
                "rollback_rehearsed": True,
            }
        ),
    )
    for gate_name in (
        gate.REQUIRED_GATES
        - gate.CHANGE_CLASS_FRESH_GATES["site_legal_pricing"]
        - gate.MUTABLE_FACT_FRESH_GATES
    ):
        mutate_claim(
            root,
            source,
            gate_name,
            lambda envelope: envelope.update(
                {
                    "issued_at": "2026-01-01T12:00:00Z",
                    "expires_at": "2026-12-31T12:00:00Z",
                }
            ),
        )
    return source


def test_repository_state_is_generated_from_independently_anchored_policy() -> None:
    source = gate.load_json(gate.DEFAULT_SOURCE, "source")
    signing_digest = hashlib.sha256(
        (gate.ROOT / gate.SIGNING_TRUST_PATH).read_bytes()
    ).hexdigest()
    derived = gate.derive(
        source,
        signature_runner=successful_cosign,
        cosign_path=COSIGN,
        trusted_policy_sha256=source["trust_policy"]["sha256"],
        trusted_signing_policy_sha256=signing_digest,
    )
    assert gate._check_outputs(derived) == []
    assert gate.validate(derived["launch"]) == []


def test_synthetic_all_blocked_state_is_fail_closed() -> None:
    source = gate.load_json(gate.DEFAULT_SOURCE, "source")
    source["release_identity"] = {
        "guard_release": "tinyzkp-guard-v1",
        "guard_version": None,
        "guard_source_sha": None,
        "engine_source_sha": None,
        "compatibility_profile": gate.PROFILE_ID,
    }
    source["release_change_class"] = "proof_critical"
    source["requested_commerce_state"] = "unconfigured"
    source["prior_qualified_release"] = {
        "status": "blocked",
        "reason_code": gate.BLOCKED_REASONS[gate.PRIOR_QUALIFIED_RELEASE_GATE],
        "evidence": [],
    }
    source["merchant"] = copy.deepcopy(
        gate.load_json(gate.DEFAULT_SOURCE, "source")["merchant"]
    )
    source["merchant"].update(
        {
            "approval_status": "pending",
            "portal_state": "unconfigured",
            "portal_url": None,
            "test_configuration": {
                key: None
                for key in (
                    "store_id",
                    "product_id",
                    "monthly_variant_id",
                    "annual_variant_id",
                    "monthly_checkout_url",
                    "annual_checkout_url",
                    "portal_url",
                )
            },
            "live_configuration": {
                key: None
                for key in (
                    "store_id",
                    "product_id",
                    "monthly_variant_id",
                    "annual_variant_id",
                    "monthly_checkout_url",
                    "annual_checkout_url",
                    "portal_url",
                )
            },
        }
    )
    source["legal"] = {
        "seller_status": "unconfirmed",
        "owner_approval_status": "not_approved",
        "release_date": None,
        "eula_sha256": None,
        "notices_sha256": None,
        "terms_sha256": None,
        "privacy_sha256": None,
        "refunds_sha256": None,
    }
    source["gates"] = {
        name: {
            "status": "blocked",
            "reason_code": gate.BLOCKED_REASONS[name],
            "evidence": [],
        }
        for name in gate.REQUIRED_GATES
    }
    derived = gate.derive(source)
    launch = derived["launch"]
    assert launch["launch_state"] == "blocked"
    assert launch["commerce_state"] == "unconfigured"
    assert launch["sales_state"] == "closed"
    assert launch["portal_state"] == "unconfigured"
    assert launch["checkout_enabled"] is False
    assert set(launch["blocking_gates"]) == gate.LAUNCH_BLOCKERS
    assert gate.validate(launch) == []


def test_generated_public_live_and_sales_frozen_surfaces_do_not_contradict_json(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    live = derive_qualified(source, tmp_path)
    assert live["launch"]["commerce_state"] == "public_live"
    assert live["offers"]["itemListElement"][1]["availability"].endswith(
        "/InStock"
    )
    sample = (
        '<a data-checkout="annual" data-closed-label="Not yet for sale" '
        'data-live-label="Buy Guard">Not yet for sale</a>'
    )
    assert ">Buy Guard</a>" in gate._checkout_html(
        sample, checkout_enabled=True
    )

    attach_signed_sales_freeze(tmp_path, source)
    frozen = derive_qualified(source, tmp_path)
    assert frozen["launch"]["sales_state"] == "frozen"
    assert frozen["launch"]["checkout_enabled"] is False
    assert frozen["offers"]["itemListElement"][1]["availability"].endswith(
        "/OutOfStock"
    )
    assert ">Not yet for sale</a>" in gate._checkout_html(
        sample, checkout_enabled=False
    )


def test_signed_evaluation_doctor_indexes_only_doctor_before_engine_gate() -> None:
    derived = gate.derive(blocked_source())
    derived["discovery"]["availability"][
        "signed_evaluation_doctor_binary"
    ] = True
    routes = gate._acquisition_routes(derived)
    assert routes["/doctor"] is True
    assert all(
        ready is False
        for route, ready in routes.items()
        if route != "/doctor"
    )
    sitemap = gate._sitemap_bytes(routes).decode("utf-8")
    assert "https://tinyzkp.com/doctor" in sitemap
    assert "https://tinyzkp.com/plonky3-out-of-memory" not in sitemap
    assert "<lastmod>" not in sitemap


def test_free_structured_offer_points_to_available_community_source() -> None:
    community = gate.derive(blocked_source())["offers"]["itemListElement"][0]
    assert community == {
        "@type": "Offer",
        "name": "TinyZKP Community source",
        "price": "0",
        "priceCurrency": "USD",
        "availability": "https://schema.org/InStock",
        "url": "https://github.com/logannye/hc-stark",
    }


def test_complete_signed_semantic_evidence_derives_public_live(tmp_path: Path) -> None:
    derived = derive_qualified(qualified_source(tmp_path), tmp_path)
    assert derived["launch"]["launch_state"] == "qualified"
    assert derived["launch"]["commerce_state"] == "public_live"
    assert derived["launch"]["sales_state"] == "live"
    assert derived["commerce"]["checkout_enabled"] is True
    assert derived["commerce"]["mode"] == "live"
    assert derived["release"]["guard_artifact_url"] == CLAIMS[
        "guard_release_ready"
    ]["artifact_url"]
    assert derived["release"]["channel_manifest"]["sha256"] == "e" * 64
    latest = derived["release"]["latest_release_index"]
    assert latest == derived["discovery"]["latest_release_index"]
    assert latest["url"] == "https://tinyzkp.com/guard-release-index-v1.json"
    assert latest["sha256"] == INDEX_SHA256
    assert latest["signature_sha256"] == INDEX_SIGNATURE_SHA256
    assert f"/release-index-revisions/{INDEX_SHA256}/" in latest[
        "immutable_revision_url"
    ]


def test_published_release_index_requires_exact_stable_and_revision_bytes(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    (tmp_path / "site" / gate.RELEASE_INDEX_NAME).write_bytes(b"changed\n")
    with pytest.raises(
        gate.GateError,
        match="revision_index is unavailable|index digest differs",
    ):
        derive_qualified(source, tmp_path)

    root = tmp_path / "missing-revision"
    source = qualified_source(root)
    (
        root
        / "site"
        / "release-index-revisions"
        / INDEX_SHA256
        / gate.RELEASE_INDEX_SIGNATURE_NAME
    ).unlink()
    with pytest.raises(gate.GateError, match="revision_signature is unavailable"):
        derive_qualified(source, root)


def test_blocked_launch_does_not_advertise_release_index() -> None:
    derived = gate.derive(blocked_source())
    assert derived["release"]["latest_release_index"] is None
    assert derived["discovery"]["latest_release_index"] is None


def test_qualified_write_removes_visible_prelaunch_contradictions(
    tmp_path: Path,
) -> None:
    shutil.copytree(gate.ROOT / "site", tmp_path / "site")
    source = qualified_source(tmp_path)
    derived = derive_qualified(source, tmp_path)
    gate._write_outputs(derived, root=tmp_path)
    assert gate._check_outputs(derived, root=tmp_path) == []
    rederived = derive_qualified(source, tmp_path)
    assert gate._check_outputs(rederived, root=tmp_path) == []

    forbidden = (
        "current status: blocked",
        "not yet for sale",
        "awaiting all launch gates",
        "awaiting engine release gates",
        "checkout is closed",
        "checkout stays closed",
        "checkout remains closed",
        "not yet published",
        "pre-launch",
        "prelaunch",
        "eventually enabled",
        "launch-blocking inputs",
    )
    for path in (tmp_path / "site").glob("*.html"):
        parser = gate._VisibleText()
        parser.feed(path.read_text(encoding="utf-8"))
        visible = " ".join(parser.parts).lower()
        assert not any(phrase in visible for phrase in forbidden), path.name
    assert "https://schema.org/OutOfStock" not in (
        tmp_path / "site" / "offers.jsonld"
    ).read_text(encoding="utf-8")
    releases_html = (tmp_path / "site/releases.html").read_text(encoding="utf-8")
    assert source["gates"]["guard_release_ready"]["evidence"]
    assert derived["release"]["guard_artifact_url"] in releases_html
    assert derived["release"]["guard_artifact_sha256"] in releases_html
    assert "SHA256SUMS.sig" in releases_html
    assert "START-HERE.txt" in releases_html
    assert "activate --license-key-stdin" in releases_html
    artifact_name = derived["release"]["guard_artifact_url"].rsplit("/", 1)[-1]
    filtered_check = (
        f"grep -F '  {artifact_name}' SHA256SUMS &gt; GUARD.sha256 "
        "&amp;&amp; sha256sum --check --strict GUARD.sha256"
    )
    assert filtered_check in releases_html
    assert "sha256sum --check --strict</code>" not in releases_html

    buyer = tmp_path / "buyer-download"
    buyer.mkdir()
    artifact_raw = b"buyer fixture archive\n"
    (buyer / artifact_name).write_bytes(artifact_raw)
    artifact_digest = hashlib.sha256(artifact_raw).hexdigest()
    (buyer / "SHA256SUMS").write_text(
        f"{'1' * 64}  another-release-asset\n"
        f"{artifact_digest}  {artifact_name}\n"
        f"{'2' * 64}  one-more-release-asset\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            "bash",
            "-c",
            f"grep -F '  {artifact_name}' SHA256SUMS > GUARD.sha256 "
            "&& sha256sum --check --strict GUARD.sha256",
        ],
        cwd=buyer,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert f"{artifact_name}: OK" in completed.stdout

    eula_sha = source["legal"]["eula_sha256"]
    published_eula = tmp_path / "site/legal" / eula_sha / "EULA.txt"
    original_eula = published_eula.read_bytes()
    published_eula.write_bytes(b"tampered\n")
    assert any("EULA" in error for error in gate._check_outputs(rederived, root=tmp_path))
    published_eula.write_bytes(original_eula)
    (tmp_path / "site/legal/unexpected.txt").write_text("extra\n")
    assert any("EULA tree" in error for error in gate._check_outputs(rederived, root=tmp_path))
    assert '"service_status": "guard_prelaunch"' not in (
        tmp_path / "site" / "discovery.json"
    ).read_text(encoding="utf-8")


def test_engine_evidence_exposes_only_production_evidence_acquisition_surfaces(
    tmp_path: Path,
) -> None:
    blocked = gate.derive(blocked_source())
    assert blocked["discovery"]["evergreen_acquisition_pages"] == []
    assert blocked["discovery"]["primary_actions"] == []
    assert "noindex,nofollow" in gate._acquisition_meta(False)
    blocked_routes = {route: False for route in gate.ACQUISITION_ROUTES}
    assert all(
        f"https://tinyzkp.com{route}".encode()
        not in gate._sitemap_bytes(blocked_routes)
        for route in gate.ACQUISITION_ROUTES
    )
    llms_source = (gate.ROOT / "site" / "llms.txt").read_text(encoding="utf-8")
    blocked_llms = gate._llms_text(
        llms_source,
        blocked_routes,
        commerce_state="unconfigured",
        doctor_ready=False,
    )
    assert all(
        f"https://tinyzkp.com{route}" not in blocked_llms
        for route in gate.ACQUISITION_ROUTES
    )

    derived = derive_qualified(engine_only_source(tmp_path), tmp_path)
    expected = [
        f"https://tinyzkp.com{route}"
        for route in gate.ACQUISITION_ROUTES
        if route != "/doctor"
    ]
    assert derived["release"]["qualified_engine_artifact_available"] is True
    assert derived["commerce"]["checkout_enabled"] is False
    assert derived["discovery"]["evergreen_acquisition_pages"] == expected
    assert derived["discovery"]["primary_actions"] == []
    assert "index,follow" in gate._acquisition_meta(True)
    engine_routes = {
        route: route != "/doctor" for route in gate.ACQUISITION_ROUTES
    }
    assert all(
        url.encode() in gate._sitemap_bytes(engine_routes) for url in expected
    )
    qualified_llms = gate._llms_text(
        blocked_llms,
        engine_routes,
        commerce_state="unconfigured",
        doctor_ready=False,
    )
    assert gate.LLMS_ACQUISITION_LINES[0] not in qualified_llms
    assert all(
        line in qualified_llms for line in gate.LLMS_ACQUISITION_LINES[1:]
    )
    assert all(
        line not in qualified_llms
        for line in gate.LLMS_ACQUISITION_RECOMMENDATIONS
    )


def test_non_allowlisted_or_failed_signature_cannot_pass(tmp_path: Path) -> None:
    source = qualified_source(tmp_path)
    source["gates"]["engine_release_ready"]["evidence"][0]["signer_id"] = "invented"
    with pytest.raises(gate.GateError, match="not allowlisted"):
        derive_qualified(source, tmp_path)

    source = qualified_source(tmp_path / "failed")

    def failed_cosign(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 1, stdout="", stderr="bad")

    with pytest.raises(gate.GateError, match="signature verification failed"):
        gate.derive(
            source,
            root=tmp_path / "failed",
            signature_runner=failed_cosign,
            cosign_path=COSIGN,
            trusted_policy_sha256=source["trust_policy"]["sha256"],
        )


def test_trust_policy_path_digest_and_signature_digest_are_bound(tmp_path: Path) -> None:
    source = qualified_source(tmp_path)
    source["trust_policy"]["sha256"] = "0" * 64
    with pytest.raises(gate.GateError, match="trust policy digest"):
        derive_qualified(source, tmp_path)

    source = qualified_source(tmp_path / "signature")
    source["gates"]["engine_release_ready"]["evidence"][0][
        "signature_sha256"
    ] = "0" * 64
    with pytest.raises(gate.GateError, match="signature digest"):
        derive_qualified(source, tmp_path / "signature")


def test_keyless_verification_binds_workflow_commit_ref_repo_and_trigger(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    commands: list[list[str]] = []

    def capture_cosign(*args, **kwargs):
        command = args[0]
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="verified", stderr="")

    signing_policy_sha256 = hashlib.sha256(
        (tmp_path / gate.SIGNING_TRUST_PATH).read_bytes()
    ).hexdigest()
    gate.derive(
        source,
        root=tmp_path,
        signature_runner=capture_cosign,
        cosign_path=COSIGN,
        trusted_policy_sha256=source["trust_policy"]["sha256"],
        trusted_signing_policy_sha256=signing_policy_sha256,
    )
    assert commands
    for command in commands:
        assert command[command.index("--certificate-github-workflow-sha") + 1] == (
            WORKFLOW_SOURCE_SHA
        )
        assert command[command.index("--certificate-github-workflow-ref") + 1] == (
            "refs/heads/main"
        )
        assert command[
            command.index("--certificate-github-workflow-repository") + 1
        ] == "logannye/hc-stark"
        assert command[
            command.index("--certificate-github-workflow-trigger") + 1
        ] == "workflow_dispatch"


def test_gate_evidence_from_a_different_workflow_commit_fails_closed(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "engine_release_ready",
        lambda envelope: envelope.update({"workflow_source_sha": "2" * 40}),
    )

    def reject_wrong_workflow_sha(*args, **kwargs):
        command = args[0]
        observed = command[command.index("--certificate-github-workflow-sha") + 1]
        return subprocess.CompletedProcess(
            command,
            0 if observed == WORKFLOW_SOURCE_SHA else 1,
            stdout="",
            stderr="workflow SHA differs",
        )

    signing_policy_sha256 = hashlib.sha256(
        (tmp_path / gate.SIGNING_TRUST_PATH).read_bytes()
    ).hexdigest()
    with pytest.raises(gate.GateError, match="signature verification failed"):
        gate.derive(
            source,
            root=tmp_path,
            signature_runner=reject_wrong_workflow_sha,
            cosign_path=COSIGN,
            trusted_policy_sha256=source["trust_policy"]["sha256"],
            trusted_signing_policy_sha256=signing_policy_sha256,
        )


def test_repo_controlled_policy_and_evidence_cannot_replace_external_trust_root(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    protected_digest = source["trust_policy"]["sha256"]

    policy_path = tmp_path / source["trust_policy"]["path"]
    policy = json.loads(policy_path.read_text())
    policy["signers"][0]["oidc_issuer"] = "https://replacement-issuer.example"
    policy_raw = gate.canonical_bytes(policy)
    policy_path.write_bytes(policy_raw)
    source["trust_policy"]["sha256"] = hashlib.sha256(policy_raw).hexdigest()

    reference = source["gates"]["engine_release_ready"]["evidence"][0]
    evidence_path = tmp_path / reference["path"]
    envelope = json.loads(evidence_path.read_text())
    envelope["expires_at"] = "2026-07-21T12:00:00Z"
    evidence_raw = gate.canonical_bytes(envelope)
    evidence_path.write_bytes(evidence_raw)
    reference["sha256"] = hashlib.sha256(evidence_raw).hexdigest()
    signature_path = tmp_path / reference["signature_path"]
    signature_raw = gate.canonical_bytes(
        {"replacement_bundle_for_claim_sha256": reference["sha256"]}
    )
    signature_path.write_bytes(signature_raw)
    reference["signature_sha256"] = hashlib.sha256(signature_raw).hexdigest()

    with pytest.raises(gate.GateError, match="independently protected trust root"):
        gate.derive(
            source,
            root=tmp_path,
            signature_runner=successful_cosign,
            cosign_path=COSIGN,
            trusted_policy_sha256=protected_digest,
        )


def test_passing_evidence_cannot_omit_protected_trust_root(tmp_path: Path) -> None:
    source = qualified_source(tmp_path)
    with pytest.raises(gate.GateError, match="protected trust-policy"):
        gate.derive(
            source,
            root=tmp_path,
            signature_runner=successful_cosign,
            cosign_path=COSIGN,
        )


def test_guard_signing_key_is_bound_to_independent_trust(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    with pytest.raises(gate.GateError, match="independently protected root"):
        gate.derive(
            source,
            root=tmp_path,
            signature_runner=successful_cosign,
            cosign_path=COSIGN,
            trusted_policy_sha256=source["trust_policy"]["sha256"],
            trusted_signing_policy_sha256="0" * 64,
        )

    key_path = tmp_path / gate.SIGNING_PUBLIC_KEY_PATH
    key_path.write_bytes(
        b"-----BEGIN PUBLIC KEY-----\nchanged\n-----END PUBLIC KEY-----\n"
    )
    signing_digest = hashlib.sha256(
        (tmp_path / gate.SIGNING_TRUST_PATH).read_bytes()
    ).hexdigest()
    with pytest.raises(gate.GateError, match="public key differs"):
        gate.derive(
            source,
            root=tmp_path,
            signature_runner=successful_cosign,
            cosign_path=COSIGN,
            trusted_policy_sha256=source["trust_policy"]["sha256"],
            trusted_signing_policy_sha256=signing_digest,
        )


def test_release_rehearsal_requires_technical_build_deploy_and_rollback_checks(
    tmp_path: Path,
) -> None:
    for field in (
        "qualification_completed",
        "build_validation_passed",
        "deployment_rehearsed",
        "rollback_rehearsed",
        "release_artifact_identity_verified",
    ):
        root = tmp_path / field
        source = qualified_source(root)
        mutate_claim(
            root,
            source,
            "release_rehearsal_within_budget",
            lambda envelope, field=field: envelope["claims"].__setitem__(field, False),
        )
        with pytest.raises(gate.GateError, match=f"{field} must be true"):
            derive_qualified(source, root)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("retirement_notices_sent", 1, "notices and API-data export"),
        ("external_api_usage_exports_resolved", 1, "notices and API-data export"),
        ("open_export_requests", 1, "open_export_requests must be zero"),
        (
            "customer_artifacts_pending_disposition",
            1,
            "customer_artifacts_pending_disposition must be zero",
        ),
    ],
)
def test_legacy_resolution_requires_notice_and_export_counts_to_match_inventory(
    tmp_path: Path, field: str, value: int, message: str
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "legacy_obligations_resolved",
        lambda envelope: envelope["claims"].__setitem__(field, value),
    )
    with pytest.raises(gate.GateError, match=message):
        derive_qualified(source, tmp_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "owner_only_legacy_tinyzkp_subscriptions_resolved",
            1,
            "two owner-only TinyZKP",
        ),
        (
            "owner_only_legacy_catalog_objects_disabled",
            False,
            "owner_only_legacy_catalog_objects_disabled",
        ),
        (
            "unrelated_stripe_catalog_objects_untouched",
            False,
            "unrelated_stripe_catalog_objects_untouched",
        ),
    ],
)
def test_legacy_resolution_isolates_owner_tinyzkp_subscriptions_from_other_products(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "legacy_obligations_resolved",
        lambda envelope: envelope["claims"].__setitem__(field, value),
    )
    with pytest.raises(gate.GateError, match=message):
        derive_qualified(source, tmp_path)


def test_release_rehearsal_rejects_legacy_budget_claims(tmp_path: Path) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "release_rehearsal_within_budget",
        lambda envelope: envelope["claims"].__setitem__("owner_minutes", 1),
    )
    with pytest.raises(gate.GateError, match="extra=\\['owner_minutes'\\]"):
        derive_qualified(source, tmp_path)


def test_live_hidden_keeps_checkout_private_while_owner_gates_remain_blocked(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    source["requested_commerce_state"] = "live_hidden"
    for name in (
        "merchant_live_owner_smoke_passed",
        "legacy_obligations_resolved",
        "hosted_infrastructure_decommissioned",
    ):
        source["gates"][name] = {
            "status": "blocked",
            "reason_code": gate.BLOCKED_REASONS[name],
            "evidence": [],
        }
    derived = derive_qualified(source, tmp_path)
    assert derived["launch"]["launch_state"] == "blocked"
    assert derived["launch"]["commerce_state"] == "live_hidden"
    assert derived["launch"]["sales_state"] == "closed"
    assert derived["commerce"]["checkout_enabled"] is False
    assert derived["commerce"]["variants"]["annual"]["checkout_url"] is None
    assert derived["commerce"]["variants"]["annual"]["variant_id"] == "402"
    assert source["merchant"]["live_configuration"]["annual_checkout_url"].startswith(
        "https://"
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://store.lemonsqueezy.com:bad/buy/example",
        "https://store.lemonsqueezy.com:444/buy/example",
        "https://user@store.lemonsqueezy.com/buy/example",
        "https://store.lemonsqueezy.com/buy/example#fragment",
        "https://store.lemonsqueezy.com\\@evil.example/buy/example",
        "https://store.lemonsqueezy.com/\nexample",
        " https://store.lemonsqueezy.com/buy/example",
        "https://store.lemonsqueezy.com\u0000/buy/example",
    ],
)
def test_https_url_rejects_ambiguous_or_hostile_forms(value: str) -> None:
    with pytest.raises(gate.GateError, match="HTTPS URL|approved HTTPS"):
        gate._validate_https_url(
            value,
            "checkout",
            required=True,
            allowed_hosts=("lemonsqueezy.com",),
        )


def test_https_url_allows_reviewed_lemon_query_and_default_tls_port() -> None:
    value = "https://store.lemonsqueezy.com:443/buy/example?checkout%5Bemail%5D=x"
    assert (
        gate._validate_https_url(
            value,
            "checkout",
            required=True,
            allowed_hosts=("lemonsqueezy.com",),
        )
        == value
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://lnholdings.lemonsqueezy.com/cart/example",
        "https://lnholdings.lemonsqueezy.com/checkout/buy/annual-live",
        (
            "https://lnholdings.lemonsqueezy.com/checkout/buy/annual-live?"
            "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-18&"
            "checkout%5Bcustom%5D%5Bguard_version%5D=0.1.0&email=owner@example.com"
        ),
        (
            "https://app.lemonsqueezy.com/checkout/buy/annual-live?"
            "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-18&"
            "checkout%5Bcustom%5D%5Bguard_version%5D=0.1.0"
        ),
        LIVE_CONFIG["annual_checkout_url"] + "#",
    ],
)
def test_checkout_url_requires_hosted_buy_link_and_only_fixed_custom_data(
    value: str,
) -> None:
    with pytest.raises(gate.GateError):
        gate._validate_checkout_url(
            value,
            "checkout",
            required=True,
            expected_terms_version="2026-07-18",
            expected_guard_version="0.1.0",
        )


@pytest.mark.parametrize(
    "value",
    [
        "https://lnholdings.lemonsqueezy.com/billing?signed=customer",
        "https://lnholdings.lemonsqueezy.com/billing?",
        "https://lnholdings.lemonsqueezy.com/billing#",
        "https://lnholdings.lemonsqueezy.com/billing/",
        "https://lnholdings.lemonsqueezy.com/my-orders/customer",
        "https://app.lemonsqueezy.com/billing",
        "https://other-store.lemonsqueezy.com/billing",
    ],
)
def test_portal_url_requires_generic_unsigned_matching_store(value: str) -> None:
    with pytest.raises(gate.GateError):
        gate._validate_portal_url(
            value,
            "portal",
            required=True,
            expected_store_hostname="lnholdings.lemonsqueezy.com",
        )


@pytest.mark.parametrize(
    "mutation",
    ["reused_product", "reused_variant", "duplicate_checkout"],
)
def test_test_live_catalog_and_checkout_objects_must_be_distinct(
    tmp_path: Path, mutation: str
) -> None:
    source = qualified_source(tmp_path)
    if mutation == "reused_product":
        source["merchant"]["live_configuration"]["product_id"] = TEST_CONFIG[
            "product_id"
        ]
    elif mutation == "reused_variant":
        source["merchant"]["live_configuration"]["annual_variant_id"] = (
            TEST_CONFIG["annual_variant_id"]
        )
    else:
        source["merchant"]["live_configuration"]["annual_checkout_url"] = (
            source["merchant"]["live_configuration"]["monthly_checkout_url"]
        )
    with pytest.raises(gate.GateError, match="distinct|must differ"):
        derive_qualified(source, tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_policy", "external_review_v1"),
        ("qualification_basis", "independently_reviewed"),
    ],
)
def test_owner_only_policy_wire_values_are_locked(field: str, value: str) -> None:
    source = blocked_source()
    source[field] = value
    with pytest.raises(gate.GateError, match=field):
        gate.derive(source)


def test_owner_signed_freeze_closes_checkout_and_preserves_portal(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    attach_signed_sales_freeze(tmp_path, source)
    derived = derive_qualified(source, tmp_path)
    assert derived["launch"]["launch_state"] == "qualified"
    assert derived["launch"]["sales_state"] == "frozen"
    assert derived["commerce"]["checkout_enabled"] is False
    assert derived["commerce"]["customer_portal_url"].startswith("https://")


def test_sales_freeze_rejects_unsigned_and_tampered_records(tmp_path: Path) -> None:
    unsigned_root = tmp_path / "unsigned"
    unsigned = qualified_source(unsigned_root)
    unsigned["requested_commerce_state"] = "sales_frozen"
    with pytest.raises(gate.GateError, match="owner-signed freeze record"):
        derive_qualified(unsigned, unsigned_root)

    tampered_root = tmp_path / "tampered"
    tampered = qualified_source(tampered_root)
    attach_signed_sales_freeze(tampered_root, tampered)
    reference = tampered["sales_freeze"]["evidence"][0]
    evidence = tampered_root / reference["path"]
    envelope = json.loads(evidence.read_text())
    envelope["reason"] = "unsigned_operator_override"
    raw = gate.canonical_bytes(envelope)
    evidence.write_bytes(raw)
    reference["sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(gate.GateError, match="contract differs"):
        derive_qualified(tampered, tampered_root)


def test_sales_frozen_rejects_synthetic_pending_or_portalless_state(
    tmp_path: Path,
) -> None:
    for mutation in ("pending", "portalless", "no-live-history"):
        root = tmp_path / mutation
        source = qualified_source(root)
        if mutation == "pending":
            source["merchant"]["approval_status"] = "pending"
        elif mutation == "portalless":
            source["merchant"]["portal_state"] = "unconfigured"
            source["merchant"]["portal_url"] = None
        else:
            source["gates"]["merchant_live_owner_smoke_passed"] = {
                "status": "blocked",
                "reason_code": gate.BLOCKED_REASONS[
                    "merchant_live_owner_smoke_passed"
                ],
                "evidence": [],
            }
        attach_signed_sales_freeze(root, source)
        with pytest.raises(gate.GateError, match="sales_frozen requires"):
            derive_qualified(source, root)


def test_partial_evidence_requires_exact_candidate_identity(tmp_path: Path) -> None:
    source = qualified_source(tmp_path)
    for name in gate.REQUIRED_GATES - {"engine_release_ready"}:
        source["gates"][name] = {
            "status": "blocked",
            "reason_code": gate.BLOCKED_REASONS[name],
            "evidence": [],
        }
    source["requested_commerce_state"] = "test_published"
    source["release_identity"] = blocked_source()["release_identity"]
    with pytest.raises(gate.GateError, match="requires a semantic version"):
        derive_qualified(source, tmp_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("artifact_url", None, "artifact URL"),
        ("artifact_sha256", "0", "artifact_sha256"),
        ("oci_digest", "sha256:bad", "oci_digest"),
        ("channel_identity_sha256", "0", "channel_identity_sha256"),
    ],
)
def test_guard_release_requires_digest_bound_candidate_artifact(
    tmp_path: Path, field: str, value, message: str
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "guard_release_ready",
        lambda envelope: envelope["claims"].__setitem__(field, value),
    )
    with pytest.raises(gate.GateError, match=message):
        derive_qualified(source, tmp_path)


def test_candidate_build_authorization_is_closed_and_noncommercial(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    remove_published_index(tmp_path)
    source["requested_commerce_state"] = "live_hidden"
    source["gates"]["guard_release_ready"] = {
        "status": "blocked",
        "reason_code": gate.BLOCKED_REASONS["guard_release_ready"],
        "evidence": [],
    }
    derived = derive_qualified(source, tmp_path)
    gate._require_candidate_build_ready(derived, now=NOW)
    authorization = derived["candidate_authorization"]
    assert authorization["authorization_state"] == "authorized"
    assert authorization["authorization_scope"] == "prepare_signed_guard_draft_only"
    assert authorization["commercial_release_authorized"] is False
    assert authorization["checkout_enabled"] is False
    assert authorization["expected_public_candidate_tag"] == "guard-v1.0.0"
    assert authorization["engine"]["candidate_tag"] == "backend-v1.0.0"
    assert (
        authorization["engine"]["public_contracts_git_revision"]
        == IDENTITY["engine_source_sha"]
    )
    assert authorization["legal_artifacts"] == {
        "release_date": "2026-07-18",
        "eula_sha256": source["legal"]["eula_sha256"],
        "eula_url": gate._eula_url(source["legal"]["eula_sha256"]),
        "notices_sha256": source["legal"]["notices_sha256"],
    }


@pytest.mark.parametrize(
    ("evaluated_at", "now", "message"),
    [
        (
            "2026-07-17T11:59:59Z",
            datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc),
            "older than 24 hours",
        ),
        (
            "2026-07-18T12:00:01Z",
            datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc),
            "future-dated",
        ),
    ],
)
def test_candidate_readiness_rejects_stale_or_future_evaluation_clock(
    tmp_path: Path, evaluated_at: str, now: datetime, message: str
) -> None:
    source = qualified_source(tmp_path)
    remove_published_index(tmp_path)
    source["requested_commerce_state"] = "live_hidden"
    source["gates"]["guard_release_ready"] = {
        "status": "blocked",
        "reason_code": gate.BLOCKED_REASONS["guard_release_ready"],
        "evidence": [],
    }
    derived = derive_qualified(source, tmp_path)
    derived["launch"]["evaluated_at"] = evaluated_at
    with pytest.raises(gate.GateError, match=message):
        gate._require_candidate_build_ready(derived, now=now)


def test_promotion_requires_freshness_but_routine_live_deploy_does_not(
    tmp_path: Path,
) -> None:
    promotion_source = qualified_source(tmp_path / "promotion")
    remove_published_index(tmp_path / "promotion")
    promotion_source["requested_commerce_state"] = "live_hidden"
    mutate_claim(
        tmp_path / "promotion",
        promotion_source,
        "guard_release_ready",
        lambda envelope: envelope["claims"].__setitem__(
            "artifact_published", False
        ),
    )
    promotion = derive_qualified(promotion_source, tmp_path / "promotion")
    promotion["launch"]["evaluated_at"] = "2026-07-17T11:59:59Z"
    with pytest.raises(gate.GateError, match="older than 24 hours"):
        gate._require_promotion_ready(promotion, now=NOW)

    production = derive_qualified(
        qualified_source(tmp_path / "production"), tmp_path / "production"
    )
    production["launch"]["evaluated_at"] = "2026-07-18T12:00:01Z"
    errors = gate.validate(
        production["launch"], require_ready=True, now=NOW
    )
    assert any("future-dated" in error for error in errors)
    production["launch"]["evaluated_at"] = "2026-07-17T11:59:59Z"
    assert gate.validate(
        production["launch"], require_ready=True, now=NOW
    ) == []


def test_promotion_ready_has_only_publication_blocked_and_checkout_closed(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    remove_published_index(tmp_path)
    source["requested_commerce_state"] = "live_hidden"
    mutate_claim(
        tmp_path,
        source,
        "guard_release_ready",
        lambda envelope: envelope["claims"].__setitem__(
            "artifact_published", False
        ),
    )


def test_imported_signed_index_derives_publication_without_mutating_guard_evidence(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    assert CLAIMS["guard_release_ready"]["artifact_published"] is False
    published = derive_qualified(source, tmp_path)
    assert published["release"]["guard_artifact_available"] is True
    assert published["launch"]["gate_status"]["guard_artifact_published"]["status"] == "passed"

    remove_published_index(tmp_path)
    source["requested_commerce_state"] = "live_hidden"
    not_published = derive_qualified(source, tmp_path)
    assert not_published["release"]["guard_artifact_available"] is False
    assert not_published["launch"]["blocking_gates"] == ["guard_artifact_published"]
    derived = derive_qualified(source, tmp_path)
    gate._require_promotion_ready(derived, now=NOW)
    assert derived["launch"]["blocking_gates"] == [
        gate.ARTIFACT_PUBLICATION_BLOCKER
    ]
    assert derived["launch"]["checkout_enabled"] is False
    assert derived["release"]["guard_artifact_available"] is False
    assert (
        derived["candidate_authorization"]["authorization_state"]
        == "candidate_prepared"
    )


@pytest.mark.parametrize(
    "mutation",
    ["other_gate_blocked", "artifact_already_public", "checkout_requested"],
)
def test_promotion_ready_fails_closed_for_wrong_sequence(
    tmp_path: Path, mutation: str
) -> None:
    source = qualified_source(tmp_path)
    if mutation != "artifact_already_public":
        remove_published_index(tmp_path)
    source["requested_commerce_state"] = "live_hidden"
    mutate_claim(
        tmp_path,
        source,
        "guard_release_ready",
        lambda envelope: envelope["claims"].__setitem__(
            "artifact_published", False
        ),
        )
    if mutation == "other_gate_blocked":
        source["gates"]["legacy_obligations_resolved"] = {
            "status": "blocked",
            "reason_code": gate.BLOCKED_REASONS["legacy_obligations_resolved"],
            "evidence": [],
        }
    derived = derive_qualified(source, tmp_path)
    if mutation == "checkout_requested":
        derived["launch"]["commerce_state"] = "public_live"
        derived["launch"]["checkout_enabled"] = True
    with pytest.raises(gate.GateError, match="promotion is not ready"):
        gate._require_promotion_ready(derived, now=NOW)


def test_action_time_revalidates_each_evidence_expiry(tmp_path: Path) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "engine_release_ready",
        lambda envelope: envelope.__setitem__(
            "expires_at", "2026-07-18T13:00:00Z"
        ),
    )
    signing_policy_sha256 = hashlib.sha256(
        (tmp_path / gate.SIGNING_TRUST_PATH).read_bytes()
    ).hexdigest()
    with pytest.raises(gate.GateError, match="expired at action time"):
        gate.derive(
            source,
            root=tmp_path,
            signature_runner=successful_cosign,
            cosign_path=COSIGN,
            trusted_policy_sha256=source["trust_policy"]["sha256"],
            trusted_signing_policy_sha256=signing_policy_sha256,
            current_time=datetime(
                2026, 7, 18, 14, 0, 0, tzinfo=timezone.utc
            ),
        )
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("channel_release_identity", "tinyzkp-guard/invalid"),
        ("channel_guard_version", "1.0.1"),
        ("channel_guard_source_sha", "f" * 40),
        ("channel_engine_source_sha", "f" * 40),
        ("public_candidate_authorization_commit", "not-a-commit"),
        ("channel_compatibility_profile", "unsupported-profile"),
        ("channel_artifact_sha256", "f" * 64),
        ("channel_oci_digest", "sha256:" + "f" * 64),
    ],
)
def test_guard_channel_identity_must_match_candidate_and_artifacts(
    tmp_path: Path, field: str, value: str
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "guard_release_ready",
        lambda envelope: envelope["claims"].__setitem__(field, value),
    )
    with pytest.raises(gate.GateError, match=field):
        derive_qualified(source, tmp_path)


def test_public_live_generated_release_identity_cannot_diverge(
    tmp_path: Path,
) -> None:
    derived = derive_qualified(qualified_source(tmp_path), tmp_path)
    derived["release"]["guard_artifact_sha256"] = "f" * 64
    with pytest.raises(gate.GateError, match="one exact Guard artifact"):
        gate._validate_output_identity_parity(derived)


@pytest.mark.parametrize(
    "field",
    sorted(
        set(CLAIMS["engine_release_ready"])
        - {"backend_gate_status"}
    ),
)
@pytest.mark.parametrize("mutation", ["false", "missing"])
def test_engine_release_rejects_every_missing_or_false_qualification_claim(
    tmp_path: Path, field: str, mutation: str
) -> None:
    source = qualified_source(tmp_path)

    def mutate(envelope: dict) -> None:
        if mutation == "missing":
            envelope["claims"].pop(field)
        else:
            envelope["claims"][field] = False

    mutate_claim(tmp_path, source, "engine_release_ready", mutate)
    with pytest.raises(gate.GateError, match=field):
        derive_qualified(source, tmp_path)


@pytest.mark.parametrize(
    "field",
    sorted(
        key
        for key, value in CLAIMS["guard_release_ready"].items()
        if value is True and key != "artifact_published"
    ),
)
@pytest.mark.parametrize("mutation", ["false", "missing"])
def test_guard_release_rejects_every_missing_or_false_qualification_claim(
    tmp_path: Path, field: str, mutation: str
) -> None:
    source = qualified_source(tmp_path)

    def mutate(envelope: dict) -> None:
        if mutation == "missing":
            envelope["claims"].pop(field)
        else:
            envelope["claims"][field] = False

    mutate_claim(tmp_path, source, "guard_release_ready", mutate)
    with pytest.raises(gate.GateError, match=field):
        derive_qualified(source, tmp_path)


def test_external_review_and_adoption_status_is_advisory_and_transparent(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    derived = derive_qualified(source, tmp_path)
    expected = {name: "not_completed" for name in gate.ADVISORY_ITEMS}
    assert derived["launch"]["advisory_status"] == expected
    assert derived["release"]["advisory_status"] == expected
    assert not (set(expected) & set(derived["launch"]["blocking_gates"]))

    source["advisory_status"]["three_external_workloads"] = "completed"
    with pytest.raises(gate.GateError, match="transparent and not_completed"):
        derive_qualified(source, tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("embedded_merchant_mode", "test"),
        ("embedded_store_id", "999"),
        ("embedded_product_id", "999"),
        ("embedded_monthly_variant_id", "999"),
        ("embedded_annual_variant_id", "999"),
    ],
)
def test_guard_embedded_catalog_must_match_live_merchant_configuration(
    tmp_path: Path, field: str, value: str
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "guard_release_ready",
        lambda envelope: envelope["claims"].__setitem__(field, value),
    )
    with pytest.raises(gate.GateError, match="merchant"):
        derive_qualified(source, tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("release_date", "2026-7-18"),
        ("eula_sha256", "not-a-digest"),
        ("notices_sha256", None),
    ],
)
def test_legal_evidence_binds_release_date_and_legal_artifact_digests(
    tmp_path: Path, field: str, value
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "legal_terms_approved",
        lambda envelope: envelope["claims"].__setitem__(field, value),
    )
    with pytest.raises(gate.GateError, match=field):
        derive_qualified(source, tmp_path)


def test_legal_approval_binds_actual_bytes_and_pricing_effective_date(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    derived = derive_qualified(source, tmp_path)
    assert derived["pricing"]["effective_date"] == source["legal"]["release_date"]

    (tmp_path / "site/terms.html").write_text(
        "<!doctype html><html><body>tampered terms</body></html>\n",
        encoding="utf-8",
    )
    with pytest.raises(gate.GateError, match="actual repository bytes"):
        derive_qualified(source, tmp_path)

    root = tmp_path / "placeholder"
    source = qualified_source(root)
    (root / "legal/EULA.txt").write_text(
        "UNRESOLVED PLACEHOLDER\n", encoding="utf-8"
    )
    with pytest.raises(gate.GateError, match="release-blocking markers"):
        derive_qualified(source, root)

    blocked = gate.derive(blocked_source())
    assert blocked["pricing"]["effective_date"] is None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("Final EULA without a date.\n", "exactly one Effective Date"),
        (
            "Effective Date: 2026-07-18\nEffective Date: 2026-07-18\n",
            "exactly one Effective Date",
        ),
        (
            "Effective Date: 2026-07-19\n",
            "differs from legal release_date",
        ),
    ],
)
def test_eula_effective_date_is_unique_and_matches_checkout_terms(
    tmp_path: Path, text: str, message: str
) -> None:
    legal = tmp_path / "legal"
    legal.mkdir()
    (legal / "EULA.txt").write_text(text, encoding="utf-8")
    with pytest.raises(gate.GateError, match=message):
        gate._validate_eula_effective_date(tmp_path, "2026-07-18")


def test_unchanged_engine_evidence_can_be_reused_only_for_non_proof_change(
    tmp_path: Path,
) -> None:
    def age_engine(envelope: dict) -> None:
        envelope["issued_at"] = "2026-01-01T12:00:00Z"
        envelope["expires_at"] = "2026-12-31T12:00:00Z"

    proof_root = tmp_path / "proof"
    proof_source = qualified_source(proof_root)
    mutate_claim(
        proof_root,
        proof_source,
        "engine_release_ready",
        age_engine,
    )
    with pytest.raises(gate.GateError, match="120 days"):
        derive_qualified(proof_source, proof_root)

    package_root = tmp_path / "package"
    package_source = guard_package_source(package_root)
    mutate_claim(
        package_root,
        package_source,
        "engine_release_ready",
        age_engine,
    )
    derive_qualified(package_source, package_root)

    mutate_claim(
        package_root,
        package_source,
        "engine_release_ready",
        lambda envelope: envelope["release_identity"].__setitem__(
            "engine_source_sha", "f" * 40
        ),
    )
    with pytest.raises(gate.GateError, match="engine_source_sha"):
        derive_qualified(package_source, package_root)


def test_guard_package_reuses_durable_owner_evidence_without_adoption_blocker(
    tmp_path: Path,
) -> None:
    source = guard_package_source(tmp_path)
    derived = derive_qualified(source, tmp_path)
    assert derived["launch"]["launch_state"] == "qualified"
    assert derived["launch"]["advisory_status"]["five_unaided_installs"] == (
        "not_completed"
    )


def test_proof_critical_successor_requires_exact_immutable_predecessor(
    tmp_path: Path,
) -> None:
    source, prior_index_sha = proof_successor_source(tmp_path)
    assert derive_qualified(source, tmp_path)["launch"]["launch_state"] == "qualified"

    rewrite_publication(
        tmp_path,
        publication_kind="initial_ga",
        prior_index_sha256=None,
    )
    with pytest.raises(gate.GateError, match="predecessor binding"):
        derive_qualified(source, tmp_path)

    root = tmp_path / "symlink"
    source, prior_index_sha = proof_successor_source(root)
    prior_path = (
        root
        / "site/release-index-revisions"
        / prior_index_sha
        / gate.RELEASE_INDEX_NAME
    )
    prior_path.unlink()
    prior_path.symlink_to(root / "site" / gate.RELEASE_INDEX_NAME)
    with pytest.raises(gate.GateError, match="symlink"):
        derive_qualified(source, root)


def test_first_release_cannot_self_label_as_guard_package_only(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    source["release_change_class"] = "guard_package_only"
    mutate_claim(
        tmp_path,
        source,
        "release_rehearsal_within_budget",
        lambda envelope: envelope["claims"].__setitem__(
            "change_class", "guard_package_only"
        ),
    )
    with pytest.raises(gate.GateError, match="signed prior qualified release"):
        derive_qualified(source, tmp_path)


def test_guard_package_reuse_rejects_cross_release_legal_document(
    tmp_path: Path,
) -> None:
    source = guard_package_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "legal_terms_approved",
        lambda envelope: envelope["claims"].__setitem__(
            "eula_sha256", "6" * 64
        ),
    )
    with pytest.raises(gate.GateError, match="document identity"):
        derive_qualified(source, tmp_path)


def test_site_legal_pricing_reuses_software_and_reruns_site_merchant_legal_rollback(
    tmp_path: Path,
) -> None:
    source = site_legal_pricing_source(tmp_path)
    derived = derive_qualified(source, tmp_path)
    assert derived["launch"]["launch_state"] == "qualified"
    assert derived["release"]["release_identity"] == IDENTITY

    mutate_claim(
        tmp_path,
        source,
        "release_rehearsal_within_budget",
        lambda envelope: envelope["claims"].__setitem__(
            "rollback_rehearsed", False
        ),
    )
    with pytest.raises(gate.GateError, match="rollback_rehearsed"):
        derive_qualified(source, tmp_path)


def test_site_legal_pricing_cannot_change_software_identity(
    tmp_path: Path,
) -> None:
    source = site_legal_pricing_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "guard_release_ready",
        lambda envelope: envelope["release_identity"].__setitem__(
            "guard_source_sha", "6" * 40
        ),
    )
    with pytest.raises(gate.GateError, match="release identity differs"):
        derive_qualified(source, tmp_path)


def test_sandbox_expiry_and_owner_live_catalog_inspection_are_required(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "merchant_sandbox_lifecycle_passed",
        lambda envelope: envelope.__setitem__(
            "expires_at", "2026-07-18T11:59:59Z"
        ),
    )
    with pytest.raises(gate.GateError, match="has expired"):
        derive_qualified(source, tmp_path)

    root = tmp_path / "live"
    source = qualified_source(root)
    mutate_claim(
        root,
        source,
        "merchant_live_owner_smoke_passed",
        lambda envelope: envelope["claims"].__setitem__(
            "annual_price_rendered", False
        ),
    )
    with pytest.raises(gate.GateError, match="annual_price_rendered"):
        derive_qualified(source, root)


def test_test_and_live_variant_identity_mixing_is_rejected(tmp_path: Path) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "merchant_sandbox_lifecycle_passed",
        lambda envelope: envelope["claims"].__setitem__(
            "annual_variant_id", "402"
        ),
    )
    with pytest.raises(gate.GateError, match="differs from merchant configuration"):
        derive_qualified(source, tmp_path)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("monthly_checkout_url", LIVE_CONFIG["annual_checkout_url"]),
        ("portal_url", "https://another-store.lemonsqueezy.com/billing"),
        ("store_hostname", "another-store.lemonsqueezy.com"),
    ),
)
def test_merchant_evidence_binds_exact_urls_portal_and_store(
    tmp_path: Path, field: str, replacement: str
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "merchant_live_owner_smoke_passed",
        lambda envelope: envelope["claims"].__setitem__(field, replacement),
    )
    with pytest.raises(gate.GateError):
        derive_qualified(source, tmp_path)


def test_digest_identity_semantics_and_safe_paths_remain_enforced(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    source["gates"]["engine_release_ready"]["evidence"][0]["sha256"] = "0" * 64
    with pytest.raises(gate.GateError, match="digest does not match"):
        derive_qualified(source, tmp_path)

    root = tmp_path / "identity"
    source = qualified_source(root)
    mutate_claim(
        root,
        source,
        "engine_release_ready",
        lambda envelope: envelope["release_identity"].__setitem__(
            "engine_source_sha", "f" * 40
        ),
    )
    with pytest.raises(gate.GateError, match="release identity differs"):
        derive_qualified(source, root)

    root = tmp_path / "path"
    source = qualified_source(root)
    source["gates"]["engine_release_ready"]["evidence"][0][
        "path"
    ] = "release/evidence/guard-launch-v2/../outside.json"
    with pytest.raises(gate.GateError, match="normalized JSON path"):
        derive_qualified(source, root)
