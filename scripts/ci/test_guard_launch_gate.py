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
COSIGN = Path("/opt/tinyzkp-test/cosign")
INDEX_RAW = b'{"current_release_identity":"test","product":"tinyzkp-guard","releases":[],"schema_version":1}\n'
INDEX_SIGNATURE_RAW = b"test-guard-release-index-signature\n"
INDEX_SHA256 = hashlib.sha256(INDEX_RAW).hexdigest()
INDEX_SIGNATURE_SHA256 = hashlib.sha256(INDEX_SIGNATURE_RAW).hexdigest()
TEST_CONFIG = {
    "store_id": "101",
    "product_id": "201",
    "monthly_variant_id": "301",
    "annual_variant_id": "302",
}
LIVE_CONFIG = {
    "store_id": "102",
    "product_id": "202",
    "monthly_variant_id": "401",
    "annual_variant_id": "402",
    "monthly_checkout_url": "https://store.lemonsqueezy.com/buy/monthly-live",
    "annual_checkout_url": "https://store.lemonsqueezy.com/buy/annual-live",
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
        "independent_reproduction": True,
        "specialist_fri_approval": True,
        "independent_review_no_high_or_critical": True,
        "external_non_reference_acceptance": True,
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
        "artifact_published": True,
        "artifact_url": "https://github.com/example/tinyzkp/releases/download/v1/guard.tar.gz",
        "artifact_sha256": "c" * 64,
        "oci_digest": "sha256:" + "d" * 64,
        "channel_url": "https://github.com/example/tinyzkp/releases/download/v1/channel.json",
        "channel_identity_sha256": "e" * 64,
        "release_index_url": "https://github.com/example/tinyzkp/releases/download/v1/guard-release-index-v1.json",
        "release_index_sha256": INDEX_SHA256,
        "release_index_signature_url": "https://github.com/example/tinyzkp/releases/download/v1/guard-release-index-v1.json.sig",
        "release_index_signature_sha256": INDEX_SIGNATURE_SHA256,
        "channel_release_identity": (
            f"tinyzkp-guard/{IDENTITY['guard_version']}"
            f"+guard.{IDENTITY['guard_source_sha']}"
            f".engine.{IDENTITY['engine_source_sha']}"
            f".artifact.{'c' * 64}"
        ),
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
        **{key: LIVE_CONFIG[key] for key in TEST_CONFIG},
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
        "counsel_approved": True,
        "eula": True,
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
        "mode": "test",
        "catalog_policy": copy.deepcopy(gate.MERCHANT_CATALOG_POLICY),
        **TEST_CONFIG,
    },
    "merchant_live_owner_smoke_passed": {
        "owner_purchase": True,
        "activation": True,
        "portal": True,
        "cancellation": True,
        "refund": True,
        "cadence": "annual",
        "mode": "live",
        "catalog_policy": copy.deepcopy(gate.MERCHANT_CATALOG_POLICY),
        "receipt_amount_usd": 4990,
        "receipt_currency": "USD",
        **{key: LIVE_CONFIG[key] for key in TEST_CONFIG},
    },
    "legacy_obligations_resolved": {
        "unresolved_obligations": 0,
        "statutory_records_retained": True,
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
        "retired_410_period_days": 90,
    },
    "release_rehearsal_within_budget": {
        "qualification_completed": True,
        "owner_minutes": 480,
        "external_spend_cents": 300000,
        "cash_reserve_cents": 600000,
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
            }
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
        "portal_url": "https://app.lemonsqueezy.com/my-orders/example",
        "catalog_policy": copy.deepcopy(gate.MERCHANT_CATALOG_POLICY),
        "test_configuration": copy.deepcopy(TEST_CONFIG),
        "live_configuration": copy.deepcopy(LIVE_CONFIG),
    }
    source["legal"] = {
        "seller_status": "confirmed",
        "counsel_status": "approved",
        "release_date": "2026-07-18",
        "eula_sha256": "8" * 64,
        "notices_sha256": "9" * 64,
        "terms_sha256": "6" * 64,
        "privacy_sha256": "7" * 64,
        "refunds_sha256": "5" * 64,
    }
    write_trust(root, source)
    write_signing_trust(root)
    evidence_dir = root / "release" / "evidence" / "guard-launch-v2"
    evidence_dir.mkdir(parents=True)
    for gate_name in gate.REQUIRED_GATES:
        kind, _max_age = gate.GATE_POLICIES[gate_name]
        envelope = {
            "schema_version": 1,
            "document_type": "GuardGateEvidenceV1",
            "evidence_kind": kind,
            "gate": gate_name,
            "result": "passed",
            "issued_at": ISSUED_AT,
            "expires_at": EXPIRES_AT,
            "release_identity": copy.deepcopy(IDENTITY),
            "claims": copy.deepcopy(CLAIMS[gate_name]),
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
    return source


def write_prior_release_evidence(
    root: Path, source: dict, prior_identity: dict
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
        "prior_release_index_sha256": "d" * 64,
        "prior_channel_url": (
            "https://github.com/example/tinyzkp/releases/download/"
            f"guard-v{prior_identity['guard_version']}/guard-channel-v1.json"
        ),
    }
    envelope = {
        "schema_version": 1,
        "document_type": "GuardGateEvidenceV1",
        "evidence_kind": kind,
        "gate": gate_name,
        "result": "passed",
        "issued_at": ISSUED_AT,
        "expires_at": "2027-07-17T12:00:00Z",
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


def engine_only_source(root: Path) -> dict:
    source = qualified_source(root)
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
    write_prior_release_evidence(root, source, prior_identity)
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
                "channel_prior_release_index_sha256": "d" * 64,
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
    mutate_claim(
        root,
        source,
        "five_unaided_installs",
        lambda envelope: envelope["claims"].update(
            {"clean_machines": 2, "verified_under_60_minutes": 2}
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


def test_repository_state_is_generated_and_fail_closed() -> None:
    source = gate.load_json(gate.DEFAULT_SOURCE, "source")
    derived = gate.derive(source)
    assert gate._check_outputs(derived) == []
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

    source["requested_commerce_state"] = "sales_frozen"
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


def test_passing_evidence_cannot_omit_external_trust_root(tmp_path: Path) -> None:
    source = qualified_source(tmp_path)
    with pytest.raises(gate.GateError, match="independently protected"):
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


def test_release_rehearsal_time_cost_and_reserve_are_semantic_gates(
    tmp_path: Path,
) -> None:
    for field, value, message in (
        ("owner_minutes", 481, "eight owner hours"),
        ("external_spend_cents", 300001, "\\$3,000"),
        ("cash_reserve_cents", 599999, "\\$6,000"),
    ):
        root = tmp_path / field
        source = qualified_source(root)
        mutate_claim(
            root,
            source,
            "release_rehearsal_within_budget",
            lambda envelope, field=field, value=value: envelope["claims"].__setitem__(
                field, value
            ),
        )
        with pytest.raises(gate.GateError, match=message):
            derive_qualified(source, root)


def test_live_hidden_allows_unlisted_founding_checkout_without_public_url(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    source["requested_commerce_state"] = "live_hidden"
    for name in (
        "three_external_workloads",
        "two_standard_annual_customers",
        "five_unaided_installs",
        "merchant_live_owner_smoke_passed",
        "legacy_obligations_resolved",
        "hosted_infrastructure_decommissioned",
        "release_rehearsal_within_budget",
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


def test_blocked_launch_can_freeze_sales_and_preserve_portal(tmp_path: Path) -> None:
    source = qualified_source(tmp_path)
    source["requested_commerce_state"] = "sales_frozen"
    source["gates"]["engine_release_ready"] = {
        "status": "blocked",
        "reason_code": gate.BLOCKED_REASONS["engine_release_ready"],
        "evidence": [],
    }
    derived = derive_qualified(source, tmp_path)
    assert derived["launch"]["launch_state"] == "blocked"
    assert derived["launch"]["sales_state"] == "frozen"
    assert derived["commerce"]["checkout_enabled"] is False
    assert derived["commerce"]["customer_portal_url"].startswith("https://")


def test_sales_frozen_rejects_synthetic_pending_or_portalless_state(
    tmp_path: Path,
) -> None:
    for mutation in ("pending", "portalless", "no-live-history"):
        root = tmp_path / mutation
        source = qualified_source(root)
        source["requested_commerce_state"] = "sales_frozen"
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
        "eula_sha256": "8" * 64,
        "notices_sha256": "9" * 64,
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


def test_promotion_and_production_readiness_share_real_utc_freshness(
    tmp_path: Path,
) -> None:
    promotion_source = qualified_source(tmp_path / "promotion")
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


def test_promotion_ready_has_only_publication_blocked_and_checkout_closed(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    source["requested_commerce_state"] = "live_hidden"
    mutate_claim(
        tmp_path,
        source,
        "guard_release_ready",
        lambda envelope: envelope["claims"].__setitem__(
            "artifact_published", False
        ),
    )
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
        source["gates"]["five_unaided_installs"] = {
            "status": "blocked",
            "reason_code": gate.BLOCKED_REASONS["five_unaided_installs"],
            "evidence": [],
        }
    elif mutation == "artifact_already_public":
        mutate_claim(
            tmp_path,
            source,
            "guard_release_ready",
            lambda envelope: envelope["claims"].__setitem__(
                "artifact_published", True
            ),
        )
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


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("max_workloads_per_organization", 2, "one workload"),
        ("public_adapter", False, "public_adapter"),
        ("public_job_contract", False, "public_job_contract"),
        ("witness_data_transferred", True, "no witness transfer"),
        ("customer_specific_branches", 1, "branches must be zero"),
        ("organizations_with_real_failure_problem", 2, "real failure"),
        ("minimum_documented_failure_cost_usd", 4990, "materially exceed"),
        ("written_annual_price_acceptances", 1, "two written"),
    ],
)
def test_market_gate_rejects_each_self_service_bypass(
    tmp_path: Path, field: str, value, message: str
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "three_external_workloads",
        lambda envelope: envelope["claims"].__setitem__(field, value),
    )
    with pytest.raises(gate.GateError, match=message):
        derive_qualified(source, tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("organizations", 4),
        ("workloads", 4),
        ("organizations_with_real_failure_problem", 4),
    ],
)
def test_founding_validation_cannot_exceed_three_organizations_or_workloads(
    tmp_path: Path, field: str, value: int
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "three_external_workloads",
        lambda envelope: envelope["claims"].__setitem__(field, value),
    )
    with pytest.raises(gate.GateError, match="exactly three"):
        derive_qualified(source, tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("clean_machines", 2),
        ("clean_machines", 6),
        ("verified_under_60_minutes", 6),
        ("median_minutes", 30),
        ("ordinary_purchase", False),
        ("license_received", False),
        ("artifact_downloaded", False),
        ("artifact_signature_verified", False),
        ("release_activated", False),
        ("proof_produced", False),
        ("official_verifier_accepted", False),
        ("interruption_resumed", False),
        ("ci_policy_passed", False),
        ("portal_cancelled", False),
    ],
)
def test_clean_machine_gate_requires_exact_five_complete_journeys(
    tmp_path: Path, field: str, value
) -> None:
    source = qualified_source(tmp_path)
    mutate_claim(
        tmp_path,
        source,
        "five_unaided_installs",
        lambda envelope: envelope["claims"].__setitem__(field, value),
    )
    with pytest.raises(gate.GateError):
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


def test_guard_package_reuses_durable_evidence_and_requires_two_machine_smoke(
    tmp_path: Path,
) -> None:
    source = guard_package_source(tmp_path)
    derived = derive_qualified(source, tmp_path)
    assert derived["launch"]["launch_state"] == "qualified"

    mutate_claim(
        tmp_path,
        source,
        "five_unaided_installs",
        lambda envelope: envelope["claims"].update(
            {"clean_machines": 5, "verified_under_60_minutes": 5}
        ),
    )
    with pytest.raises(gate.GateError, match="exactly 2 machines"):
        derive_qualified(source, tmp_path)


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
    mutate_claim(
        tmp_path,
        source,
        "five_unaided_installs",
        lambda envelope: envelope["claims"].update(
            {"clean_machines": 2, "verified_under_60_minutes": 2}
        ),
    )
    with pytest.raises(gate.GateError, match="signed prior qualified release"):
        derive_qualified(source, tmp_path)


@pytest.mark.parametrize(
    ("gate_name", "mutator", "message"),
    [
        (
            "three_external_workloads",
            lambda envelope: envelope["release_identity"].__setitem__(
                "compatibility_profile", "other-profile"
            ),
            "compatibility_profile",
        ),
        (
            "two_standard_annual_customers",
            lambda envelope: envelope["claims"].__setitem__("annual_variant_id", "999"),
            "merchant configuration",
        ),
        (
            "legal_terms_approved",
            lambda envelope: envelope["claims"].__setitem__(
                "eula_sha256", "6" * 64
            ),
            "document identity",
        ),
    ],
)
def test_guard_package_reuse_rejects_cross_profile_catalog_and_document(
    tmp_path: Path, gate_name: str, mutator, message: str
) -> None:
    source = guard_package_source(tmp_path)
    mutate_claim(tmp_path, source, gate_name, mutator)
    with pytest.raises(gate.GateError, match=message):
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


def test_sandbox_expiry_and_owner_live_annual_cadence_are_required(
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

    root = tmp_path / "monthly"
    source = qualified_source(root)
    mutate_claim(
        root,
        source,
        "merchant_live_owner_smoke_passed",
        lambda envelope: envelope["claims"].__setitem__("cadence", "monthly"),
    )
    with pytest.raises(gate.GateError, match="annual live purchase"):
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
