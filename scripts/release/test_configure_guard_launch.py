from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
sys.path.insert(0, str(ROOT / "scripts/release"))
import build_guard_owner_evidence as owner  # noqa: E402
import configure_guard_launch as configure  # noqa: E402
import guard_launch_gate as gate  # noqa: E402


IDENTITY = {
    "guard_release": "tinyzkp-guard-v1",
    "guard_version": "0.1.0",
    "guard_source_sha": "a" * 40,
    "engine_source_sha": "b" * 40,
    "compatibility_profile": gate.PROFILE_ID,
}
WORKFLOW_SOURCE_SHA = "c" * 40
ENGINE_CLAIMS = {
    "backend_gate_status": "qualified",
    "engine_release_tag": "backend-v0.1.0",
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
}


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def prepared_root(tmp_path: Path) -> Path:
    for relative in (
        "release/guard-launch-evidence-v2.json",
        "release/guard-launch-trust-v1.json",
        "release/guard-signing-trust-v1.json",
        "release/guard-signing-public-key.pem",
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    shutil.copytree(ROOT / "site", tmp_path / "site")
    (tmp_path / "legal").mkdir()
    (tmp_path / "legal/EULA.txt").write_text(
        "Final fixture EULA for LN Holdings test seller.\n"
        "Effective Date: 2026-07-21\n",
        encoding="utf-8",
    )
    (tmp_path / "legal/THIRD-PARTY-NOTICES.txt").write_text(
        "Final fixture dependency notices.\n", encoding="utf-8"
    )
    source = gate.load_json(
        tmp_path / "release/guard-launch-evidence-v2.json", "source"
    )
    source["release_identity"] = {
        **IDENTITY,
        "guard_version": None,
        "guard_source_sha": None,
        "engine_source_sha": None,
    }
    source["requested_commerce_state"] = "unconfigured"
    source["gates"] = {
        name: {
            "status": "blocked",
            "reason_code": gate.BLOCKED_REASONS[name],
            "evidence": [],
        }
        for name in gate.REQUIRED_GATES
    }
    source["prior_qualified_release"] = {
        "status": "blocked",
        "reason_code": gate.BLOCKED_REASONS[gate.PRIOR_QUALIFIED_RELEASE_GATE],
        "evidence": [],
    }
    trust_raw = (tmp_path / "release/guard-launch-trust-v1.json").read_bytes()
    source["trust_policy"]["sha256"] = hashlib.sha256(trust_raw).hexdigest()
    (tmp_path / "release/guard-launch-evidence-v2.json").write_bytes(
        gate.canonical_bytes(source)
    )
    return tmp_path


def configuration(root: Path) -> dict:
    date = "2026-07-21"
    custom = (
        "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-21&"
        "checkout%5Bcustom%5D%5Bguard_version%5D=0.1.0"
    )
    null_configuration = {
        "store_id": None,
        "product_id": None,
        "monthly_variant_id": None,
        "annual_variant_id": None,
        "monthly_checkout_url": None,
        "annual_checkout_url": None,
        "portal_url": None,
    }
    return {
        "schema_version": 1,
        "document_type": "GuardOwnerLaunchConfigurationV1",
        "expected_current_commerce_state": "unconfigured",
        "requested_commerce_state": "test_published",
        "release_change_class": "proof_critical",
        "release_identity": IDENTITY,
        "merchant": {
            "provider": "lemon_squeezy",
            "approval_status": "pending",
            "portal_state": "unconfigured",
            "portal_url": None,
            "catalog_policy": gate.MERCHANT_CATALOG_POLICY,
            "test_configuration": {
                "store_id": "101",
                "product_id": "201",
                "monthly_variant_id": "301",
                "annual_variant_id": "302",
                "monthly_checkout_url": (
                    "https://lnholdings.lemonsqueezy.com/checkout/buy/monthly-test?"
                    + custom
                ),
                "annual_checkout_url": (
                    "https://lnholdings.lemonsqueezy.com/checkout/buy/annual-test?"
                    + custom
                ),
                "portal_url": "https://lnholdings.lemonsqueezy.com/billing",
            },
            "live_configuration": null_configuration,
        },
        "legal_action": "approve_exact_repository_bytes",
        "legal_release_date": date,
    }


def successful_cosign(*args, **kwargs):
    return subprocess.CompletedProcess(args[0], 0, stdout="verified", stderr="")


def test_bootstrap_stages_identity_and_accepts_first_signed_gate(tmp_path: Path) -> None:
    root = prepared_root(tmp_path)
    config_path = root / "configuration.json"
    write_json(config_path, configuration(root))
    issued_at = datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    source = configure.apply_configuration(
        root=root,
        configuration_path=config_path,
        issued_at=issued_at,
    )
    staged = gate.derive(source, root=root)
    assert staged["launch"]["commerce_state"] == "test_published"
    assert staged["launch"]["checkout_enabled"] is False
    assert staged["launch"]["release_identity"] == IDENTITY

    claims = root / "engine-claims.json"
    claims.write_bytes(gate.canonical_bytes(ENGINE_CLAIMS))
    evidence = root / "release/evidence/guard-launch-v2/engine-first.json"
    owner.build_envelope(
        root=root,
        gate_name="engine_release_ready",
        claims_path=claims,
        issued_at_value=issued_at,
        workflow_source_sha=WORKFLOW_SOURCE_SHA,
        output=evidence,
    )
    bundle = evidence.with_name("engine-first.sigstore.json")
    bundle.write_bytes(gate.canonical_bytes({"bundle": "test"}))
    source = owner.attach_envelope(
        root=root,
        gate_name="engine_release_ready",
        evidence=evidence,
        signature=bundle,
    )
    signing_digest = hashlib.sha256(
        (root / gate.SIGNING_TRUST_PATH).read_bytes()
    ).hexdigest()
    derived = gate.derive(
        source,
        root=root,
        signature_runner=successful_cosign,
        cosign_path=Path("/opt/tinyzkp-test/cosign"),
        trusted_policy_sha256=source["trust_policy"]["sha256"],
        trusted_signing_policy_sha256=signing_digest,
    )
    assert derived["launch"]["gate_status"]["engine_release_ready"]["status"] == "passed"
    assert derived["launch"]["checkout_enabled"] is False


def test_freeze_attaches_exact_owner_signed_evidence(tmp_path: Path) -> None:
    root = prepared_root(tmp_path)
    source_path = root / "release/guard-launch-evidence-v2.json"
    source = gate.load_json(source_path, "source")
    source["requested_commerce_state"] = "public_live"
    source_path.write_bytes(gate.canonical_bytes(source))
    source_sha256 = gate.sha256_bytes(gate.canonical_bytes(source))
    write_json(
        root / "release/guard-launch-state-v2.json",
        {
            "commerce_state": "public_live",
            "launch_state": "qualified",
            "checkout_enabled": True,
            "source_sha256": source_sha256,
        },
    )
    before = gate.load_json(source_path, "source")
    evidence = root / "release/evidence/guard-launch-v2/sales-freeze.json"
    configure.build_freeze_envelope(
        root=root,
        issued_at="2026-07-21T12:00:00Z",
        workflow_source_sha=WORKFLOW_SOURCE_SHA,
        output=evidence,
    )
    signature = evidence.with_name("sales-freeze.sigstore.json")
    signature.write_bytes(gate.canonical_bytes({"bundle": "test"}))
    after = configure.freeze_sales(
        root=root,
        evidence=evidence,
        signature=signature,
    )
    assert after["requested_commerce_state"] == "sales_frozen"
    assert after["sales_freeze"]["status"] == "passed"
    assert after["sales_freeze"]["evidence"][0]["path"].endswith(
        "sales-freeze.json"
    )
    assert after["evaluated_at"] == before["evaluated_at"]
    unchanged = {
        key: value
        for key, value in after.items()
        if key not in {"requested_commerce_state", "sales_freeze"}
    }
    assert unchanged == {
        key: value
        for key, value in before.items()
        if key not in {"requested_commerce_state", "sales_freeze"}
    }
