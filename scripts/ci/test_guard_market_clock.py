import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

import guard_market_clock as market
import pytest


COSIGN = Path("/opt/tinyzkp-test/cosign")


def successful_cosign(*args, **kwargs):
    return subprocess.CompletedProcess(args[0], 0, stdout="verified", stderr="")


def blocked_source() -> dict:
    return market.load(market.SOURCE, "source")


def write_evidence(root: Path, source: dict, subject: str, claims: dict) -> None:
    kind, purpose, _reason = market.SUBJECTS[subject]
    envelope = {
        "schema_version": 1,
        "document_type": "GuardMarketEvidenceRecordV1",
        "evidence_kind": kind,
        "subject": subject,
        "result": "passed",
        "issued_at": "2026-07-17T12:00:00Z",
        "claims": claims,
    }
    raw = market.canonical(envelope)
    evidence_dir = root / "release" / "evidence" / "guard-market-v1"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / f"{subject}.json"
    path.write_bytes(raw)
    bundle = evidence_dir / f"{subject}.sigstore.json"
    bundle_raw = market.canonical({"bundle_for": hashlib.sha256(raw).hexdigest()})
    bundle.write_bytes(bundle_raw)
    source[subject] = {
        "status": "passed",
        "reason_code": None,
        "evidence": [
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "signature_path": bundle.relative_to(root).as_posix(),
                "signature_sha256": hashlib.sha256(bundle_raw).hexdigest(),
                "signer_id": "market-reviewer",
                "purpose": purpose,
            }
        ],
    }


def qualified_source(root: Path, announced_at: str = "2026-07-18T12:00:00Z") -> dict:
    source = blocked_source()
    trust = {
        "schema_version": 1,
        "document_type": "GuardLaunchTrustV1",
        "signers": [
            {
                "id": "market-reviewer",
                "purposes": sorted(market.launch.MARKET_TRUST_PURPOSES),
                "certificate_identity_regexp": "^https://reviewer.example/market$",
                "oidc_issuer": "https://issuer.example",
            }
        ],
    }
    trust_raw = market.canonical(trust)
    trust_path = root / "release" / "guard-market-trust-v1.json"
    trust_path.parent.mkdir(parents=True, exist_ok=True)
    trust_path.write_bytes(trust_raw)
    source["trust_policy"]["sha256"] = hashlib.sha256(trust_raw).hexdigest()
    write_evidence(
        root,
        source,
        "doctor_evaluation_release",
        {
            "release_tag": "doctor-eval-v1.0.0",
            "release_url": "https://github.com/example/tinyzkp/releases/tag/doctor-eval-v1.0.0",
            "engine_source_sha": "a" * 40,
            "engine_artifact_sha256": "b" * 64,
            "oci_digest": "sha256:" + "c" * 64,
            "schema_bundle_sha256": "d" * 64,
            "synthetic_job_sha256": "e" * 64,
            "published_at": "2026-07-17T12:00:00Z",
            "signature_verified": True,
            "attestation_verified": True,
            "exact_contract_doctor_command": True,
            "prerelease": True,
        },
    )
    write_evidence(
        root,
        source,
        "community_announcement",
        {
            "community": "plonky3",
            "announcement_url": "https://github.com/example/community/discussions/1",
            "announced_at": announced_at,
            "doctor_release_tag": "doctor-eval-v1.0.0",
            "moderator_approved": True,
            "announcement_count": 1,
            "direct_messages_sent": 0,
            "outbound_campaign": False,
            "recurring_campaign": False,
        },
    )
    return source


def derive(source: dict, root: Path) -> dict:
    return market.derive(
        source,
        root=root,
        trusted_policy_sha256=source["trust_policy"]["sha256"],
        signature_runner=successful_cosign,
        cosign_path=COSIGN,
    )


def test_checked_in_market_clock_is_closed_and_not_fabricated() -> None:
    source = blocked_source()
    result = market.derive(source)
    assert result["status"] == "not_started"
    assert result["started_at"] is None
    assert result["day_90_deadline"] is None
    assert result["six_month_stop_deadline"] is None
    assert result["initial_decision_date"] == "2026-10-16"
    assert market.OUTPUT.read_bytes() == market.canonical(result)


def test_clock_starts_only_from_signed_doctor_and_one_approved_announcement(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path)
    result = derive(source, tmp_path)
    assert result["status"] == "running"
    assert result["started_at"] == "2026-07-18T12:00:00Z"
    assert result["day_90_deadline"] == "2026-10-16T12:00:00Z"
    assert result["six_month_stop_deadline"] == "2027-01-18T12:00:00Z"

    source = qualified_source(tmp_path / "partial")
    source["community_announcement"] = blocked_source()["community_announcement"]
    result = derive(source, tmp_path / "partial")
    assert result["status"] == "not_started"


def test_phase_one_market_signer_can_start_clock_while_launch_stays_blocked(
    tmp_path: Path,
) -> None:
    market_source = qualified_source(tmp_path)
    market_result = derive(market_source, tmp_path)
    assert market_result["status"] == "running"

    launch_trust = market.launch.DEFAULT_SOURCE.parent / "guard-launch-trust-v1.json"
    target = tmp_path / "release" / "guard-launch-trust-v1.json"
    target.write_bytes(launch_trust.read_bytes())
    signing_trust = (
        market.launch.DEFAULT_SOURCE.parent / "guard-signing-trust-v1.json"
    )
    signing_target = tmp_path / "release" / "guard-signing-trust-v1.json"
    signing_target.write_bytes(signing_trust.read_bytes())
    configured_signing = market.launch.load_json(signing_trust, "signing trust")
    if configured_signing["status"] == "configured":
        key_source = (
            market.launch.DEFAULT_SOURCE.parents[1]
            / configured_signing["public_key_path"]
        )
        key_target = tmp_path / configured_signing["public_key_path"]
        key_target.parent.mkdir(parents=True, exist_ok=True)
        key_target.write_bytes(key_source.read_bytes())
    launch_source = market.launch.load_json(market.launch.DEFAULT_SOURCE, "launch")
    launch_result = market.launch.derive(launch_source, root=tmp_path)
    assert launch_result["launch"]["launch_state"] == "blocked"
    assert launch_result["launch"]["checkout_enabled"] is False


def test_late_announcement_does_not_relabel_initial_decision_as_day_90(
    tmp_path: Path,
) -> None:
    source = qualified_source(tmp_path, "2026-09-01T12:00:00Z")
    source["evaluated_at"] = "2026-09-01T12:00:00Z"
    result = derive(source, tmp_path)
    assert result["initial_decision_date"] == "2026-10-16"
    assert result["day_90_deadline"] == "2026-11-30T12:00:00Z"


def test_market_evidence_needs_external_trust_and_forbids_outbound(tmp_path: Path) -> None:
    source = qualified_source(tmp_path)
    try:
        market.derive(
            source,
            root=tmp_path,
            signature_runner=successful_cosign,
            cosign_path=COSIGN,
        )
        assert False, "missing external trust must fail"
    except market.MarketError as error:
        assert "independently protected" in str(error)

    unsafe = copy.deepcopy(source)
    unsafe["acquisition_policy"]["direct_messages_allowed"] = True
    try:
        derive(unsafe, tmp_path)
        assert False, "outbound acquisition must fail"
    except market.MarketError as error:
        assert "acquisition policy" in str(error)


def test_market_start_or_update_rejects_stale_and_future_evaluation_clock(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)
    for label, evaluated_at, message in (
        ("stale", "2026-07-17T11:59:59Z", "older than 24 hours"),
        ("future", "2026-07-18T12:00:01Z", "future-dated"),
    ):
        root = tmp_path / label
        source = qualified_source(root)
        source["evaluated_at"] = evaluated_at
        with pytest.raises(market.MarketError, match=message):
            market.derive(
                source,
                root=root,
                trusted_policy_sha256=source["trust_policy"]["sha256"],
                signature_runner=successful_cosign,
                cosign_path=COSIGN,
                require_current_evaluation=True,
                now=now,
            )
