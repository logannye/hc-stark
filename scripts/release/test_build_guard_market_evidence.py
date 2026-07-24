import copy
import hashlib
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import build_guard_market_evidence as owner  # noqa: E402
import guard_market_clock as market  # noqa: E402


DOCTOR_CLAIMS = {
    "release_tag": "doctor-eval-v0.1.0",
    "release_url": "https://github.com/logannye/hc-stark/releases/tag/doctor-eval-v0.1.0",
    "engine_source_sha": "a" * 40,
    "engine_artifact_sha256": "1" * 64,
    "oci_digest": "sha256:" + "2" * 64,
    "schema_bundle_sha256": "3" * 64,
    "synthetic_job_sha256": "4" * 64,
    "published_at": "2026-07-24T12:00:00Z",
    "signature_verified": True,
    "attestation_verified": True,
    "exact_contract_doctor_command": True,
    "prerelease": True,
}
ANNOUNCEMENT_CLAIMS = {
    "community": "plonky3",
    "announcement_url": "https://github.com/Plonky3/Plonky3/discussions/1",
    "announced_at": "2026-07-27T12:00:00Z",
    "doctor_release_tag": "doctor-eval-v0.1.0",
    "moderator_approved": True,
    "announcement_count": 1,
    "direct_messages_sent": 0,
    "outbound_campaign": False,
    "recurring_campaign": False,
}


def prepared_root(tmp_path: Path) -> Path:
    release = tmp_path / "release"
    release.mkdir(parents=True)
    source = market.load(market.SOURCE, "market source")
    source = copy.deepcopy(source)
    source["evaluated_at"] = "2026-07-18T12:00:00Z"
    for subject, (_kind, _purpose, reason) in market.SUBJECTS.items():
        source[subject] = {
            "status": "blocked",
            "reason_code": reason,
            "evidence": [],
        }
    trust = {
        "document_type": "GuardLaunchTrustV1",
        "schema_version": 1,
        "signers": [],
    }
    trust_raw = market.canonical(trust)
    source["trust_policy"] = {
        "path": "release/guard-market-trust-v1.json",
        "sha256": hashlib.sha256(trust_raw).hexdigest(),
    }
    (release / "guard-market-trust-v1.json").write_bytes(trust_raw)
    (release / "guard-market-evidence-v1.json").write_bytes(
        market.canonical(source)
    )
    return tmp_path


def claims_file(root: Path, name: str, claims: dict) -> Path:
    path = root / name
    path.write_bytes(market.canonical(claims))
    return path


def build_and_attach(
    root: Path, subject: str, claims: dict, issued_at: str
) -> tuple[Path, dict]:
    evidence = root / f"release/evidence/guard-market-v1/{subject}.json"
    owner.build_envelope(
        root=root,
        subject=subject,
        claims_path=claims_file(root, f"{subject}-claims.json", claims),
        issued_at_value=issued_at,
        output=evidence,
    )
    signature = evidence.with_name(f"{subject}.sigstore.json")
    signature.write_bytes(market.canonical({"bundle": "test-only"}))
    return evidence, owner.attach_envelope(
        root=root,
        subject=subject,
        evidence=evidence,
        signature=signature,
    )


def test_first_attachment_installs_exact_owner_trust_and_subject_reference(
    tmp_path: Path,
) -> None:
    root = prepared_root(tmp_path)
    evidence, source = build_and_attach(
        root,
        "doctor_evaluation_release",
        DOCTOR_CLAIMS,
        "2026-07-24T12:05:00Z",
    )
    trust = market.load(
        root / "release/guard-market-trust-v1.json", "market trust"
    )
    assert trust["signers"] == [owner.OWNER_SIGNER]
    assert source["trust_policy"]["sha256"] == hashlib.sha256(
        market.canonical(trust)
    ).hexdigest()
    record = source["doctor_evaluation_release"]
    assert record["status"] == "passed"
    assert record["reason_code"] is None
    assert record["evidence"][0]["path"] == (
        "release/evidence/guard-market-v1/doctor_evaluation_release.json"
    )
    assert record["evidence"][0]["sha256"] == hashlib.sha256(
        evidence.read_bytes()
    ).hexdigest()
    assert record["evidence"][0]["signer_id"] == owner.OWNER_SIGNER_ID
    assert record["evidence"][0]["purpose"] == (
        "guard_market:doctor_evaluation_release"
    )


def test_announcement_requires_doctor_and_reuses_exact_trust(tmp_path: Path) -> None:
    root = prepared_root(tmp_path)
    claims = claims_file(root, "announcement.json", ANNOUNCEMENT_CLAIMS)
    evidence = root / "release/evidence/guard-market-v1/announcement.json"
    owner.build_envelope(
        root=root,
        subject="community_announcement",
        claims_path=claims,
        issued_at_value="2026-07-27T12:05:00Z",
        output=evidence,
    )
    signature = evidence.with_name("announcement.sigstore.json")
    signature.write_bytes(market.canonical({"bundle": "test-only"}))
    with pytest.raises(owner.EvidenceError, match="cannot precede doctor"):
        owner.attach_envelope(
            root=root,
            subject="community_announcement",
            evidence=evidence,
            signature=signature,
        )

    root = prepared_root(tmp_path / "sequenced")
    build_and_attach(
        root,
        "doctor_evaluation_release",
        DOCTOR_CLAIMS,
        "2026-07-24T12:05:00Z",
    )
    _announcement, source = build_and_attach(
        root,
        "community_announcement",
        ANNOUNCEMENT_CLAIMS,
        "2026-07-27T12:05:00Z",
    )
    assert source["community_announcement"]["status"] == "passed"
    trust = market.load(
        root / "release/guard-market-trust-v1.json", "market trust"
    )
    assert trust["signers"] == [owner.OWNER_SIGNER]


def test_rejects_replacement_outside_path_and_malformed_claims(
    tmp_path: Path,
) -> None:
    root = prepared_root(tmp_path)
    build_and_attach(
        root,
        "doctor_evaluation_release",
        DOCTOR_CLAIMS,
        "2026-07-24T12:05:00Z",
    )
    with pytest.raises(owner.EvidenceError, match="cannot replace"):
        owner.build_envelope(
            root=root,
            subject="doctor_evaluation_release",
            claims_path=claims_file(root, "again.json", DOCTOR_CLAIMS),
            issued_at_value="2026-07-24T12:10:00Z",
            output=root / "release/evidence/guard-market-v1/again.json",
        )

    fresh = prepared_root(tmp_path / "fresh")
    with pytest.raises(owner.EvidenceError, match="outside the repository"):
        owner.build_envelope(
            root=fresh,
            subject="doctor_evaluation_release",
            claims_path=claims_file(fresh, "claims.json", DOCTOR_CLAIMS),
            issued_at_value="2026-07-24T12:05:00Z",
            output=tmp_path.parent / "outside.json",
        )
    malformed = fresh / "malformed.json"
    malformed.write_text(
        '{"release_tag":"doctor-eval-v0.1.0","release_tag":"duplicate"}',
        encoding="utf-8",
    )
    with pytest.raises(owner.EvidenceError, match="strict JSON"):
        owner.build_envelope(
            root=fresh,
            subject="doctor_evaluation_release",
            claims_path=malformed,
            issued_at_value="2026-07-24T12:05:00Z",
            output=fresh / "release/evidence/guard-market-v1/malformed.json",
        )
