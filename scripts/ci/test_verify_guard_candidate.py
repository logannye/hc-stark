import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile

import pytest

import verify_guard_candidate as verifier


IDENTITY = {
    "guard_version": "1.0.0",
    "guard_source_sha": "a" * 40,
    "engine_source_sha": "b" * 40,
    "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
}
ENGINE_ARTIFACT = "c" * 64
RELEASE_IDENTITY = verifier.expected_release_identity(IDENTITY, ENGINE_ARTIFACT)
PUBLIC_AUTHORIZATION_COMMIT = "f" * 40


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def add_bytes(archive, name, raw):
    member = tarfile.TarInfo(name)
    member.size = len(raw)
    member.mode = 0o644
    archive.addfile(member, io.BytesIO(raw))


def authorization_fixture(state: str, public_commit):
    return {
        "schema_version": 1,
        "document_type": "GuardCandidateBuildAuthorizationV1",
        "authorization_state": state,
        "authorization_scope": "prepare_signed_guard_draft_only",
        "commercial_release_authorized": False,
        "checkout_enabled": False,
        "public_gate_source_sha256": "1" * 64,
        "release_change_class": "proof_critical",
        "prior_qualified_release": None,
        "public_candidate_authorization_commit": public_commit,
        "release_identity": {
            "guard_release": "tinyzkp-guard-v1",
            **IDENTITY,
        },
        "expected_public_candidate_tag": "guard-v1.0.0",
        "engine": {"identity": "engine"},
        "compatibility_profile": IDENTITY["compatibility_profile"],
        "legal_artifacts": {"identity": "legal"},
        "merchant_catalog": {"identity": "catalog"},
        "signing_trust": {"identity": "signing"},
        "reviewed_evidence": {
            "launch_evidence_sha256": "1" * 64,
            "launch_trust_policy_sha256": "2" * 64,
            "required_passed_gates": [
                "engine_release_ready",
                "legal_terms_approved",
                "merchant_sandbox_lifecycle_passed",
                "release_rehearsal_within_budget",
            ],
        },
        "remaining_launch_blockers": ["guard_artifact_published"],
    }


def oci_fixture(
    path: Path,
    *,
    release_identity: str = RELEASE_IDENTITY,
    extra_labels: dict[str, str] | None = None,
):
    labels = {
        "org.opencontainers.image.title": "TinyZKP Guard",
        "org.opencontainers.image.source": "https://github.com/logannye/hc-stark",
        "org.opencontainers.image.version": IDENTITY["guard_version"],
        "org.opencontainers.image.revision": IDENTITY["guard_source_sha"],
        "org.opencontainers.image.tinyzkp.release-identity": release_identity,
        "org.opencontainers.image.tinyzkp.engine-revision": IDENTITY[
            "engine_source_sha"
        ],
        "org.opencontainers.image.tinyzkp.engine-artifact-sha256": ENGINE_ARTIFACT,
        "org.opencontainers.image.tinyzkp.profile": IDENTITY[
            "compatibility_profile"
        ],
    }
    labels.update(extra_labels or {})
    config_raw = canonical(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {"Labels": labels},
        }
    )
    config_digest = hashlib.sha256(config_raw).hexdigest()
    manifest_raw = canonical(
        {
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{config_digest}",
                "size": len(config_raw),
            },
            "layers": [],
        }
    )
    manifest_digest = hashlib.sha256(manifest_raw).hexdigest()
    index_raw = canonical(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{manifest_digest}",
                    "size": len(manifest_raw),
                }
            ],
        }
    )
    with tarfile.open(path, "w") as archive:
        add_bytes(archive, "index.json", index_raw)
        add_bytes(archive, f"blobs/sha256/{config_digest}", config_raw)
        add_bytes(archive, f"blobs/sha256/{manifest_digest}", manifest_raw)
    return {
        "guard_version": IDENTITY["guard_version"],
        "guard_source_sha": IDENTITY["guard_source_sha"],
        "engine_source_sha": IDENTITY["engine_source_sha"],
        "engine_artifact_sha256": ENGINE_ARTIFACT,
        "release_identity": RELEASE_IDENTITY,
        "oci_digest": f"sha256:{manifest_digest}",
    }


def test_exact_oci_archive_identity_is_accepted(tmp_path):
    archive = tmp_path / "guard.oci.tar"
    channel = oci_fixture(archive)
    verifier.verify_oci(archive, channel, IDENTITY)


def test_oci_archive_with_different_embedded_release_is_rejected(tmp_path):
    archive = tmp_path / "guard.oci.tar"
    channel = oci_fixture(archive, release_identity="tinyzkp-guard/wrong")
    with pytest.raises(verifier.CandidateError, match="OCI labels differ"):
        verifier.verify_oci(archive, channel, IDENTITY)


def test_oci_archive_cannot_embed_a_mutable_launch_state(tmp_path):
    archive = tmp_path / "guard.oci.tar"
    channel = oci_fixture(
        archive,
        extra_labels={
            "org.opencontainers.image.tinyzkp.qualification": "public_live"
        },
    )
    with pytest.raises(verifier.CandidateError, match="OCI labels differ"):
        verifier.verify_oci(archive, channel, IDENTITY)


def test_candidate_authorization_a_is_bound_to_promotion_evidence_b():
    build = authorization_fixture("authorized", None)
    promotion = authorization_fixture(
        "candidate_prepared", PUBLIC_AUTHORIZATION_COMMIT
    )
    verifier.verify_build_authorization(
        build, promotion, PUBLIC_AUTHORIZATION_COMMIT
    )


def test_candidate_authorization_a_cannot_differ_on_immutable_input():
    build = authorization_fixture("authorized", None)
    promotion = authorization_fixture(
        "candidate_prepared", PUBLIC_AUTHORIZATION_COMMIT
    )
    build["merchant_catalog"] = {"identity": "different"}
    with pytest.raises(verifier.CandidateError, match="immutable build inputs"):
        verifier.verify_build_authorization(
            build, promotion, PUBLIC_AUTHORIZATION_COMMIT
        )


def index_entry(
    version: str,
    release_identity: str,
    *,
    state: str = "current",
    successor=None,
):
    base = (
        "https://github.com/logannye/hc-stark/releases/download/"
        f"guard-v{version}"
    )
    return {
        "guard_version": version,
        "release_identity": release_identity,
        "compatibility_profile": IDENTITY["compatibility_profile"],
        "release_date": "2026-07-18",
        "channel_url": f"{base}/guard-channel-v1.json",
        "channel_sha256": "7" * 64,
        "artifacts": [
            {
                "name": "guard.tar.gz",
                "url": f"{base}/guard.tar.gz",
                "sha256": "8" * 64,
            }
        ],
        "state": state,
        "successor_release_identity": successor,
        "advisory_url": None,
    }


def test_first_ga_index_cannot_smuggle_prior_history():
    channel = {
        "guard_version": IDENTITY["guard_version"],
        "release_identity": RELEASE_IDENTITY,
        "compatibility_profile": IDENTITY["compatibility_profile"],
        "release_date": "2026-07-18",
    }
    artifact_map = {"guard.tar.gz": {"sha256": "8" * 64}}
    current = index_entry(IDENTITY["guard_version"], RELEASE_IDENTITY)
    index = {
        "schema_version": 1,
        "product": "tinyzkp-guard",
        "current_release_identity": RELEASE_IDENTITY,
        "releases": [current],
    }
    verifier.verify_index(
        index,
        channel,
        "7" * 64,
        artifact_map,
        prior_index=None,
        prior_index_sha256=None,
        expected_prior_identity=None,
    )
    index["releases"].insert(
        0,
        index_entry(
            "0.9.0",
            "tinyzkp-guard/prior",
            state="superseded",
            successor=RELEASE_IDENTITY,
        ),
    )
    with pytest.raises(verifier.CandidateError, match="first Guard GA"):
        verifier.verify_index(
            index,
            channel,
            "7" * 64,
            artifact_map,
            prior_index=None,
            prior_index_sha256=None,
            expected_prior_identity=None,
        )


def test_successor_index_preserves_every_prior_entry():
    prior_identity = "tinyzkp-guard/prior"
    older_identity = "tinyzkp-guard/older"
    prior_entries = [
        index_entry(
            "0.8.0",
            older_identity,
            state="superseded",
            successor=prior_identity,
        ),
        index_entry("0.9.0", prior_identity),
    ]
    prior = {
        "schema_version": 1,
        "product": "tinyzkp-guard",
        "current_release_identity": prior_identity,
        "releases": prior_entries,
    }
    successor_entries = copy.deepcopy(prior_entries)
    successor_entries[-1]["state"] = "superseded"
    successor_entries[-1]["successor_release_identity"] = RELEASE_IDENTITY
    successor_entries.append(index_entry("1.0.0", RELEASE_IDENTITY))
    successor = {
        "schema_version": 1,
        "product": "tinyzkp-guard",
        "current_release_identity": RELEASE_IDENTITY,
        "releases": successor_entries,
    }
    channel = {
        "guard_version": "1.0.0",
        "release_identity": RELEASE_IDENTITY,
        "compatibility_profile": IDENTITY["compatibility_profile"],
        "release_date": "2026-07-18",
    }
    verifier.verify_index(
        successor,
        channel,
        "7" * 64,
        {"guard.tar.gz": {"sha256": "8" * 64}},
        prior_index=prior,
        prior_index_sha256="9" * 64,
        expected_prior_identity=prior_identity,
    )
    successor["releases"].pop(0)
    with pytest.raises(verifier.CandidateError, match="prior Guard release index"):
        verifier.verify_index(
            successor,
            channel,
            "7" * 64,
            {"guard.tar.gz": {"sha256": "8" * 64}},
            prior_index=prior,
            prior_index_sha256="9" * 64,
            expected_prior_identity=prior_identity,
        )
