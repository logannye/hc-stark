import copy
import hashlib
import json
from pathlib import Path

import pytest

import build_guard_publication as publication


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def fixture(tmp_path: Path, *, version: str = "0.1.0") -> tuple[Path, Path, dict]:
    identity = {
        "guard_release": "tinyzkp-guard-v1",
        "guard_version": version,
        "guard_source_sha": "a" * 40,
        "engine_source_sha": "b" * 40,
        "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
    }
    signed_identity = (
        f"tinyzkp-guard/{version}+guard.{'a' * 40}.engine.{'b' * 40}.artifact.{'c' * 64}"
    )
    base = f"https://github.com/logannye/hc-stark/releases/download/guard-v{version}"
    artifact = {
        "name": f"tinyzkp-guard-{version}-linux-x86_64.tar.gz",
        "url": f"{base}/tinyzkp-guard-{version}-linux-x86_64.tar.gz",
        "sha256": "c" * 64,
    }
    index = {
        "schema_version": 1,
        "product": "tinyzkp-guard",
        "current_release_identity": signed_identity,
        "releases": [
            {
                "guard_version": version,
                "release_identity": signed_identity,
                "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
                "release_date": "2026-07-21",
                "channel_url": f"{base}/guard-channel-v1.json",
                "channel_sha256": "d" * 64,
                "artifacts": [artifact],
                "state": "current",
                "successor_release_identity": None,
                "advisory_url": None,
            }
        ],
    }
    candidate = tmp_path / "candidate"
    write_json(candidate / "guard-release-index-v1.json", index)
    (candidate / "guard-release-index-v1.json.sig").write_bytes(b"signature\n")
    index_sha = hashlib.sha256((candidate / "guard-release-index-v1.json").read_bytes()).hexdigest()
    signature_sha = hashlib.sha256((candidate / "guard-release-index-v1.json.sig").read_bytes()).hexdigest()
    claims = {
        "artifact_url": artifact["url"],
        "artifact_sha256": artifact["sha256"],
        "channel_url": f"{base}/guard-channel-v1.json",
        "channel_identity_sha256": "d" * 64,
        "release_index_url": f"{base}/guard-release-index-v1.json",
        "release_index_sha256": index_sha,
        "release_index_signature_url": f"{base}/guard-release-index-v1.json.sig",
        "release_index_signature_sha256": signature_sha,
        "oci_digest": "sha256:" + "e" * 64,
    }
    evidence_path = tmp_path / "release/evidence/guard-launch-v2/guard.json"
    write_json(evidence_path, {"claims": claims})
    write_json(
        tmp_path / "release/guard-launch-evidence-v2.json",
        {"requested_commerce_state": "live_hidden"},
    )
    write_json(
        tmp_path / "release/guard-launch-state-v2.json",
        {
            "release_identity": identity,
            "commerce_state": "live_hidden",
            "checkout_enabled": False,
            "blocking_gates": ["guard_artifact_published"],
            "gate_status": {
                "guard_artifact_published": {"status": "blocked"},
                "guard_release_ready": {
                    "evidence": [
                        {"path": "release/evidence/guard-launch-v2/guard.json"}
                    ]
                },
            },
        },
    )
    channel = {
        "signed_release_identity": signed_identity,
        "url": claims["channel_url"],
        "sha256": claims["channel_identity_sha256"],
        "release_index_sha256": index_sha,
    }
    write_json(
        tmp_path / "site/release.json",
        {
            "guard_artifact_available": False,
            "guard_artifact_url": claims["artifact_url"],
            "guard_artifact_sha256": claims["artifact_sha256"],
            "channel_manifest": channel,
            "latest_release_index": None,
        },
    )
    write_json(
        tmp_path / "release/guard-candidate-build-authorization-v1.json",
        {
            "authorization_state": "candidate_prepared",
            "prior_qualified_release": None,
            "engine": {"oci_digest": "sha256:" + "f" * 64},
        },
    )
    return tmp_path, candidate, claims


def successor_fixture(tmp_path: Path) -> tuple[Path, Path, dict, str]:
    root, candidate, _old_claims = fixture(tmp_path)
    prior_index_path = candidate / "guard-release-index-v1.json"
    prior_index = json.loads(prior_index_path.read_text())
    prior_raw = prior_index_path.read_bytes()
    prior_sha = hashlib.sha256(prior_raw).hexdigest()
    site = root / "site"
    site.mkdir(exist_ok=True)
    (site / "guard-release-index-v1.json").write_bytes(prior_raw)
    (site / "guard-release-index-v1.json.sig").write_bytes(b"old signature\n")
    write_json(site / "guard-artifact-publication-v1.json", {"retained": True})
    write_json(
        site / "guard-artifact-publication-v1.sigstore.json", {"bundle": True}
    )

    version = "0.1.1"
    identity = {
        "guard_release": "tinyzkp-guard-v1",
        "guard_version": version,
        "guard_source_sha": "1" * 40,
        "engine_source_sha": "b" * 40,
        "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
    }
    signed_identity = (
        f"tinyzkp-guard/{version}+guard.{'1' * 40}.engine.{'b' * 40}.artifact.{'4' * 64}"
    )
    base = f"https://github.com/logannye/hc-stark/releases/download/guard-v{version}"
    artifact = {
        "name": f"tinyzkp-guard-{version}-linux-x86_64.tar.gz",
        "url": f"{base}/tinyzkp-guard-{version}-linux-x86_64.tar.gz",
        "sha256": "4" * 64,
    }
    prior_entry = copy.deepcopy(prior_index["releases"][0])
    prior_entry.update(
        {
            "state": "superseded",
            "successor_release_identity": signed_identity,
            "advisory_url": None,
        }
    )
    successor_entry = {
        "guard_version": version,
        "release_identity": signed_identity,
        "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
        "release_date": "2026-07-22",
        "channel_url": f"{base}/guard-channel-v1.json",
        "channel_sha256": "5" * 64,
        "artifacts": [artifact],
        "state": "current",
        "successor_release_identity": None,
        "advisory_url": None,
    }
    successor_index = {
        **prior_index,
        "current_release_identity": signed_identity,
        "releases": [prior_entry, successor_entry],
    }
    write_json(prior_index_path, successor_index)
    index_sha = hashlib.sha256(prior_index_path.read_bytes()).hexdigest()
    signature_sha = hashlib.sha256(
        (candidate / "guard-release-index-v1.json.sig").read_bytes()
    ).hexdigest()
    claims = {
        "artifact_url": artifact["url"],
        "artifact_sha256": artifact["sha256"],
        "channel_url": successor_entry["channel_url"],
        "channel_identity_sha256": successor_entry["channel_sha256"],
        "release_index_url": f"{base}/guard-release-index-v1.json",
        "release_index_sha256": index_sha,
        "release_index_signature_url": f"{base}/guard-release-index-v1.json.sig",
        "release_index_signature_sha256": signature_sha,
        "oci_digest": "sha256:" + "6" * 64,
    }
    write_json(root / "release/evidence/guard-launch-v2/guard.json", {"claims": claims})
    launch, _ = publication.load(root / "release/guard-launch-state-v2.json", "launch")
    launch["release_identity"] = identity
    write_json(root / "release/guard-launch-state-v2.json", launch)
    site_release, _ = publication.load(root / "site/release.json", "release")
    site_release.update(
        {
            "guard_artifact_url": artifact["url"],
            "guard_artifact_sha256": artifact["sha256"],
            "channel_manifest": {
                "signed_release_identity": signed_identity,
                "url": claims["channel_url"],
                "sha256": claims["channel_identity_sha256"],
                "release_index_sha256": index_sha,
            },
        }
    )
    write_json(root / "site/release.json", site_release)
    authorization, _ = publication.load(
        root / "release/guard-candidate-build-authorization-v1.json", "authorization"
    )
    authorization.update(
        {
            "release_change_class": "proof_critical",
            "prior_qualified_release": {
                "release_identity": prior_index["current_release_identity"],
                "release_index_sha256": prior_sha,
            },
        }
    )
    write_json(root / "release/guard-candidate-build-authorization-v1.json", authorization)
    return root, candidate, claims, prior_sha


def test_builds_strict_null_prior_publication_bound_to_exact_downloads(
    tmp_path: Path,
) -> None:
    root, candidate, claims = fixture(tmp_path)
    result = publication.build(
        root=root,
        candidate_dir=candidate,
        promotion_run_id="123456789",
        promotion_run_attempt=2,
        promotion_source_sha="1" * 40,
        workflow_source_sha="3" * 40,
        published_at="2026-07-21T12:00:00Z",
    )
    assert result["publication_kind"] == "initial_ga"
    assert result["prior_release_index_sha256"] is None
    assert result["release_index_sha256"] == claims["release_index_sha256"]
    assert result["workflow_source_sha"] == "3" * 40
    assert all(result["anonymous_checks"].values())


def test_first_publication_rejects_existing_prior_and_missing_index_binding(
    tmp_path: Path,
) -> None:
    root, candidate, _claims = fixture(tmp_path)
    (root / "site/guard-release-index-v1.json").write_text("{}")
    with pytest.raises(publication.PublicationError, match="strict null prior"):
        publication.build(
            root=root,
            candidate_dir=candidate,
            promotion_run_id="1",
            promotion_run_attempt=1,
            promotion_source_sha="1" * 40,
            workflow_source_sha="3" * 40,
            published_at="2026-07-21T12:00:00Z",
        )
    (root / "site/guard-release-index-v1.json").unlink()
    site_release, _ = publication.load(root / "site/release.json", "release")
    del site_release["channel_manifest"]["release_index_sha256"]
    write_json(root / "site/release.json", site_release)
    with pytest.raises(publication.PublicationError, match="differs"):
        publication.build(
            root=root,
            candidate_dir=candidate,
            promotion_run_id="1",
            promotion_run_attempt=1,
            promotion_source_sha="1" * 40,
            workflow_source_sha="3" * 40,
            published_at="2026-07-21T12:00:00Z",
        )


def test_publication_rejects_malformed_signing_workflow_source(tmp_path: Path) -> None:
    root, candidate, _claims = fixture(tmp_path)
    with pytest.raises(publication.PublicationError, match="promotion run identity"):
        publication.build(
            root=root,
            candidate_dir=candidate,
            promotion_run_id="1",
            promotion_run_attempt=1,
            promotion_source_sha="1" * 40,
            workflow_source_sha="main",
            published_at="2026-07-21T12:00:00Z",
        )


def test_builds_one_append_successor_bound_to_exact_prior(tmp_path: Path) -> None:
    root, candidate, claims, prior_sha = successor_fixture(tmp_path)
    result = publication.build(
        root=root,
        candidate_dir=candidate,
        promotion_run_id="123456790",
        promotion_run_attempt=1,
        promotion_source_sha="2" * 40,
        workflow_source_sha="3" * 40,
        published_at="2026-07-22T12:00:00Z",
    )
    assert result["publication_kind"] == "successor_ga"
    assert result["prior_release_index_sha256"] == prior_sha
    assert result["release_index_sha256"] == claims["release_index_sha256"]

    index, _ = publication.load(
        candidate / "guard-release-index-v1.json", "successor index"
    )
    index["releases"][0]["release_date"] = "2026-07-20"
    write_json(candidate / "guard-release-index-v1.json", index)
    changed_sha = hashlib.sha256(
        (candidate / "guard-release-index-v1.json").read_bytes()
    ).hexdigest()
    site_release, _ = publication.load(root / "site/release.json", "release")
    site_release["channel_manifest"]["release_index_sha256"] = changed_sha
    write_json(root / "site/release.json", site_release)
    evidence, _ = publication.load(
        root / "release/evidence/guard-launch-v2/guard.json", "Guard evidence"
    )
    evidence["claims"]["release_index_sha256"] = changed_sha
    write_json(root / "release/evidence/guard-launch-v2/guard.json", evidence)
    with pytest.raises(
        publication.guard_release_index.IndexError,
        match="prior current release incorrectly",
    ):
        publication.build(
            root=root,
            candidate_dir=candidate,
            promotion_run_id="123456790",
            promotion_run_attempt=1,
            promotion_source_sha="2" * 40,
            workflow_source_sha="3" * 40,
            published_at="2026-07-22T12:00:00Z",
        )


def test_request_public_live_changes_only_locked_state(tmp_path: Path) -> None:
    path = tmp_path / "source.json"
    original = {"requested_commerce_state": "live_hidden", "retained": {"x": 1}}
    write_json(path, copy.deepcopy(original))
    publication.request_public_live(path)
    value, _ = publication.load(path, "source")
    assert value == {**original, "requested_commerce_state": "public_live"}
