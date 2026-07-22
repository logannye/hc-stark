#!/usr/bin/env python3
"""Build a strict initial or successor GA publication record."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import guard_release_index  # noqa: E402
import strict_json  # noqa: E402


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class PublicationError(ValueError):
    pass


def load(path: Path, label: str) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
        value = strict_json.loads(raw)
    except (OSError, ValueError) as error:
        raise PublicationError(f"cannot read strict {label}: {error}") from error
    if not isinstance(value, dict):
        raise PublicationError(f"{label} must be an object")
    return value, raw


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(
    *,
    root: Path,
    candidate_dir: Path,
    promotion_run_id: str,
    promotion_run_attempt: int,
    promotion_source_sha: str,
    workflow_source_sha: str,
    published_at: str,
) -> dict:
    if re.fullmatch(r"[1-9][0-9]{0,19}", promotion_run_id) is None:
        raise PublicationError("promotion run ID is invalid")
    if (
        promotion_run_attempt < 1
        or not GIT_SHA_RE.fullmatch(promotion_source_sha)
        or not GIT_SHA_RE.fullmatch(workflow_source_sha)
    ):
        raise PublicationError("promotion run identity is invalid")
    try:
        timestamp = datetime.fromisoformat(published_at.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise PublicationError("published_at is invalid") from error
    if (
        not published_at.endswith("Z")
        or timestamp.tzinfo != timezone.utc
        or timestamp.microsecond
    ):
        raise PublicationError("published_at must be second-precision UTC")

    source, _ = load(root / "release/guard-launch-evidence-v2.json", "launch source")
    launch, _ = load(root / "release/guard-launch-state-v2.json", "launch state")
    release, _ = load(root / "site/release.json", "site release")
    authorization, _ = load(
        root / "release/guard-candidate-build-authorization-v1.json",
        "candidate authorization",
    )
    stable_paths = tuple(
        root / "site" / name
        for name in (
        "guard-release-index-v1.json",
        "guard-release-index-v1.json.sig",
        "guard-artifact-publication-v1.json",
        "guard-artifact-publication-v1.sigstore.json",
        )
    )
    prior = authorization.get("prior_qualified_release")
    prior_index: dict | None = None
    prior_index_sha256: str | None = None
    if prior is None:
        if any(path.exists() or path.is_symlink() for path in stable_paths):
            raise PublicationError("initial publication requires a strict null prior")
        publication_kind = "initial_ga"
    else:
        if not isinstance(prior, dict) or set(prior) != {
            "release_identity",
            "release_index_sha256",
        }:
            raise PublicationError("successor authorization prior binding differs")
        prior_index_sha256 = prior.get("release_index_sha256")
        if not isinstance(prior_index_sha256, str) or not SHA256_RE.fullmatch(
            prior_index_sha256
        ):
            raise PublicationError("successor authorization prior digest is invalid")
        if not all(path.is_file() and not path.is_symlink() for path in stable_paths):
            raise PublicationError("successor publication requires complete stable prior material")
        prior_index, prior_raw = load(stable_paths[0], "stable prior release index")
        if hashlib.sha256(prior_raw).hexdigest() != prior_index_sha256:
            raise PublicationError("stable prior index differs from authorization")
        publication_kind = "successor_ga"
    if (
        source.get("requested_commerce_state") != "live_hidden"
        or launch.get("commerce_state") != "live_hidden"
        or launch.get("checkout_enabled") is not False
        or launch.get("blocking_gates") != ["guard_artifact_published"]
        or launch.get("gate_status", {})
        .get("guard_artifact_published", {})
        .get("status")
        != "blocked"
        or release.get("guard_artifact_available") is not False
        or release.get("latest_release_index") is not None
        or authorization.get("authorization_state") != "candidate_prepared"
    ):
        raise PublicationError("source is not first-release promotion-ready")

    index_path = candidate_dir / "guard-release-index-v1.json"
    signature_path = candidate_dir / "guard-release-index-v1.json.sig"
    index_value, index_raw = load(index_path, "candidate release index")
    releases, by_identity = guard_release_index.validate_index(
        index_value, "candidate Guard release index"
    )
    identity = launch.get("release_identity")
    channel = release.get("channel_manifest")
    if not isinstance(identity, dict) or not isinstance(channel, dict):
        raise PublicationError("promotion-ready release identity is unavailable")
    signed_identity = channel.get("signed_release_identity")
    if (
        signed_identity not in by_identity
        or index_value.get("current_release_identity") != signed_identity
        or by_identity[signed_identity].get("guard_version") != identity.get("guard_version")
        or by_identity[signed_identity].get("channel_url") != channel.get("url")
        or by_identity[signed_identity].get("channel_sha256") != channel.get("sha256")
        or not any(
            artifact.get("url") == release.get("guard_artifact_url")
            and artifact.get("sha256") == release.get("guard_artifact_sha256")
            for artifact in by_identity[signed_identity].get("artifacts", [])
        )
        or digest(index_path) != channel.get("release_index_sha256")
    ):
        raise PublicationError("release index differs from promotion-ready identity")
    if prior_index is None:
        if len(releases) != 1:
            raise PublicationError("first release index must contain exactly one release")
    else:
        if authorization.get("release_change_class") not in {
            "guard_package_only",
            "proof_critical",
        }:
            raise PublicationError("successor publication requires a software release change")
        guard_release_index.validate_successor(
            prior_index,
            index_value,
            expected_new_identity=signed_identity,
        )
    guard_claim_evidence = launch.get("gate_status", {}).get(
        "guard_release_ready", {}
    ).get("evidence", [])
    if len(guard_claim_evidence) != 1:
        raise PublicationError("exact Guard readiness evidence is unavailable")
    guard_evidence, _ = load(
        root / guard_claim_evidence[0]["path"], "Guard readiness evidence"
    )
    claims = guard_evidence.get("claims")
    if not isinstance(claims, dict):
        raise PublicationError("Guard readiness claims are unavailable")
    engine = authorization.get("engine")
    if (
        digest(index_path) != claims.get("release_index_sha256")
        or digest(signature_path) != claims.get("release_index_signature_sha256")
        or not isinstance(engine, dict)
    ):
        raise PublicationError("downloaded publication bytes differ from signed evidence")

    return {
        "schema_version": 1,
        "document_type": "GuardArtifactPublicationV1",
        "authorization_policy": "owner_only_ga_v1",
        "qualification_basis": "owner_attested",
        "signer_id": "tinyzkp-artifact-publication-main",
        "purpose": "guard_launch:artifact_publication",
        "publication_kind": publication_kind,
        "promotion_repository": "logannye/hc-stark",
        "promotion_workflow": ".github/workflows/promote-guard-release.yml",
        "promotion_run_id": promotion_run_id,
        "promotion_run_attempt": promotion_run_attempt,
        "promotion_source_sha": promotion_source_sha,
        "workflow_source_sha": workflow_source_sha,
        "prior_release_index_sha256": prior_index_sha256,
        "published_at": published_at,
        "release_identity": identity,
        "guard_release_tag": f"guard-v{identity['guard_version']}",
        "artifact_url": claims["artifact_url"],
        "artifact_sha256": claims["artifact_sha256"],
        "channel_url": claims["channel_url"],
        "channel_sha256": claims["channel_identity_sha256"],
        "release_index_url": claims["release_index_url"],
        "release_index_sha256": claims["release_index_sha256"],
        "release_index_signature_url": claims["release_index_signature_url"],
        "release_index_signature_sha256": claims[
            "release_index_signature_sha256"
        ],
        "guard_oci_reference": (
            "ghcr.io/logannye/tinyzkp-guard@" + claims["oci_digest"]
        ),
        "guard_oci_digest": claims["oci_digest"],
        "engine_oci_reference": (
            "ghcr.io/logannye/tinyzkp-engine@" + engine["oci_digest"]
        ),
        "engine_oci_digest": engine["oci_digest"],
        "anonymous_checks": {
            "github_release_artifact": True,
            "github_release_channel": True,
            "github_release_index": True,
            "guard_oci_manifest": True,
            "engine_oci_manifest": True,
        },
    }


def request_public_live(path: Path) -> None:
    source, _ = load(path, "launch source")
    if source.get("requested_commerce_state") != "live_hidden":
        raise PublicationError("only live_hidden may request a public-live import")
    source["requested_commerce_state"] = "public_live"
    path.write_text(
        json.dumps(source, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    builder = subparsers.add_parser("build")
    builder.add_argument("--root", type=Path, default=ROOT)
    builder.add_argument("--candidate-dir", type=Path, required=True)
    builder.add_argument("--promotion-run-id", required=True)
    builder.add_argument("--promotion-run-attempt", type=int, required=True)
    builder.add_argument("--promotion-source-sha", required=True)
    builder.add_argument("--workflow-source-sha", required=True)
    builder.add_argument("--published-at", required=True)
    builder.add_argument("--output", type=Path, required=True)
    requester = subparsers.add_parser("request-public-live")
    requester.add_argument("--source", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            value = build(
                root=args.root,
                candidate_dir=args.candidate_dir,
                promotion_run_id=args.promotion_run_id,
                promotion_run_attempt=args.promotion_run_attempt,
                promotion_source_sha=args.promotion_source_sha,
                workflow_source_sha=args.workflow_source_sha,
                published_at=args.published_at,
            )
            args.output.write_text(
                json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        else:
            request_public_live(args.source)
    except (OSError, KeyError, PublicationError, guard_release_index.IndexError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
