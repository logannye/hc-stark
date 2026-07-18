#!/usr/bin/env python3
"""Verify one already-built Guard draft against the reviewed public gate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
from typing import Any
from urllib.parse import quote, urlparse


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MERCHANT_CATALOG_POLICY = {
    "monthly_price_usd": 499,
    "annual_price_usd": 4990,
    "annual_default": True,
    "annual_emphasized": True,
    "entitlement_mode": "lemon_squeezy_subscription_license_keys",
    "machine_activation_limit": None,
    "trials_allowed": False,
    "coupons_allowed": False,
    "usage_metering": False,
    "add_ons_allowed": False,
    "subscription_pause_offered": False,
    "enterprise_variants_allowed": False,
    "cancel_at_period_end": True,
    "portal_enabled": True,
    "dunning_enabled": True,
    "invoices_enabled": True,
}
SOURCE_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
GUARD_SCHEMA_NAMES = {
    "job-manifest-v1.schema.json",
    "doctor-report-v1.schema.json",
    "compatibility-report-v1.schema.json",
    "reason-v1.schema.json",
    "error-envelope-v1.schema.json",
    "progress-event-v1.schema.json",
    "job-result-v1.schema.json",
    "support-report-v1.schema.json",
    "job-inspect-result-v1.schema.json",
    "guard-channel-v1.schema.json",
    "guard-release-index-v1.schema.json",
    "policy-baseline-v1.schema.json",
    "compatibility-manifest-v1.schema.json",
}
FIXED_CANDIDATE_FILES = {
    "SHA256SUMS",
    "SHA256SUMS.sig",
    "guard-channel-v1.json",
    "guard-channel-v1.json.sig",
    "guard-release-index-v1.json",
    "guard-release-index-v1.json.sig",
    "signing-public-key.pem",
}
SIGNATURE_FILES = {
    "SHA256SUMS.sig",
    "guard-channel-v1.json.sig",
    "guard-release-index-v1.json.sig",
}
BUILD_AUTHORIZATION_NAME = "guard-candidate-build-authorization-v1.json"


class CandidateError(ValueError):
    """The draft is not the exact reviewed candidate."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"cannot read strict JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CandidateError(f"{path} must contain an object")
    return value


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise CandidateError(f"{label} fields differ")
    return value


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def candidate_file(directory: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise CandidateError("candidate filename is unsafe")
    path = directory / name
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise CandidateError(f"candidate file is unsafe or unavailable: {name}")
    return path


def expected_release_identity(identity: dict[str, Any], artifact_sha256: str) -> str:
    return (
        f"tinyzkp-guard/{identity['guard_version']}"
        f"+guard.{identity['guard_source_sha']}"
        f".engine.{identity['engine_source_sha']}"
        f".artifact.{artifact_sha256}"
    )


def verify_checksum_inventory(
    candidate_dir: Path, expected_files: set[str]
) -> None:
    lines = candidate_file(candidate_dir, "SHA256SUMS").read_text(
        encoding="utf-8"
    ).splitlines()
    observed: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise CandidateError("SHA256SUMS contains a malformed line")
        checksum, name = match.groups()
        if Path(name).name != name or name in observed:
            raise CandidateError("SHA256SUMS contains an unsafe or duplicate name")
        observed[name] = checksum
    expected_covered = expected_files - SIGNATURE_FILES - {"SHA256SUMS"}
    if set(observed) != expected_covered:
        raise CandidateError("SHA256SUMS inventory differs from candidate contract")
    for name, expected in observed.items():
        if digest(candidate_file(candidate_dir, name)) != expected:
            raise CandidateError(f"SHA256SUMS differs for {name}")


def read_oci_json(
    archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str
) -> tuple[dict[str, Any], bytes]:
    member = members.get(name)
    if member is None or not member.isfile() or member.size > 16 * 1024 * 1024:
        raise CandidateError(f"OCI archive member is unavailable: {name}")
    handle = archive.extractfile(member)
    if handle is None:
        raise CandidateError(f"OCI archive member cannot be read: {name}")
    raw = handle.read()
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"OCI JSON is malformed: {name}") from exc
    if not isinstance(value, dict):
        raise CandidateError(f"OCI JSON must be an object: {name}")
    return value, raw


def verify_oci(
    path: Path,
    channel: dict[str, Any],
    identity: dict[str, Any],
) -> None:
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members_list = archive.getmembers()
            if any(member.issym() or member.islnk() for member in members_list):
                raise CandidateError("OCI archive contains a link")
            members = {member.name: member for member in members_list}
            if len(members) != len(members_list):
                raise CandidateError("OCI archive contains duplicate paths")
            index, _ = read_oci_json(archive, members, "index.json")
            manifests = index.get("manifests")
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise CandidateError("OCI index must contain exactly one manifest")
            descriptor = manifests[0]
            if not isinstance(descriptor, dict):
                raise CandidateError("OCI manifest descriptor is malformed")
            manifest_digest = descriptor.get("digest")
            if manifest_digest != channel["oci_digest"]:
                raise CandidateError("OCI archive digest differs from Guard channel")
            manifest_name = f"blobs/sha256/{manifest_digest.removeprefix('sha256:')}"
            manifest, manifest_raw = read_oci_json(archive, members, manifest_name)
            if "sha256:" + hashlib.sha256(manifest_raw).hexdigest() != manifest_digest:
                raise CandidateError("OCI manifest blob digest differs")
            config_descriptor = manifest.get("config")
            if not isinstance(config_descriptor, dict):
                raise CandidateError("OCI config descriptor is malformed")
            config_digest = config_descriptor.get("digest")
            if not isinstance(config_digest, str) or not OCI_RE.fullmatch(config_digest):
                raise CandidateError("OCI config digest is malformed")
            config_name = f"blobs/sha256/{config_digest.removeprefix('sha256:')}"
            config, config_raw = read_oci_json(archive, members, config_name)
            if "sha256:" + hashlib.sha256(config_raw).hexdigest() != config_digest:
                raise CandidateError("OCI config blob digest differs")
    except (OSError, tarfile.TarError) as exc:
        raise CandidateError("OCI archive is malformed") from exc

    if config.get("architecture") != "amd64" or config.get("os") != "linux":
        raise CandidateError("OCI platform is not linux/amd64")
    labels = config.get("config", {}).get("Labels")
    expected_labels = {
        "org.opencontainers.image.title": "TinyZKP Guard",
        "org.opencontainers.image.source": "https://github.com/logannye/hc-stark",
        "org.opencontainers.image.version": channel["guard_version"],
        "org.opencontainers.image.revision": channel["guard_source_sha"],
        "org.opencontainers.image.tinyzkp.release-identity": channel[
            "release_identity"
        ],
        "org.opencontainers.image.tinyzkp.engine-revision": channel[
            "engine_source_sha"
        ],
        "org.opencontainers.image.tinyzkp.engine-artifact-sha256": channel[
            "engine_artifact_sha256"
        ],
        "org.opencontainers.image.tinyzkp.profile": identity[
            "compatibility_profile"
        ],
    }
    if labels != expected_labels:
        raise CandidateError("OCI labels differ from reviewed release identity")


def verify_legal_bundle(
    path: Path, eula_sha256: str, notices_sha256: str
) -> None:
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = archive.getmembers()
            if any(member.issym() or member.islnk() for member in members):
                raise CandidateError("Guard tarball contains a link")
            for suffix, expected in (
                ("/legal/EULA.txt", eula_sha256),
                ("/legal/THIRD-PARTY-NOTICES.txt", notices_sha256),
            ):
                matches = [
                    member
                    for member in members
                    if member.name.endswith(suffix) and member.isfile()
                ]
                if len(matches) != 1 or matches[0].size > 4 * 1024 * 1024:
                    raise CandidateError(f"Guard tarball legal file differs: {suffix}")
                handle = archive.extractfile(matches[0])
                if handle is None or hashlib.sha256(handle.read()).hexdigest() != expected:
                    raise CandidateError(f"Guard tarball legal digest differs: {suffix}")
    except (OSError, tarfile.TarError) as exc:
        raise CandidateError("Guard tarball is malformed") from exc


def verify_provenance(
    provenance: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    authorization: dict[str, Any],
    channel: dict[str, Any],
    build_authorization_sha256: str,
) -> None:
    if (
        provenance.get("_type") != "https://in-toto.io/Statement/v1"
        or provenance.get("predicateType") != "https://slsa.dev/provenance/v1"
    ):
        raise CandidateError("Guard provenance type differs")
    provenance_name = "provenance.intoto.json"
    expected_subjects = {
        name: descriptor["sha256"]
        for name, descriptor in artifacts.items()
        if name != provenance_name
    }
    subjects = provenance.get("subject")
    observed_subjects: dict[str, str] = {}
    if not isinstance(subjects, list):
        raise CandidateError("Guard provenance subjects are malformed")
    for subject in subjects:
        if (
            not isinstance(subject, dict)
            or set(subject) != {"name", "digest"}
            or not isinstance(subject["digest"], dict)
            or set(subject["digest"]) != {"sha256"}
            or subject["name"] in observed_subjects
        ):
            raise CandidateError("Guard provenance subject is malformed")
        observed_subjects[subject["name"]] = subject["digest"]["sha256"]
    if observed_subjects != expected_subjects:
        raise CandidateError("Guard provenance subjects differ from channel artifacts")

    predicate = provenance.get("predicate")
    build = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    run = predicate.get("runDetails") if isinstance(predicate, dict) else None
    if not isinstance(build, dict) or not isinstance(run, dict):
        raise CandidateError("Guard provenance predicate is malformed")
    external = build.get("externalParameters")
    expected_external = {
        "candidate_authorization_sha256": build_authorization_sha256,
        "compatibility_profile": authorization["compatibility_profile"],
        "catalog_policy": authorization["merchant_catalog"]["catalog_policy"],
        "eula_sha256": authorization["legal_artifacts"]["eula_sha256"],
        "engine_artifact_sha256": authorization["engine"]["artifact_sha256"],
        "engine_release_tag": authorization["engine"]["candidate_tag"],
        "engine_source_sha": authorization["engine"]["source_sha"],
        "guard_source_sha": authorization["release_identity"]["guard_source_sha"],
        "guard_version": authorization["release_identity"]["guard_version"],
        "notices_sha256": authorization["legal_artifacts"]["notices_sha256"],
        "public_candidate_authorization_commit": authorization[
            "public_candidate_authorization_commit"
        ],
        "release_change_class": authorization["release_change_class"],
        "prior_qualified_release_identity": (
            authorization["prior_qualified_release"]["release_identity"]
            if authorization["prior_qualified_release"] is not None
            else None
        ),
        "prior_release_index_sha256": (
            authorization["prior_qualified_release"]["release_index_sha256"]
            if authorization["prior_qualified_release"] is not None
            else None
        ),
        "public_contracts_git_revision": authorization["engine"][
            "public_contracts_git_revision"
        ],
        "release_date": authorization["legal_artifacts"]["release_date"],
    }
    if external != expected_external:
        raise CandidateError("Guard provenance external parameters differ")
    internal = build.get("internalParameters")
    if isinstance(internal, dict):
        exact(
            internal,
            {
                "commercial_release_authorized",
                "qualification",
                "merchant_catalog",
            },
            "Guard provenance internal parameters",
        )
    if (
        not isinstance(internal, dict)
        or internal.get("commercial_release_authorized") is not False
        or internal.get("qualification") != "candidate_build_authorized"
        or internal.get("merchant_catalog") != channel["merchant_catalog"]
    ):
        raise CandidateError(
            "Guard provenance is not a noncommercial candidate-authorized draft"
        )
    builder = run.get("builder") if isinstance(run, dict) else None
    invocation = run.get("metadata", {}).get("invocationId")
    expected_builder_suffix = (
        "/.github/workflows/release-ga.yml@"
        + authorization["release_identity"]["guard_source_sha"]
    )
    if (
        not isinstance(builder, dict)
        or not isinstance(builder.get("id"), str)
        or not builder["id"].startswith("https://github.com/")
        or not builder["id"].endswith(expected_builder_suffix)
        or not isinstance(invocation, str)
        or not invocation.startswith("https://github.com/")
    ):
        raise CandidateError("Guard provenance builder identity differs")


def verify_build_authorization(
    build_authorization: dict[str, Any],
    promotion_authorization: dict[str, Any],
    public_candidate_authorization_commit: str,
) -> None:
    fields = {
        "schema_version",
        "document_type",
        "authorization_state",
        "authorization_scope",
        "commercial_release_authorized",
        "checkout_enabled",
        "public_gate_source_sha256",
        "release_change_class",
        "prior_qualified_release",
        "public_candidate_authorization_commit",
        "release_identity",
        "expected_public_candidate_tag",
        "engine",
        "compatibility_profile",
        "legal_artifacts",
        "merchant_catalog",
        "signing_trust",
        "reviewed_evidence",
        "remaining_launch_blockers",
    }
    exact(build_authorization, fields, "candidate-build authorization A")
    exact(promotion_authorization, fields, "promotion authorization B")
    stable_fields = {
        "schema_version",
        "document_type",
        "authorization_scope",
        "commercial_release_authorized",
        "checkout_enabled",
        "release_change_class",
        "prior_qualified_release",
        "release_identity",
        "expected_public_candidate_tag",
        "engine",
        "compatibility_profile",
        "legal_artifacts",
        "merchant_catalog",
        "signing_trust",
    }
    if any(
        build_authorization[field] != promotion_authorization[field]
        for field in stable_fields
    ):
        raise CandidateError(
            "candidate authorization A and promotion evidence B differ "
            "on immutable build inputs"
        )
    for value, label in (
        (build_authorization, "candidate authorization A"),
        (promotion_authorization, "promotion authorization B"),
    ):
        reviewed = value.get("reviewed_evidence")
        if (
            not isinstance(reviewed, dict)
            or value["public_gate_source_sha256"]
            != reviewed.get("launch_evidence_sha256")
            or not SHA256_RE.fullmatch(value["public_gate_source_sha256"])
        ):
            raise CandidateError(f"{label} source/evidence digest differs")
        change_class = value["release_change_class"]
        prior = value["prior_qualified_release"]
        if change_class not in {"proof_critical", "guard_package_only"}:
            raise CandidateError(f"{label} release change class differs")
        if prior is not None:
            exact(
                prior,
                {"release_identity", "release_index_sha256"},
                f"{label} prior qualified release",
            )
            if (
                not isinstance(prior["release_identity"], str)
                or not prior["release_identity"].startswith("tinyzkp-guard/")
                or not SHA256_RE.fullmatch(prior["release_index_sha256"])
            ):
                raise CandidateError(f"{label} prior qualified release is malformed")
        if change_class == "guard_package_only" and prior is None:
            raise CandidateError(
                f"{label} Guard/package release requires a qualified predecessor"
            )
    for field in ("launch_trust_policy_sha256", "required_passed_gates"):
        if (
            build_authorization["reviewed_evidence"].get(field)
            != promotion_authorization["reviewed_evidence"].get(field)
        ):
            raise CandidateError(
                "candidate authorization A and promotion evidence B differ "
                "on immutable reviewed evidence"
            )
    if (
        build_authorization["authorization_state"] != "authorized"
        or build_authorization["public_candidate_authorization_commit"] is not None
        or promotion_authorization["authorization_state"] != "candidate_prepared"
        or promotion_authorization["public_candidate_authorization_commit"]
        != public_candidate_authorization_commit
        or build_authorization["commercial_release_authorized"] is not False
        or build_authorization["checkout_enabled"] is not False
    ):
        raise CandidateError(
            "candidate authorization A and promotion evidence B sequencing differs"
        )


def verify_version(version: dict[str, Any], channel: dict[str, Any]) -> None:
    exact(
        version,
        {
            "schema_version",
            "product",
            "release",
            "compatibility_profile",
            "merchant_catalog",
            "artifact_class",
        },
        "Guard version",
    )
    release = exact(
        version["release"],
        {
            "guard_version",
            "guard_source_identity",
            "engine_source_identity",
            "engine_artifact_sha256",
            "release_identity",
            "compatibility_profile",
            "qualification",
        },
        "Guard version release identity",
    )
    expected_release = {
        "guard_version": channel["guard_version"],
        "guard_source_identity": channel["guard_source_sha"],
        "engine_source_identity": channel["engine_source_sha"],
        "engine_artifact_sha256": channel["engine_artifact_sha256"],
        "release_identity": channel["release_identity"],
        "compatibility_profile": channel["compatibility_profile"],
        "qualification": "candidate_build_authorized",
    }
    if (
        version["schema_version"] != 1
        or version["product"] != "TinyZKP Guard"
        or version["artifact_class"] != "signed_candidate"
        or version["compatibility_profile"] != channel["compatibility_profile"]
        or version["merchant_catalog"] != channel["merchant_catalog"]
        or release != expected_release
    ):
        raise CandidateError(
            "Guard binary metadata must remain an immutable signed candidate identity"
        )


def verify_index(
    index: dict[str, Any],
    channel: dict[str, Any],
    channel_sha256: str,
    artifact_map: dict[str, dict[str, Any]],
    *,
    prior_index: dict[str, Any] | None,
    prior_index_sha256: str | None,
    expected_prior_identity: str | None,
) -> None:
    required_entry_fields = {
        "guard_version",
        "release_identity",
        "compatibility_profile",
        "release_date",
        "channel_url",
        "channel_sha256",
        "artifacts",
        "state",
    }
    optional_entry_fields = {"successor_release_identity", "advisory_url"}

    def normalized_entry(value: Any, label: str) -> dict[str, Any]:
        if (
            not isinstance(value, dict)
            or not required_entry_fields.issubset(value)
            or set(value) - required_entry_fields - optional_entry_fields
        ):
            raise CandidateError(f"{label} fields differ")
        entry = {
            **value,
            "successor_release_identity": value.get(
                "successor_release_identity"
            ),
            "advisory_url": value.get("advisory_url"),
        }
        state = entry["state"]
        if state not in {"current", "superseded", "withdrawn"}:
            raise CandidateError(f"{label} state differs")
        successor = entry["successor_release_identity"]
        advisory = entry["advisory_url"]
        if state == "current" and (successor is not None or advisory is not None):
            raise CandidateError(f"{label} current-state metadata differs")
        if state == "superseded" and (
            not isinstance(successor, str)
            or not successor
            or advisory is not None
        ):
            raise CandidateError(f"{label} supersession metadata differs")
        if state == "withdrawn":
            try:
                parsed_advisory = urlparse(advisory)
                advisory_host = (parsed_advisory.hostname or "").lower()
                advisory_port = parsed_advisory.port
            except (TypeError, ValueError) as exc:
                raise CandidateError(
                    f"{label} withdrawal metadata differs"
                ) from exc
            if (
                not isinstance(advisory, str)
                or not advisory
                or not advisory.isascii()
                or "\\" in advisory
                or any(
                    ord(character) <= 0x20 or ord(character) == 0x7F
                    for character in advisory
                )
                or parsed_advisory.scheme != "https"
                or parsed_advisory.username is not None
                or parsed_advisory.password is not None
                or parsed_advisory.query
                or parsed_advisory.fragment
                or advisory_port not in {None, 443}
                or advisory_host
                not in {"github.com", "tinyzkp.com", "www.tinyzkp.com"}
                or (
                    advisory_host == "github.com"
                    and not parsed_advisory.path.startswith(
                        "/logannye/hc-stark/"
                    )
                )
                or (
                    successor is not None
                    and (
                        not isinstance(successor, str)
                        or not successor
                    )
                )
            ):
                raise CandidateError(f"{label} withdrawal metadata differs")
        if (
            not isinstance(entry["guard_version"], str)
            or not SEMVER_RE.fullmatch(entry["guard_version"])
            or not isinstance(entry["release_identity"], str)
            or not entry["release_identity"].startswith("tinyzkp-guard/")
            or entry["compatibility_profile"]
            != "tinyzkp-p3-goldilocks-v1"
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", entry["release_date"])
            or not SHA256_RE.fullmatch(entry["channel_sha256"])
        ):
            raise CandidateError(f"{label} identity differs")
        base = (
            "https://github.com/logannye/hc-stark/releases/download/"
            f"guard-v{entry['guard_version']}"
        )
        if entry["channel_url"] != f"{base}/guard-channel-v1.json":
            raise CandidateError(f"{label} channel URL differs")
        artifacts = entry["artifacts"]
        if not isinstance(artifacts, list) or not artifacts:
            raise CandidateError(f"{label} artifact inventory differs")
        observed_names: set[str] = set()
        for artifact_value in artifacts:
            artifact = exact(
                artifact_value,
                {"name", "url", "sha256"},
                f"{label} artifact",
            )
            name = artifact["name"]
            if (
                not isinstance(name, str)
                or Path(name).name != name
                or name in observed_names
                or artifact["url"] != f"{base}/{quote(name)}"
                or not SHA256_RE.fullmatch(artifact["sha256"])
            ):
                raise CandidateError(f"{label} artifact identity differs")
            observed_names.add(name)
        return entry

    def normalized_index(
        value: dict[str, Any], label: str
    ) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
        exact(
            value,
            {"schema_version", "product", "current_release_identity", "releases"},
            label,
        )
        releases_value = value["releases"]
        if (
            value["schema_version"] != 1
            or value["product"] != "tinyzkp-guard"
            or not isinstance(releases_value, list)
            or not releases_value
        ):
            raise CandidateError(f"{label} identity differs")
        normalized = [
            normalized_entry(item, f"{label} entry {index_value}")
            for index_value, item in enumerate(releases_value)
        ]
        by_identity = {item["release_identity"]: item for item in normalized}
        if len(by_identity) != len(normalized):
            raise CandidateError(f"{label} release identities are not unique")
        current_entries = [item for item in normalized if item["state"] == "current"]
        if (
            len(current_entries) != 1
            or current_entries[0]["release_identity"]
            != value["current_release_identity"]
        ):
            raise CandidateError(f"{label} must contain one declared current release")
        for item in normalized:
            successor = item["successor_release_identity"]
            if (
                successor is not None
                and (
                    successor == item["release_identity"]
                    or successor not in by_identity
                )
            ):
                raise CandidateError(f"{label} successor chain differs")
        return normalized, by_identity

    releases, _entries = normalized_index(index, "Guard release index")
    if index["current_release_identity"] != channel["release_identity"]:
        raise CandidateError("Guard release index identity differs")
    entry = releases[-1]
    if entry["state"] != "current":
        raise CandidateError("new Guard current release must be appended last")
    base = (
        "https://github.com/logannye/hc-stark/releases/download/"
        f"guard-v{channel['guard_version']}"
    )
    expected_artifacts = [
        {
            "name": name,
            "url": f"{base}/{quote(name)}",
            "sha256": descriptor["sha256"],
        }
        for name, descriptor in sorted(artifact_map.items())
    ]
    expected_entry = {
        "guard_version": channel["guard_version"],
        "release_identity": channel["release_identity"],
        "compatibility_profile": channel["compatibility_profile"],
        "release_date": channel["release_date"],
        "channel_url": f"{base}/guard-channel-v1.json",
        "channel_sha256": channel_sha256,
        "artifacts": expected_artifacts,
        "state": "current",
        "successor_release_identity": None,
        "advisory_url": None,
    }
    if entry != expected_entry:
        raise CandidateError("current Guard release index entry differs from channel")
    if expected_prior_identity is None:
        if prior_index is not None or prior_index_sha256 is not None or len(releases) != 1:
            raise CandidateError("first Guard GA index must contain only its current release")
        return
    if prior_index is None or prior_index_sha256 is None:
        raise CandidateError("successor Guard release requires the prior signed index")
    prior_releases, _prior_entries = normalized_index(
        prior_index, "prior Guard release index"
    )
    if (
        prior_index["current_release_identity"] != expected_prior_identity
        or len(releases) != len(prior_releases) + 1
    ):
        raise CandidateError("prior Guard release index identity differs")
    expected_prior_entries: list[dict[str, Any]] = []
    for prior_entry in prior_releases:
        expected = dict(prior_entry)
        if expected["state"] == "current":
            expected["state"] = "superseded"
            expected["successor_release_identity"] = channel["release_identity"]
        expected_prior_entries.append(expected)
    if releases[:-1] != expected_prior_entries:
        raise CandidateError(
            "Guard release index did not preserve the complete prior signed history"
        )


def verify(
    candidate_dir: Path,
    launch_path: Path,
    authorization_path: Path,
    build_authorization_path: Path,
    site_release_path: Path,
    schemas_dir: Path,
    prior_release_index_path: Path | None = None,
) -> None:
    launch = load(launch_path)
    authorization = load(authorization_path)
    build_authorization = load(build_authorization_path)
    site = load(site_release_path)
    channel_path = candidate_file(candidate_dir, "guard-channel-v1.json")
    channel = load(channel_path)
    index = load(candidate_file(candidate_dir, "guard-release-index-v1.json"))
    prior_index = (
        load(prior_release_index_path)
        if prior_release_index_path is not None
        else None
    )
    identity = launch["release_identity"]

    if (
        launch["launch_state"] != "blocked"
        or launch["commerce_state"] != "live_hidden"
        or launch["checkout_enabled"] is not False
        or launch["blocking_gates"] != ["guard_artifact_published"]
        or authorization["authorization_state"] != "candidate_prepared"
        or not SOURCE_RE.fullmatch(
            authorization["public_candidate_authorization_commit"]
        )
        or authorization["commercial_release_authorized"] is not False
        or authorization["checkout_enabled"] is not False
        or authorization["release_identity"] != identity
        or site["release_identity"] != identity
        or site["commerce_state"] != "live_hidden"
        or site["checkout_enabled"] is not False
        or site["guard_artifact_available"] is not False
    ):
        raise CandidateError("launch/site state is not the exact promotion-ready identity")

    expected_channel = site["channel_manifest"]
    channel_sha256 = digest(channel_path)
    if (
        channel_sha256 != expected_channel["sha256"]
        or channel.get("release_identity")
        != expected_channel["signed_release_identity"]
    ):
        raise CandidateError("Guard channel differs from site release identity")
    exact(
        channel,
        {
            "schema_version",
            "guard_version",
            "release_identity",
            "guard_source_sha",
            "engine_source_sha",
            "release_change_class",
            "prior_qualified_release_identity",
            "prior_release_index_sha256",
            "public_candidate_authorization_commit",
            "engine_artifact_sha256",
            "artifacts",
            "oci_digest",
            "schemas",
            "eula_sha256",
            "release_date",
            "compatibility_profile",
            "merchant_catalog",
            "qualification",
        },
        "Guard channel",
    )
    signed_release_identity = expected_release_identity(
        identity, channel["engine_artifact_sha256"]
    )
    bindings = {
        "schema_version": 1,
        "guard_version": identity["guard_version"],
        "release_identity": signed_release_identity,
        "guard_source_sha": identity["guard_source_sha"],
        "engine_source_sha": identity["engine_source_sha"],
        "release_change_class": authorization["release_change_class"],
        "prior_qualified_release_identity": (
            authorization["prior_qualified_release"]["release_identity"]
            if authorization["prior_qualified_release"] is not None
            else None
        ),
        "prior_release_index_sha256": (
            authorization["prior_qualified_release"]["release_index_sha256"]
            if authorization["prior_qualified_release"] is not None
            else None
        ),
        "public_candidate_authorization_commit": authorization[
            "public_candidate_authorization_commit"
        ],
        "engine_artifact_sha256": authorization["engine"]["artifact_sha256"],
        "oci_digest": site["guard_oci_digest"],
        "release_date": authorization["legal_artifacts"]["release_date"],
        "compatibility_profile": identity["compatibility_profile"],
        "qualification": "candidate_build_authorized",
    }
    for field, expected in bindings.items():
        if channel.get(field) != expected:
            raise CandidateError(f"Guard channel {field} differs from launch identity")
    prior_authorization = authorization["prior_qualified_release"]
    expected_prior_identity = (
        prior_authorization["release_identity"]
        if prior_authorization is not None
        else None
    )
    expected_prior_index_sha256 = (
        prior_authorization["release_index_sha256"]
        if prior_authorization is not None
        else None
    )
    if (
        channel["prior_qualified_release_identity"] != expected_prior_identity
        or channel["prior_release_index_sha256"] != expected_prior_index_sha256
    ):
        raise CandidateError("Guard channel predecessor differs from authorization")
    prior_index_sha256 = (
        digest(prior_release_index_path)
        if prior_release_index_path is not None
        else None
    )
    if prior_index_sha256 != expected_prior_index_sha256:
        raise CandidateError("prior signed release index digest differs")
    verify_build_authorization(
        build_authorization,
        authorization,
        channel["public_candidate_authorization_commit"],
    )
    if (
        not OCI_RE.fullmatch(channel["oci_digest"])
        or channel["eula_sha256"]
        != authorization["legal_artifacts"]["eula_sha256"]
    ):
        raise CandidateError("Guard channel OCI/EULA identity differs")
    authorization_catalog = authorization["merchant_catalog"]
    if (
        not isinstance(authorization_catalog, dict)
        or authorization_catalog.get("catalog_policy")
        != MERCHANT_CATALOG_POLICY
    ):
        raise CandidateError("candidate authorization catalog policy differs")
    expected_catalog = {
        "merchant": "lemon_squeezy",
        "entitlement_mode": "lemon_squeezy_subscription_license_keys",
        **{
            field: authorization["merchant_catalog"][field]
            for field in (
                "store_id",
                "product_id",
                "monthly_variant_id",
                "annual_variant_id",
            )
        },
    }
    if channel["merchant_catalog"] != expected_catalog:
        raise CandidateError("Guard channel merchant catalog differs")

    artifact_values = channel.get("artifacts")
    if not isinstance(artifact_values, list) or not artifact_values:
        raise CandidateError("Guard channel artifacts must be non-empty")
    artifact_map: dict[str, dict[str, Any]] = {}
    for descriptor_value in artifact_values:
        descriptor = exact(
            descriptor_value,
            {"name", "sha256", "size_bytes"},
            "Guard artifact descriptor",
        )
        name = descriptor["name"]
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or name in artifact_map
            or not isinstance(descriptor["sha256"], str)
            or not SHA256_RE.fullmatch(descriptor["sha256"])
            or not isinstance(descriptor["size_bytes"], int)
            or isinstance(descriptor["size_bytes"], bool)
            or descriptor["size_bytes"] <= 0
        ):
            raise CandidateError("Guard artifact descriptor identity is unsafe")
        path = candidate_file(candidate_dir, name)
        if (
            path.stat().st_size != descriptor["size_bytes"]
            or digest(path) != descriptor["sha256"]
        ):
            raise CandidateError(f"Guard artifact descriptor differs for {name}")
        artifact_map[name] = descriptor
    if BUILD_AUTHORIZATION_NAME not in artifact_map:
        raise CandidateError("Guard channel omits candidate authorization A")
    build_authorization_sha256 = digest(build_authorization_path)
    if (
        artifact_map[BUILD_AUTHORIZATION_NAME]["sha256"]
        != build_authorization_sha256
        or digest(candidate_file(candidate_dir, BUILD_AUTHORIZATION_NAME))
        != build_authorization_sha256
    ):
        raise CandidateError(
            "channel-listed candidate authorization differs from public commit A"
        )

    schemas = channel.get("schemas")
    if not isinstance(schemas, dict) or set(schemas) != GUARD_SCHEMA_NAMES:
        raise CandidateError("Guard channel schema inventory differs")
    for name, expected in schemas.items():
        if (
            not isinstance(expected, str)
            or not SHA256_RE.fullmatch(expected)
            or digest(candidate_file(candidate_dir, name)) != expected
            or digest(schemas_dir / name) != expected
        ):
            raise CandidateError(f"Guard channel schema digest differs for {name}")

    expected_files = set(artifact_map) | GUARD_SCHEMA_NAMES | FIXED_CANDIDATE_FILES
    observed_files = {
        path.name
        for path in candidate_dir.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if observed_files != expected_files:
        raise CandidateError("Guard candidate file inventory differs")
    verify_checksum_inventory(candidate_dir, expected_files)

    key_path = candidate_file(candidate_dir, "signing-public-key.pem")
    if digest(key_path) != authorization["signing_trust"]["public_key_sha256"]:
        raise CandidateError("candidate signing key differs from protected trust")

    artifact_url = urlparse(site["guard_artifact_url"])
    artifact_name = Path(artifact_url.path).name
    if (
        artifact_url.scheme != "https"
        or artifact_url.hostname != "github.com"
        or artifact_name not in artifact_map
        or artifact_map[artifact_name]["sha256"] != site["guard_artifact_sha256"]
    ):
        raise CandidateError("Guard artifact URL/digest does not bind a candidate file")

    oci_names = [name for name in artifact_map if name.endswith(".oci.tar")]
    tar_names = [name for name in artifact_map if name.endswith(".tar.gz")]
    if len(oci_names) != 1 or len(tar_names) != 1:
        raise CandidateError("Guard channel must contain one OCI archive and tarball")
    verify_oci(candidate_file(candidate_dir, oci_names[0]), channel, identity)
    verify_legal_bundle(
        candidate_file(candidate_dir, tar_names[0]),
        authorization["legal_artifacts"]["eula_sha256"],
        authorization["legal_artifacts"]["notices_sha256"],
    )

    provenance_name = "provenance.intoto.json"
    if provenance_name not in artifact_map:
        raise CandidateError("Guard channel omits provenance")
    verify_provenance(
        load(candidate_file(candidate_dir, provenance_name)),
        artifact_map,
        authorization,
        channel,
        build_authorization_sha256,
    )
    verify_version(
        load(candidate_file(candidate_dir, "version.json")),
        channel,
    )
    verify_index(
        index,
        channel,
        channel_sha256,
        artifact_map,
        prior_index=prior_index,
        prior_index_sha256=prior_index_sha256,
        expected_prior_identity=expected_prior_identity,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--launch-state", type=Path, required=True)
    parser.add_argument("--candidate-authorization", type=Path, required=True)
    parser.add_argument("--build-authorization", type=Path, required=True)
    parser.add_argument("--site-release", type=Path, required=True)
    parser.add_argument("--schemas-dir", type=Path, required=True)
    parser.add_argument("--prior-release-index", type=Path)
    args = parser.parse_args()
    try:
        verify(
            args.candidate_dir,
            args.launch_state,
            args.candidate_authorization,
            args.build_authorization,
            args.site_release,
            args.schemas_dir,
            args.prior_release_index,
        )
    except (
        OSError,
        KeyError,
        TypeError,
        CandidateError,
        json.JSONDecodeError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
