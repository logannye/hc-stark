#!/usr/bin/env python3
"""Verify one already-built Guard draft against the reviewed public gate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from typing import Any
from urllib.parse import parse_qsl, quote, urlparse


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
GUARD_EXAMPLE_NAMES = {
    "job-manifest-v1.example.json",
    "policy-baseline-v1.example.json",
}
GUARD_PACKAGE_STATIC_DOCUMENT_SHA256 = {
    # These are the exact buyer-facing documents reviewed for the first GA.
    # A later Guard version must deliberately add its reviewed document hashes;
    # silently inheriting stale installation or security copy is not allowed.
    "0.1.0": {
        "README.md": "0ac849baa192ff8fd83f4b7c8a620822a5362f1ba54e31f043fb917d4ca14fa4",
        "SECURITY.md": "b24affd0cf898558abd82514eaaae80eecefdbac626c616d41f4e3023e84f0e8",
        "INSTALL.md": "74ea5e4c3a091f18fdc1b48b3a555dd1dcaca3e31ebb747258af542cf0c339fb",
        "START-HERE.txt": "333701529de6c3acf3239fa5f99865da2051665c281c038d5f8f508bea7affbb",
    }
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
AUTHORIZATION_POLICY = "owner_only_ga_v1"
QUALIFICATION_BASIS = "owner_attested"
ADVISORY_STATUS = {
    "external_design_partner_integration": "not_completed",
    "five_unaided_installs": "not_completed",
    "implementation_review_no_high_findings": "not_completed",
    "independent_resource_reproduction": "not_completed",
    "plonky3_specialist_review": "not_completed",
    "three_external_workloads": "not_completed",
    "two_standard_annual_customers": "not_completed",
}


def validate_authorization_merchant_catalog(
    catalog: Any, *, legal: dict[str, Any], identity: dict[str, Any]
) -> dict[str, Any]:
    value = exact(
        catalog,
        {
            "merchant",
            "mode",
            "store_id",
            "product_id",
            "monthly_variant_id",
            "annual_variant_id",
            "monthly_checkout_url",
            "annual_checkout_url",
            "customer_portal_url",
            "store_hostname",
            "catalog_policy",
        },
        "candidate authorization merchant catalog",
    )
    if (
        value["merchant"] != "lemon_squeezy"
        or value["mode"] != "live"
        or value["catalog_policy"] != MERCHANT_CATALOG_POLICY
        or not isinstance(value["store_hostname"], str)
        or re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.lemonsqueezy\.com",
            value["store_hostname"],
        )
        is None
    ):
        raise CandidateError("candidate authorization catalog policy differs")
    for field in (
        "store_id",
        "product_id",
        "monthly_variant_id",
        "annual_variant_id",
    ):
        if not isinstance(value[field], str) or re.fullmatch(r"[1-9][0-9]*", value[field]) is None:
            raise CandidateError(f"candidate authorization {field} differs")
    expected_query = sorted(
        [
            ("checkout[custom][terms_version]", legal["release_date"]),
            ("checkout[custom][guard_version]", identity["guard_version"]),
        ]
    )
    checkout_urls: list[str] = []
    for cadence in ("monthly", "annual"):
        url = value[f"{cadence}_checkout_url"]
        parsed = urlparse(url) if isinstance(url, str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or parsed.hostname != value["store_hostname"]
            or parsed.netloc != value["store_hostname"]
            or parsed.username is not None
            or parsed.password is not None
            or "#" in url
            or parsed.fragment
            or re.fullmatch(r"/checkout/buy/[A-Za-z0-9_-]+", parsed.path) is None
            or sorted(parse_qsl(parsed.query, keep_blank_values=True)) != expected_query
        ):
            raise CandidateError(
                f"candidate authorization {cadence} checkout URL differs"
            )
        checkout_urls.append(url)
    if checkout_urls[0] == checkout_urls[1]:
        raise CandidateError("candidate authorization checkout URLs must differ")
    portal_url = value["customer_portal_url"]
    portal = urlparse(portal_url) if isinstance(portal_url, str) else None
    if (
        portal is None
        or "?" in portal_url
        or "#" in portal_url
        or portal.scheme != "https"
        or portal.netloc != value["store_hostname"]
        or portal.path != "/billing"
        or portal.params
        or portal.query
        or portal.fragment
        or portal.username is not None
        or portal.password is not None
    ):
        raise CandidateError("candidate authorization customer portal differs")
    return value


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


def _archive_regular_bytes(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
    *,
    maximum_bytes: int = 256 * 1024 * 1024,
) -> bytes:
    member = members.get(name)
    if (
        member is None
        or not member.isfile()
        or not 1 <= member.size <= maximum_bytes
    ):
        raise CandidateError(f"Guard tarball member differs: {name}")
    handle = archive.extractfile(member)
    if handle is None:
        raise CandidateError(f"Guard tarball member cannot be read: {name}")
    raw = handle.read(maximum_bytes + 1)
    if len(raw) != member.size or len(raw) > maximum_bytes:
        raise CandidateError(f"Guard tarball member size differs: {name}")
    return raw


def verify_release_bundle(
    path: Path,
    *,
    candidate_dir: Path,
    artifact_name: str,
    channel: dict[str, Any],
    authorization: dict[str, Any],
) -> None:
    """Verify the exact buyer-delivery archive, not only its legal files.

    The tarball itself is signed as a candidate artifact. This check additionally
    prevents that signed blob from carrying stale source-repository guidance,
    mismatched agreement/delivery metadata, extra files, or a different embedded
    engine and contract set.
    """
    guard_version = channel["guard_version"]
    root = f"tinyzkp-guard-{guard_version}-linux-x86_64"
    expected_relative_files = {
        "AGREEMENT.txt",
        "DELIVERY.txt",
        "INSTALL.md",
        "README.md",
        "SECURITY.md",
        "START-HERE.txt",
        "bin/tinyzkp",
        "bin/tinyzkp-engine",
        "compatibility-manifest-v1.json",
        "legal/EULA.txt",
        "legal/THIRD-PARTY-NOTICES.txt",
        "version.json",
        *(f"schemas/{name}" for name in GUARD_SCHEMA_NAMES),
        *(f"examples/{name}" for name in GUARD_EXAMPLE_NAMES),
    }
    expected_relative_directories = {
        ".",
        "bin",
        "examples",
        "legal",
        "schemas",
    }
    try:
        with tarfile.open(path, mode="r:*") as archive:
            member_list = archive.getmembers()
            members: dict[str, tarfile.TarInfo] = {}
            observed_files: set[str] = set()
            observed_directories: set[str] = set()
            for member in member_list:
                raw_name = member.name.rstrip("/")
                parsed_name = PurePosixPath(raw_name)
                if (
                    not raw_name
                    or parsed_name.is_absolute()
                    or ".." in parsed_name.parts
                    or str(parsed_name) != raw_name
                    or not parsed_name.parts
                    or parsed_name.parts[0] != root
                    or raw_name in members
                    or member.issym()
                    or member.islnk()
                ):
                    raise CandidateError("Guard tarball contains an unsafe path or link")
                members[raw_name] = member
                relative = PurePosixPath(*parsed_name.parts[1:])
                relative_name = str(relative) if relative.parts else "."
                if member.isfile():
                    observed_files.add(relative_name)
                elif member.isdir():
                    observed_directories.add(relative_name)
                else:
                    raise CandidateError("Guard tarball contains a special filesystem entry")
            if observed_files != expected_relative_files:
                raise CandidateError("Guard tarball file inventory differs")
            if observed_directories != expected_relative_directories:
                raise CandidateError("Guard tarball directory inventory differs")

            def bundled(relative: str, *, maximum_bytes: int = 256 * 1024 * 1024) -> bytes:
                return _archive_regular_bytes(
                    archive,
                    members,
                    f"{root}/{relative}",
                    maximum_bytes=maximum_bytes,
                )

            reviewed_documents = GUARD_PACKAGE_STATIC_DOCUMENT_SHA256.get(guard_version)
            if reviewed_documents is None:
                raise CandidateError(
                    "Guard version has no reviewed buyer-document digest contract"
                )
            for name, expected in reviewed_documents.items():
                if hashlib.sha256(bundled(name, maximum_bytes=256 * 1024)).hexdigest() != expected:
                    raise CandidateError(f"Guard tarball buyer document differs: {name}")

            legal = authorization["legal_artifacts"]
            signing = authorization["signing_trust"]
            expected_agreement = (
                "schema_version=1\n"
                f"release_date={legal['release_date']}\n"
                f"eula_sha256={legal['eula_sha256']}\n"
                f"eula_url=https://tinyzkp.com/legal/{legal['eula_sha256']}/EULA.txt\n"
                "bundled_eula=legal/EULA.txt\n"
            ).encode()
            expected_delivery = (
                "schema_version=1\n"
                f"guard_version={guard_version}\n"
                f"release_tag=guard-v{guard_version}\n"
                f"artifact_name={artifact_name}\n"
                "artifact_url=https://github.com/logannye/hc-stark/releases/download/"
                f"guard-v{guard_version}/{artifact_name}\n"
                "receipt_confirmation_url=https://tinyzkp.com/releases\n"
                f"signing_public_key_sha256={signing['public_key_sha256']}\n"
            ).encode()
            if bundled("AGREEMENT.txt", maximum_bytes=64 * 1024) != expected_agreement:
                raise CandidateError("Guard tarball AGREEMENT.txt differs")
            if bundled("DELIVERY.txt", maximum_bytes=64 * 1024) != expected_delivery:
                raise CandidateError("Guard tarball DELIVERY.txt differs")

            eula_raw = bundled("legal/EULA.txt", maximum_bytes=4 * 1024 * 1024)
            notices_raw = bundled(
                "legal/THIRD-PARTY-NOTICES.txt", maximum_bytes=4 * 1024 * 1024
            )
            for relative, raw, expected in (
                ("legal/EULA.txt", eula_raw, legal["eula_sha256"]),
                (
                    "legal/THIRD-PARTY-NOTICES.txt",
                    notices_raw,
                    legal["notices_sha256"],
                ),
            ):
                if hashlib.sha256(raw).hexdigest() != expected:
                    raise CandidateError(f"Guard tarball legal digest differs: {relative}")
            try:
                eula_text = eula_raw.decode("utf-8")
            except UnicodeDecodeError as error:
                raise CandidateError("Guard tarball EULA is not UTF-8") from error
            effective_dates = re.findall(
                r"(?m)^Effective Date: (\d{4}-\d{2}-\d{2})$", eula_text
            )
            if effective_dates != [legal["release_date"]]:
                raise CandidateError(
                    "Guard tarball EULA effective date differs from authorization"
                )
            if (
                hashlib.sha256(bundled("bin/tinyzkp-engine")).hexdigest()
                != channel["engine_artifact_sha256"]
            ):
                raise CandidateError("Guard tarball engine binary digest differs")
            for relative, candidate_name in (
                ("version.json", "version.json"),
                (
                    "compatibility-manifest-v1.json",
                    "compatibility-manifest-v1.json",
                ),
                *((f"schemas/{name}", name) for name in GUARD_SCHEMA_NAMES),
            ):
                if bundled(relative, maximum_bytes=16 * 1024 * 1024) != candidate_file(
                    candidate_dir, candidate_name
                ).read_bytes():
                    raise CandidateError(
                        f"Guard tarball embedded candidate file differs: {relative}"
                    )
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
        "authorization_policy": authorization["authorization_policy"],
        "candidate_authorization_sha256": build_authorization_sha256,
        "compatibility_profile": authorization["compatibility_profile"],
        "merchant_catalog": authorization["merchant_catalog"],
        "eula_sha256": authorization["legal_artifacts"]["eula_sha256"],
        "eula_url": authorization["legal_artifacts"]["eula_url"],
        "engine_artifact_sha256": authorization["engine"]["artifact_sha256"],
        "engine_release_tag": authorization["engine"]["candidate_tag"],
        "engine_source_sha": authorization["engine"]["source_sha"],
        "guard_source_sha": authorization["release_identity"]["guard_source_sha"],
        "guard_version": authorization["release_identity"]["guard_version"],
        "notices_sha256": authorization["legal_artifacts"]["notices_sha256"],
        "qualification_basis": authorization["qualification_basis"],
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
        "authorization_policy",
        "qualification_basis",
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
        "authorization_policy",
        "qualification_basis",
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
            or set(reviewed)
            != {
                "launch_evidence_sha256",
                "launch_trust_policy_sha256",
                "required_passed_gates",
                "advisory_status",
            }
            or value["authorization_policy"] != AUTHORIZATION_POLICY
            or value["qualification_basis"] != QUALIFICATION_BASIS
            or reviewed.get("advisory_status") != ADVISORY_STATUS
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
    for field in (
        "launch_trust_policy_sha256",
        "required_passed_gates",
        "advisory_status",
    ):
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
        or launch.get("authorization_policy") != AUTHORIZATION_POLICY
        or launch.get("qualification_basis") != QUALIFICATION_BASIS
        or launch["commerce_state"] != "live_hidden"
        or launch["checkout_enabled"] is not False
        or launch["blocking_gates"] != ["guard_artifact_published"]
        or authorization["authorization_state"] != "candidate_prepared"
        or authorization.get("authorization_policy") != AUTHORIZATION_POLICY
        or authorization.get("qualification_basis") != QUALIFICATION_BASIS
        or not SOURCE_RE.fullmatch(
            authorization["public_candidate_authorization_commit"]
        )
        or authorization["commercial_release_authorized"] is not False
        or authorization["checkout_enabled"] is not False
        or authorization["release_identity"] != identity
        or site["release_identity"] != identity
        or site.get("authorization_policy") != AUTHORIZATION_POLICY
        or site.get("qualification_basis") != QUALIFICATION_BASIS
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
    authorization_catalog = validate_authorization_merchant_catalog(
        authorization["merchant_catalog"],
        legal=authorization["legal_artifacts"],
        identity=authorization["release_identity"],
    )
    if authorization["legal_artifacts"].get("eula_url") != (
        "https://tinyzkp.com/legal/"
        f"{authorization['legal_artifacts'].get('eula_sha256')}/EULA.txt"
    ):
        raise CandidateError("candidate authorization exact EULA URL differs")
    expected_catalog = {
        "merchant": "lemon_squeezy",
        "entitlement_mode": "lemon_squeezy_subscription_license_keys",
        **{
            field: authorization_catalog[field]
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
    verify_release_bundle(
        candidate_file(candidate_dir, tar_names[0]),
        candidate_dir=candidate_dir,
        artifact_name=tar_names[0],
        channel=channel,
        authorization=authorization,
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
