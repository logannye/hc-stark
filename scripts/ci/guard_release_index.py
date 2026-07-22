#!/usr/bin/env python3
"""Validate signed Guard release indexes and restricted index-only revisions."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import quote, urlparse
import re
import shutil
import subprocess
import sys
from typing import Any

import strict_json


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
RELEASE_ID_RE = re.compile(r"^tinyzkp-guard/[A-Za-z0-9.+-]{1,512}$")
PRIVATE_REPOSITORY = "logannye/tinyzkp-guard"
PUBLIC_REPOSITORY = "logannye/hc-stark"
PUBLIC_KEY_PATH = "release/guard-signing-public-key.pem"
INDEX_NAME = "guard-release-index-v1.json"
SIGNATURE_NAME = "guard-release-index-v1.json.sig"
HANDOFF_NAME = "guard-release-index-revision-handoff-v1.json"
ENTRY_FIELDS = {
    "guard_version",
    "release_identity",
    "compatibility_profile",
    "release_date",
    "channel_url",
    "channel_sha256",
    "artifacts",
    "state",
    "successor_release_identity",
    "advisory_url",
}
IMMUTABLE_ENTRY_FIELDS = ENTRY_FIELDS - {
    "state",
    "successor_release_identity",
    "advisory_url",
}


class IndexError(ValueError):
    """A release index, handoff, signature, or transition is invalid."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndexError(f"{label} fields differ")
    return value


def load(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = strict_json.loads(raw)
    except (OSError, ValueError) as exc:
        raise IndexError(f"cannot read strict {label} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise IndexError(f"{label} must be an object")
    return value, raw


def _safe_https_url(value: Any, label: str, *, advisory: bool) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or "\\" in value
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise IndexError(f"{label} must be an unambiguous ASCII HTTPS URL")
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise IndexError(f"{label} must be a well-formed HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in {None, 443}
    ):
        raise IndexError(f"{label} must be an approved HTTPS URL")
    if advisory:
        if (
            parsed.query
            or host not in {"github.com", "tinyzkp.com", "www.tinyzkp.com"}
            or (
                host == "github.com"
                and not parsed.path.startswith("/logannye/hc-stark/")
            )
        ):
            raise IndexError(f"{label} must use an approved advisory URL")
    return value


def validate_index(
    value: Any, label: str
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    index = exact(
        value,
        {"schema_version", "product", "current_release_identity", "releases"},
        label,
    )
    releases_value = index["releases"]
    if (
        index["schema_version"] != 1
        or index["product"] != "tinyzkp-guard"
        or not isinstance(releases_value, list)
        or not releases_value
    ):
        raise IndexError(f"{label} identity differs")
    releases: list[dict[str, Any]] = []
    for position, entry_value in enumerate(releases_value):
        entry_label = f"{label} entry {position}"
        entry = exact(entry_value, ENTRY_FIELDS, entry_label)
        if (
            not isinstance(entry["guard_version"], str)
            or not SEMVER_RE.fullmatch(entry["guard_version"])
            or not isinstance(entry["release_identity"], str)
            or not RELEASE_ID_RE.fullmatch(entry["release_identity"])
            or entry["compatibility_profile"] != "tinyzkp-p3-goldilocks-v1"
            or not isinstance(entry["release_date"], str)
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", entry["release_date"])
            or not isinstance(entry["channel_sha256"], str)
            or not SHA256_RE.fullmatch(entry["channel_sha256"])
        ):
            raise IndexError(f"{entry_label} identity differs")
        base = (
            "https://github.com/logannye/hc-stark/releases/download/"
            f"guard-v{entry['guard_version']}"
        )
        if entry["channel_url"] != f"{base}/guard-channel-v1.json":
            raise IndexError(f"{entry_label} channel URL differs")
        _safe_https_url(entry["channel_url"], f"{entry_label} channel URL", advisory=False)
        artifacts = entry["artifacts"]
        if not isinstance(artifacts, list) or not artifacts:
            raise IndexError(f"{entry_label} artifact inventory differs")
        names: set[str] = set()
        for artifact_value in artifacts:
            artifact = exact(
                artifact_value, {"name", "url", "sha256"}, f"{entry_label} artifact"
            )
            name = artifact["name"]
            if (
                not isinstance(name, str)
                or Path(name).name != name
                or name in names
                or artifact["url"] != f"{base}/{quote(name)}"
                or not isinstance(artifact["sha256"], str)
                or not SHA256_RE.fullmatch(artifact["sha256"])
            ):
                raise IndexError(f"{entry_label} artifact identity differs")
            _safe_https_url(
                artifact["url"], f"{entry_label} artifact URL", advisory=False
            )
            names.add(name)
        state = entry["state"]
        successor = entry["successor_release_identity"]
        advisory_url = entry["advisory_url"]
        if state not in {"current", "superseded", "withdrawn"}:
            raise IndexError(f"{entry_label} state differs")
        if state == "current" and (successor is not None or advisory_url is not None):
            raise IndexError(f"{entry_label} current-state metadata differs")
        if state == "superseded" and (
            not isinstance(successor, str)
            or not RELEASE_ID_RE.fullmatch(successor)
            or advisory_url is not None
        ):
            raise IndexError(f"{entry_label} supersession metadata differs")
        if state == "withdrawn":
            if (
                not isinstance(advisory_url, str)
                or (
                    successor is not None
                    and (
                        not isinstance(successor, str)
                        or not RELEASE_ID_RE.fullmatch(successor)
                    )
                )
            ):
                raise IndexError(f"{entry_label} withdrawal metadata differs")
            _safe_https_url(
                advisory_url, f"{entry_label} advisory URL", advisory=True
            )
        releases.append(entry)
    by_identity = {entry["release_identity"]: entry for entry in releases}
    if len(by_identity) != len(releases):
        raise IndexError(f"{label} release identities are not unique")
    current = [entry for entry in releases if entry["state"] == "current"]
    if (
        len(current) != 1
        or current[0]["release_identity"] != index["current_release_identity"]
    ):
        raise IndexError(f"{label} must contain one declared current release")
    for entry in releases:
        successor = entry["successor_release_identity"]
        if successor is not None and (
            successor == entry["release_identity"] or successor not in by_identity
        ):
            raise IndexError(f"{label} successor chain differs")
    return releases, by_identity


def validate_handoff(
    value: Any,
    *,
    prior_raw: bytes,
    revised_raw: bytes,
    public_key_sha256: str,
    expected_private_run_id: str | None = None,
) -> dict[str, Any]:
    handoff = exact(
        value,
        {
            "schema_version",
            "document_type",
            "private_repository",
            "private_run_id",
            "private_source_sha",
            "prior_index_sha256",
            "revised_index_sha256",
            "target_release_identity",
            "replacement_current_release_identity",
            "signer_public_key_sha256",
            "signature_format",
        },
        "Guard release index revision handoff",
    )
    if (
        handoff["schema_version"] != 1
        or handoff["document_type"] != "GuardReleaseIndexRevisionHandoffV1"
        or handoff["private_repository"] != PRIVATE_REPOSITORY
        or not isinstance(handoff["private_run_id"], str)
        or not re.fullmatch(r"[1-9][0-9]{0,19}", handoff["private_run_id"])
        or (
            expected_private_run_id is not None
            and handoff["private_run_id"] != expected_private_run_id
        )
        or not isinstance(handoff["private_source_sha"], str)
        or not GIT_SHA_RE.fullmatch(handoff["private_source_sha"])
        or handoff["prior_index_sha256"] != sha256_bytes(prior_raw)
        or handoff["revised_index_sha256"] != sha256_bytes(revised_raw)
        or not isinstance(handoff["target_release_identity"], str)
        or not RELEASE_ID_RE.fullmatch(handoff["target_release_identity"])
        or (
            handoff["replacement_current_release_identity"] is not None
            and (
                not isinstance(handoff["replacement_current_release_identity"], str)
                or not RELEASE_ID_RE.fullmatch(
                    handoff["replacement_current_release_identity"]
                )
            )
        )
        or handoff["signer_public_key_sha256"] != public_key_sha256
        or handoff["signature_format"] != "cosign-raw-signature-v1"
    ):
        raise IndexError("Guard release index revision handoff identity differs")
    return handoff


def validate_transition(
    prior: dict[str, Any],
    revised: dict[str, Any],
    handoff: dict[str, Any],
) -> None:
    prior_releases, prior_by_identity = validate_index(prior, "prior Guard release index")
    revised_releases, revised_by_identity = validate_index(
        revised, "revised Guard release index"
    )
    prior_order = [entry["release_identity"] for entry in prior_releases]
    revised_order = [entry["release_identity"] for entry in revised_releases]
    if prior_order != revised_order:
        raise IndexError("revision did not preserve full release-index order")
    target_identity = handoff["target_release_identity"]
    replacement_identity = handoff["replacement_current_release_identity"]
    if target_identity not in prior_by_identity:
        raise IndexError("revision target is absent from the prior release index")
    if replacement_identity is not None and (
        replacement_identity not in prior_by_identity
        or replacement_identity == target_identity
    ):
        raise IndexError("revision replacement identity is invalid")
    for identity in prior_order:
        prior_entry = prior_by_identity[identity]
        revised_entry = revised_by_identity[identity]
        for field in IMMUTABLE_ENTRY_FIELDS:
            if revised_entry[field] != prior_entry[field]:
                raise IndexError(
                    f"revision changed immutable history for {identity}: {field}"
                )
        if identity not in {target_identity, replacement_identity} and (
            revised_entry != prior_entry
        ):
            raise IndexError(f"revision changed unrelated release history: {identity}")

    prior_target = prior_by_identity[target_identity]
    revised_target = revised_by_identity[target_identity]
    if (
        revised_target["state"] != "withdrawn"
        or not isinstance(revised_target["advisory_url"], str)
    ):
        raise IndexError("revision target must be withdrawn with an advisory")
    if prior_target["state"] == "current":
        if replacement_identity is None:
            raise IndexError("current withdrawal requires a replacement release")
        prior_replacement = prior_by_identity[replacement_identity]
        revised_replacement = revised_by_identity[replacement_identity]
        if (
            prior_replacement["state"] != "superseded"
            or revised_replacement["state"] != "current"
            or revised_replacement["successor_release_identity"] is not None
            or revised_replacement["advisory_url"] is not None
            or revised_target["successor_release_identity"] != replacement_identity
            or revised["current_release_identity"] != replacement_identity
        ):
            raise IndexError("current withdrawal replacement transition differs")
    else:
        if replacement_identity is not None:
            raise IndexError("non-current withdrawal cannot replace the current release")
        if (
            revised["current_release_identity"] != prior["current_release_identity"]
            or revised_target["successor_release_identity"]
            != prior_target["successor_release_identity"]
        ):
            raise IndexError("non-current withdrawal changed recommendation history")
    if prior_target["state"] == "withdrawn" and (
        revised_target["state"] != prior_target["state"]
        or revised_target["successor_release_identity"]
        != prior_target["successor_release_identity"]
        or revised_target["advisory_url"] == prior_target["advisory_url"]
    ):
        raise IndexError("withdrawn advisory revision must change only its advisory URL")
    if prior_target["state"] != "withdrawn" and (
        revised_target["advisory_url"] is None
        or revised_target["state"] == prior_target["state"]
    ):
        raise IndexError("withdrawal revision did not change the target state")


def validate_successor(
    prior: dict[str, Any],
    revised: dict[str, Any],
    *,
    expected_new_identity: str,
) -> None:
    """Allow exactly one immutable append and current→superseded transition."""
    prior_releases, prior_by_identity = validate_index(
        prior, "prior Guard release index"
    )
    revised_releases, revised_by_identity = validate_index(
        revised, "successor Guard release index"
    )
    prior_order = [entry["release_identity"] for entry in prior_releases]
    revised_order = [entry["release_identity"] for entry in revised_releases]
    if (
        revised_order[:-1] != prior_order
        or len(revised_order) != len(prior_order) + 1
        or revised_order[-1] != expected_new_identity
        or expected_new_identity in prior_by_identity
    ):
        raise IndexError("successor release index must append exactly one release")
    prior_current = prior["current_release_identity"]
    for identity in prior_order:
        before = prior_by_identity[identity]
        after = revised_by_identity[identity]
        if identity == prior_current:
            expected = {
                **before,
                "state": "superseded",
                "successor_release_identity": expected_new_identity,
                "advisory_url": None,
            }
            if after != expected:
                raise IndexError("successor index changed the prior current release incorrectly")
        elif after != before:
            raise IndexError("successor index changed immutable release history")
    new_entry = revised_by_identity[expected_new_identity]
    if (
        revised["current_release_identity"] != expected_new_identity
        or new_entry["state"] != "current"
        or new_entry["successor_release_identity"] is not None
        or new_entry["advisory_url"] is not None
    ):
        raise IndexError("successor index current release differs")


def verify_signature(
    *,
    index_path: Path,
    signature_path: Path,
    public_key_path: Path,
    cosign: str | None = None,
) -> None:
    executable = cosign or shutil.which("cosign")
    if not executable:
        raise IndexError("cosign is unavailable")
    completed = subprocess.run(
        [
            executable,
            "verify-blob",
            "--key",
            str(public_key_path),
            "--signature",
            str(signature_path),
            str(index_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise IndexError("Guard release index signature verification failed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prior-index", type=Path, required=True)
    parser.add_argument("--revised-index", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--private-run-id")
    parser.add_argument("--cosign")
    args = parser.parse_args(argv)
    try:
        prior, prior_raw = load(args.prior_index, "prior Guard release index")
        revised, revised_raw = load(args.revised_index, "revised Guard release index")
        handoff_value, _handoff_raw = load(args.handoff, "revision handoff")
        public_key_raw = args.public_key.read_bytes()
        handoff = validate_handoff(
            handoff_value,
            prior_raw=prior_raw,
            revised_raw=revised_raw,
            public_key_sha256=sha256_bytes(public_key_raw),
            expected_private_run_id=args.private_run_id,
        )
        validate_transition(prior, revised, handoff)
        verify_signature(
            index_path=args.revised_index,
            signature_path=args.signature,
            public_key_path=args.public_key,
            cosign=args.cosign,
        )
    except (OSError, IndexError, subprocess.TimeoutExpired) as exc:
        print(f"Guard release index revision: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "schema_version": 1,
                "status": "verified",
                "prior_index_sha256": handoff["prior_index_sha256"],
                "revised_index_sha256": handoff["revised_index_sha256"],
                "target_release_identity": handoff["target_release_identity"],
                "replacement_current_release_identity": handoff[
                    "replacement_current_release_identity"
                ],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
