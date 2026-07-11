#!/usr/bin/env python3
"""Strict, offline helpers for TinyZKP commercial evidence artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any


MAX_JSON_BYTES = 1024 * 1024
MAX_BOUND_ARTIFACT_BYTES = 256 * 1024 * 1024
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PROFILE_ID = "tinyzkp-p3-goldilocks-v1"
PLONKY3_VERSION = "0.6.1"
# Commercial evidence uses the frozen verifier target already enforced by the
# evaluation acceptance contract, not the Rust WorkloadManifestV1 spelling.
EXPECTED_VERIFIER = "unmodified-p3-uni-stark-0.6.1"
PINNED_P3_CRATES = {
    "p3-air",
    "p3-challenger",
    "p3-commit",
    "p3-dft",
    "p3-field",
    "p3-fri",
    "p3-goldilocks",
    "p3-matrix",
    "p3-merkle-tree",
    "p3-poseidon2-air",
    "p3-symmetric",
    "p3-uni-stark",
}
PINNED_ARTIFACT_DEPENDENCIES = {
    "base64",
    "blake3",
    "getrandom",
    "postcard",
    "rand",
    "rayon",
    "serde",
    "serde_json",
}


class EvidenceError(ValueError):
    """An evidence artifact failed a fail-closed validation rule."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise EvidenceError(f"non-finite JSON number is forbidden: {value}")


def read_regular_bytes(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_JSON_BYTES,
    require_owner_only: bool = True,
) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise EvidenceError(f"cannot read {label}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"{label} must be a regular non-symlink file")
        if require_owner_only and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise EvidenceError(
                f"{label} must be owner-only (no group/other permissions)"
            )
        if (
            require_owner_only
            and hasattr(os, "geteuid")
            and metadata.st_uid != os.geteuid()
        ):
            raise EvidenceError(f"{label} must be owned by the current operator")
        if metadata.st_size <= 0 or metadata.st_size > max_bytes:
            raise EvidenceError(f"{label} is empty or exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if not payload or len(payload) > max_bytes:
            raise EvidenceError(f"{label} is empty or exceeds {max_bytes} bytes")
        return payload
    finally:
        os.close(descriptor)


def load_json(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_JSON_BYTES,
    require_owner_only: bool = True,
) -> tuple[Any, bytes]:
    raw = read_regular_bytes(
        path,
        label,
        max_bytes=max_bytes,
        require_owner_only=require_owner_only,
    )
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label} is not strict UTF-8 JSON: {error}") from error
    return value, raw


def canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise EvidenceError(f"evidence is not canonical JSON: {error}") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    if set(value) != keys:
        missing = sorted(keys - set(value))
        extra = sorted(set(value) - keys)
        raise EvidenceError(f"{label} keys differ; missing={missing}, extra={extra}")
    return value


def nonempty_string(value: Any, label: str, *, max_length: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise EvidenceError(
            f"{label} must be a trimmed non-empty string of at most {max_length} characters"
        )
    return value


def safe_id(value: Any, label: str) -> str:
    result = nonempty_string(value, label, max_length=128)
    if SAFE_ID.fullmatch(result) is None:
        raise EvidenceError(f"{label} must use safe identifier characters")
    return result


def sha256_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def positive_integer(value: Any, label: str, *, maximum: int = (1 << 63) - 1) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
        or value > maximum
    ):
        raise EvidenceError(
            f"{label} must be a positive integer no greater than {maximum}"
        )
    return value


def canonical_timestamp(value: Any, label: str) -> str:
    raw = nonempty_string(value, label, max_length=20)
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise EvidenceError(
            f"{label} must use canonical UTC second precision"
        ) from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != raw:
        raise EvidenceError(f"{label} must use canonical UTC second precision")
    return raw


def canonical_date(value: Any, label: str) -> str:
    raw = nonempty_string(value, label, max_length=10)
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%d")
    except ValueError as error:
        raise EvidenceError(f"{label} must use YYYY-MM-DD") from error
    if parsed.strftime("%Y-%m-%d") != raw:
        raise EvidenceError(f"{label} must use YYYY-MM-DD")
    return raw


def command_argv(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        raise EvidenceError(f"{label} must be an argv array with 1-128 entries")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(nonempty_string(item, f"{label}[{index}]", max_length=2048))
    return result


def atomic_write_canonical(path: Path, value: Any) -> str:
    raw = canonical_bytes(value)
    parent = path.parent
    if parent.is_symlink():
        raise EvidenceError("evidence output directory must not be a symlink")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise EvidenceError("evidence output must be a regular non-symlink file")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
    return sha256_bytes(raw)


def compatibility_identity(path: Path) -> dict[str, str]:
    payload, raw = load_json(
        path,
        "Plonky3 compatibility manifest",
        require_owner_only=False,
    )
    manifest = exact_object(
        payload,
        {
            "schema_version",
            "profile_id",
            "release_status",
            "rust_toolchain",
            "cargo_lock_sha256",
            "upstream",
            "configuration",
            "pinned_crates",
            "artifact_dependencies",
            "validated_workloads",
            "known_limits",
        },
        "Plonky3 compatibility manifest",
    )
    upstream = exact_object(
        manifest.get("upstream"),
        {"repository", "tag", "reference_configuration"},
        "compatibility upstream",
    )
    configuration = exact_object(
        manifest.get("configuration"),
        {
            "field",
            "challenge_field",
            "merkle_and_transcript_permutation",
            "permutation_seed",
            "permutation_rng",
            "poseidon2_trace_rng",
            "fri_parameters",
            "proof_system",
            "proof_serializer",
            "official_verifier_required",
        },
        "compatibility configuration",
    )
    if (
        manifest.get("schema_version") != 1
        or manifest.get("profile_id") != PROFILE_ID
        or manifest.get("release_status") != "backend_recovery"
        or upstream.get("repository") != "https://github.com/Plonky3/Plonky3"
        or upstream.get("tag") != "v0.6.1"
        or upstream.get("reference_configuration")
        != "keccak-air/examples/prove_goldilocks_poseidon2.rs"
        or configuration.get("field") != "p3_goldilocks::Goldilocks"
        or configuration.get("challenge_field")
        != "BinomialExtensionField<Goldilocks,2>"
        or configuration.get("merkle_and_transcript_permutation")
        != "Poseidon2Goldilocks<8>"
        or configuration.get("permutation_seed") != 1
        or configuration.get("permutation_rng")
        != "rand-0.10.2::Xoshiro256PlusPlus"
        or configuration.get("poseidon2_trace_rng")
        != "rand-0.10.2::Xoshiro256PlusPlus"
        or configuration.get("fri_parameters") != "FriParameters::new_benchmark"
        or configuration.get("proof_system") != "p3_uni_stark"
        or configuration.get("proof_serializer") != "postcard-1.1.3"
        or configuration.get("official_verifier_required") is not True
    ):
        raise EvidenceError("unsupported Plonky3 compatibility profile")
    nonempty_string(manifest.get("rust_toolchain"), "compatibility rust_toolchain")
    sha256_hex(manifest.get("cargo_lock_sha256"), "compatibility cargo_lock_sha256")
    crates = manifest.get("pinned_crates")
    if not isinstance(crates, list):
        raise EvidenceError("compatibility pinned_crates must be an array")
    seen: set[str] = set()
    for item in crates:
        crate = exact_object(item, {"name", "version", "checksum"}, "pinned crate")
        name = nonempty_string(crate.get("name"), "pinned crate name", max_length=80)
        if name in seen:
            raise EvidenceError("compatibility pinned_crates contains duplicate names")
        seen.add(name)
        if crate.get("version") != PLONKY3_VERSION:
            raise EvidenceError("every pinned Plonky3 crate must equal 0.6.1")
        sha256_hex(crate.get("checksum"), f"pinned crate {name} checksum")
    if seen != PINNED_P3_CRATES:
        raise EvidenceError(
            "compatibility manifest has an incomplete or unknown Plonky3 crate set"
        )
    dependencies = manifest.get("artifact_dependencies")
    if not isinstance(dependencies, list):
        raise EvidenceError("compatibility artifact_dependencies must be an array")
    dependency_names: set[str] = set()
    for item in dependencies:
        dependency = exact_object(
            item, {"name", "version", "checksum"}, "artifact dependency"
        )
        name = nonempty_string(
            dependency.get("name"), "artifact dependency name", max_length=80
        )
        if name in dependency_names:
            raise EvidenceError(
                "compatibility artifact_dependencies contains duplicate names"
            )
        dependency_names.add(name)
        nonempty_string(
            dependency.get("version"),
            f"artifact dependency {name} version",
            max_length=40,
        )
        sha256_hex(dependency.get("checksum"), f"artifact dependency {name} checksum")
    if dependency_names != PINNED_ARTIFACT_DEPENDENCIES:
        raise EvidenceError(
            "compatibility artifact dependency set is incomplete or unknown"
        )
    if manifest.get("validated_workloads") != ["fibonacci", "poseidon2_goldilocks"]:
        raise EvidenceError(
            "compatibility validated_workloads differs from the frozen profile"
        )
    known_limits = manifest.get("known_limits")
    if not isinstance(known_limits, list) or not known_limits:
        raise EvidenceError("compatibility known_limits must be a non-empty array")
    for index, limit in enumerate(known_limits):
        nonempty_string(
            limit,
            f"compatibility known_limits[{index}]",
            max_length=1000,
        )
    return {
        "profile": PROFILE_ID,
        "plonky3_version": PLONKY3_VERSION,
        "expected_verifier": EXPECTED_VERIFIER,
        "compatibility_manifest_sha256": sha256_bytes(raw),
    }
