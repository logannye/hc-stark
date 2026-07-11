#!/usr/bin/env python3
"""Build and verify the fail-closed TinyZKP billing Python wheelhouse.

This tool deliberately uses only the Python standard library.  It can verify
the dependency metadata before a runtime exists, download the one reviewed
target wheel for each locked distribution on a separate build machine, and
verify a sealed production wheelhouse without importing any wheel content.

The checked-in host provenance remains deliberately unconfigured.  On the
reviewed production host this tool can capture and verify the Debian-owned
interpreter, standard library, dynamic loader, shared libraries, installed
billing virtualenv, and pinned Node binary.  The resulting canonical inventory
digest is suitable for binding into separate release evidence; it is not a
substitute for independent review of the captured inventory.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import importlib.metadata
import io
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import zipfile


ROOT = pathlib.Path(__file__).resolve().parent
DEFAULT_REQUIREMENTS = ROOT / "requirements.txt"
DEFAULT_LOCK = ROOT / "requirements.lock"
DEFAULT_BOOTSTRAP_LOCK = ROOT / "requirements-bootstrap.lock"
DEFAULT_PROFILE = ROOT / "runtime-profile.json"
DEFAULT_MANIFEST = ROOT / "wheelhouse-manifest.json"
DEFAULT_HOST_PROVENANCE = ROOT / "host-runtime-provenance.json"
DEFAULT_VENV_ROOT = pathlib.Path("/var/lib/tinyzkp-runtime/billing-venv")
DEFAULT_NODE_BINARY = pathlib.Path(
    "/var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node"
)
DEFAULT_NODE_SHA256 = "41a74efb34cbde5c7632cdac0cf8bd1a14d0b8d73dc1e82755014d9a9ce70f5c"

MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_WHEEL_BYTES = 128 * 1024 * 1024
MAX_WHEEL_MEMBERS = 20_000
MAX_WHEEL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_HOST_RUNTIME_FILES = 20_000
MAX_HOST_RUNTIME_BYTES = 768 * 1024 * 1024
HASH_RE = re.compile(r"[0-9a-f]{64}")
NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
VERSION_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.!+_-]*[A-Za-z0-9])?")
TAG_RE = re.compile(r"[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+")
LOCK_RE = re.compile(
    r"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[(?P<extras>[A-Za-z0-9_,.-]+)\])?"
    r"==(?P<version>[A-Za-z0-9](?:[A-Za-z0-9.!+_-]*[A-Za-z0-9])?)"
    r" --hash=sha256:(?P<sha256>[0-9a-f]{64})"
)
DIRECT_RE = re.compile(
    r"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[(?P<extras>[A-Za-z0-9_,.-]+)\])?"
    r"==(?P<version>[A-Za-z0-9](?:[A-Za-z0-9.!+_-]*[A-Za-z0-9])?)"
)


class RuntimeLockError(ValueError):
    """The runtime profile, lock, wheelhouse, or host is not authorized."""


@dataclass(frozen=True)
class LockedRequirement:
    name: str
    version: str
    sha256: str


@dataclass(frozen=True)
class DirectRequirement:
    name: str
    version: str
    extras: frozenset[str]


@dataclass(frozen=True)
class Artifact:
    filename: str
    name: str
    version: str
    sha256: str
    size: int
    role: str


@dataclass(frozen=True)
class HostFacts:
    kernel: str
    machine: str
    os_id: str
    os_version_id: str
    implementation: str
    major: int
    minor: int
    soabi: str
    executable: str


@dataclass(frozen=True)
class RuntimeIdentity:
    file_count: int
    byte_count: int
    identity_sha256: str


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular(path: pathlib.Path, *, label: str, limit: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RuntimeLockError(f"{label} is unavailable: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeLockError(f"{label} must be a regular non-symlink file")
    if metadata.st_size < 1 or metadata.st_size > limit:
        raise RuntimeLockError(f"{label} has an invalid size")
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeLockError(f"{label} verification requires O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeLockError(f"{label} cannot be read") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
        ):
            raise RuntimeLockError(f"{label} changed before it was opened")
        content = bytearray()
        while len(content) <= limit:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise RuntimeLockError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    if len(content) != metadata.st_size or len(content) > limit:
        raise RuntimeLockError(f"{label} changed while it was read")
    return bytes(content)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeLockError(f"JSON key is duplicated: {key}")
        result[key] = value
    return result


def _load_json(path: pathlib.Path, *, label: str) -> tuple[dict[str, object], bytes]:
    raw = _read_regular(path, label=label, limit=MAX_METADATA_BYTES)
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeLockError(f"{label} is not canonical UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise RuntimeLockError(f"{label} must be a JSON object")
    return value, raw


def _exact_keys(value: dict[str, object], expected: set[str], *, label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        extra = ", ".join(sorted(actual - expected)) or "none"
        raise RuntimeLockError(f"{label} keys differ (missing: {missing}; extra: {extra})")


def normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _parse_records(raw: bytes, *, bootstrap: bool = False) -> dict[str, LockedRequirement]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeLockError("requirements lock must be UTF-8") from error
    if "\x00" in text or "\\\n" in text:
        raise RuntimeLockError("requirements lock cannot contain NULs or continuations")
    records: dict[str, LockedRequirement] = {}
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = LOCK_RE.fullmatch(line)
        if match is None:
            raise RuntimeLockError(f"requirements lock line {number} is not an exact hashed pin")
        name = normalize_name(match.group("name"))
        if name in records:
            raise RuntimeLockError(f"requirements lock duplicates {name}")
        records[name] = LockedRequirement(
            name=name,
            version=match.group("version"),
            sha256=match.group("sha256"),
        )
    if not records:
        raise RuntimeLockError("requirements lock is empty")
    if bootstrap and set(records) != {"pip"}:
        raise RuntimeLockError("bootstrap lock must contain exactly one pip wheel")
    if not bootstrap and "pip" in records:
        raise RuntimeLockError("pip is bootstrap-only and cannot be installed at runtime")
    return records


def _parse_direct_requirements(raw: bytes) -> dict[str, DirectRequirement]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeLockError("direct requirements must be UTF-8") from error
    if "\x00" in text or "\\\n" in text:
        raise RuntimeLockError("direct requirements cannot contain NULs or continuations")
    records: dict[str, DirectRequirement] = {}
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = DIRECT_RE.fullmatch(line)
        if match is None:
            raise RuntimeLockError(f"direct requirements line {number} is not an exact pin")
        name = normalize_name(match.group("name"))
        if name in records:
            raise RuntimeLockError(f"direct requirements duplicate {name}")
        extras_raw = match.group("extras") or ""
        extras = frozenset(
            normalize_name(extra.strip()) for extra in extras_raw.split(",") if extra.strip()
        )
        records[name] = DirectRequirement(name, match.group("version"), extras)
    if not records:
        raise RuntimeLockError("direct requirements are empty")
    return records


class _MarkerParser:
    """Strict evaluator for the PEP 508 marker subset used by reviewed wheels."""

    TOKEN_RE = re.compile(
        r"\s*(?:"
        r"(?P<string>'[^'\\]*'|\"[^\"\\]*\")|"
        r"(?P<operator>==|!=|<=|>=|<|>)|"
        r"(?P<left>\()|(?P<right>\))|"
        r"(?P<word>[A-Za-z_][A-Za-z0-9_.-]*)"
        r")"
    )

    def __init__(self, marker: str, environment: dict[str, str]):
        self.environment = environment
        self.tokens: list[tuple[str, str]] = []
        position = 0
        while position < len(marker):
            match = self.TOKEN_RE.match(marker, position)
            if match is None:
                raise RuntimeLockError(f"unsupported dependency marker syntax: {marker}")
            kind = match.lastgroup
            assert kind is not None
            self.tokens.append((kind, match.group(kind)))
            position = match.end()
        self.position = 0

    def _peek(self, value: str | None = None) -> bool:
        if self.position >= len(self.tokens):
            return False
        return value is None or self.tokens[self.position][1].lower() == value

    def _take(self, value: str | None = None) -> tuple[str, str]:
        if not self._peek(value):
            expected = value or "marker token"
            raise RuntimeLockError(f"dependency marker expected {expected}")
        token = self.tokens[self.position]
        self.position += 1
        return token

    def parse(self) -> bool:
        result = self._parse_or()
        if self.position != len(self.tokens):
            raise RuntimeLockError("dependency marker has trailing syntax")
        return result

    def _parse_or(self) -> bool:
        values = [self._parse_and()]
        while self._peek("or"):
            self._take("or")
            values.append(self._parse_and())
        return any(values)

    def _parse_and(self) -> bool:
        values = [self._parse_factor()]
        while self._peek("and"):
            self._take("and")
            values.append(self._parse_factor())
        return all(values)

    def _parse_factor(self) -> bool:
        if self._peek() and self.tokens[self.position][0] == "left":
            self._take()
            result = self._parse_or()
            if not self._peek() or self.tokens[self.position][0] != "right":
                raise RuntimeLockError("dependency marker has an unmatched parenthesis")
            self._take()
            return result
        left, left_is_version = self._operand()
        if self._peek("not"):
            self._take("not")
            self._take("in")
            operator = "not in"
        elif self._peek("in"):
            self._take("in")
            operator = "in"
        else:
            kind, operator = self._take()
            if kind != "operator":
                raise RuntimeLockError("dependency marker comparison operator is invalid")
        right, right_is_version = self._operand()
        return self._compare(left, right, operator, left_is_version or right_is_version)

    def _operand(self) -> tuple[str, bool]:
        kind, value = self._take()
        if kind == "string":
            return value[1:-1], False
        if kind != "word" or value in {"and", "or", "in", "not"}:
            raise RuntimeLockError("dependency marker operand is invalid")
        if value not in self.environment:
            raise RuntimeLockError(f"dependency marker variable is unsupported: {value}")
        return self.environment[value], value in {
            "python_version",
            "python_full_version",
            "implementation_version",
        }

    @staticmethod
    def _version_key(value: str) -> tuple[tuple[int, object], ...]:
        parts = re.findall(r"[0-9]+|[A-Za-z]+", value)
        return tuple((0, int(part)) if part.isdigit() else (1, part.lower()) for part in parts)

    @classmethod
    def _compare(
        cls, left: str, right: str, operator: str, is_version: bool
    ) -> bool:
        if operator == "in":
            return left in right
        if operator == "not in":
            return left not in right
        left_value: object = cls._version_key(left) if is_version else left
        right_value: object = cls._version_key(right) if is_version else right
        comparisons = {
            "==": lambda: left_value == right_value,
            "!=": lambda: left_value != right_value,
            "<": lambda: left_value < right_value,
            "<=": lambda: left_value <= right_value,
            ">": lambda: left_value > right_value,
            ">=": lambda: left_value >= right_value,
        }
        if operator not in comparisons:
            raise RuntimeLockError(f"dependency marker operator is unsupported: {operator}")
        return comparisons[operator]()


DEPENDENCY_RE = re.compile(
    r"\s*(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[(?P<extras>[A-Za-z0-9_,.-]+)\])?"
    r"(?P<constraint>\s*(?:\([^)]*\)|[^;]*))?\s*"
)


def _parse_dependency(value: str) -> tuple[str, frozenset[str], str | None]:
    requirement, separator, marker = value.partition(";")
    if "@" in requirement or "://" in requirement:
        raise RuntimeLockError("wheel dependency contains a direct reference")
    match = DEPENDENCY_RE.fullmatch(requirement)
    if match is None:
        raise RuntimeLockError(f"wheel dependency is unsupported: {value}")
    constraint = (match.group("constraint") or "").strip()
    if constraint and re.fullmatch(r"[()0-9A-Za-z.*+!<>=~,_ -]+", constraint) is None:
        raise RuntimeLockError(f"wheel dependency constraint is unsupported: {value}")
    extras = frozenset(
        normalize_name(extra.strip())
        for extra in (match.group("extras") or "").split(",")
        if extra.strip()
    )
    return normalize_name(match.group("name")), extras, marker.strip() if separator else None


def _marker_environment(extra: str) -> dict[str, str]:
    return {
        "extra": extra,
        "implementation_name": "cpython",
        "implementation_version": "3.11.0",
        "os_name": "posix",
        "platform_machine": "x86_64",
        "platform_python_implementation": "CPython",
        "platform_release": "",
        "platform_system": "Linux",
        "platform_version": "",
        "python_full_version": "3.11.0",
        "python_version": "3.11",
        "sys_platform": "linux",
    }


def _marker_is_active(marker: str | None, extras: set[str]) -> bool:
    if marker is None:
        return True
    candidates = extras or {""}
    return any(_MarkerParser(marker, _marker_environment(extra)).parse() for extra in candidates)


def verify_dependency_closure(
    direct: dict[str, DirectRequirement],
    locked: dict[str, LockedRequirement],
    requires_dist: dict[str, list[str]],
) -> None:
    if set(requires_dist) != set(locked):
        raise RuntimeLockError("wheel dependency metadata does not equal the runtime lock")
    selected_extras = {name: set(record.extras) for name, record in direct.items()}
    reachable = set(direct)
    pending = list(direct)
    processed: dict[str, frozenset[str]] = {}
    while pending:
        name = pending.pop()
        extras = selected_extras.setdefault(name, set())
        frozen_extras = frozenset(extras)
        if processed.get(name) == frozen_extras:
            continue
        processed[name] = frozen_extras
        if name not in locked:
            raise RuntimeLockError(f"active dependency is absent from lock: {name}")
        for raw_dependency in requires_dist[name]:
            dependency, dependency_extras, marker = _parse_dependency(raw_dependency)
            if not _marker_is_active(marker, extras):
                continue
            if dependency not in locked:
                raise RuntimeLockError(f"active dependency is absent from lock: {dependency}")
            reachable.add(dependency)
            existing = selected_extras.setdefault(dependency, set())
            before = frozenset(existing)
            existing.update(dependency_extras)
            if processed.get(dependency) != frozenset(existing) or before != frozenset(existing):
                pending.append(dependency)
    unexpected = sorted(set(locked) - reachable)
    if unexpected:
        raise RuntimeLockError(
            "runtime lock contains distributions outside the active dependency closure: "
            + ", ".join(unexpected)
        )


def load_profile(path: pathlib.Path) -> tuple[dict[str, object], bytes]:
    profile, raw = _load_json(path, label="runtime profile")
    _exact_keys(
        profile,
        {
            "accepted_wheel_tags",
            "bootstrap_lock_sha256",
            "download_target",
            "kernel",
            "lock_sha256",
            "machine",
            "operating_system",
            "profile_id",
            "python",
            "requirements_sha256",
            "schema_version",
        },
        label="runtime profile",
    )
    if profile["schema_version"] != 1:
        raise RuntimeLockError("unsupported runtime profile schema")
    if not isinstance(profile["profile_id"], str) or re.fullmatch(
        r"tinyzkp-billing-[a-z0-9_-]+-v[1-9][0-9]*", profile["profile_id"]
    ) is None:
        raise RuntimeLockError("runtime profile ID is malformed")
    if profile["kernel"] != "linux" or profile["machine"] != "x86_64":
        raise RuntimeLockError("production billing profile must target Linux x86_64")
    operating_system = profile["operating_system"]
    if not isinstance(operating_system, dict):
        raise RuntimeLockError("operating_system must be an object")
    _exact_keys(operating_system, {"id", "version_id"}, label="operating_system")
    if operating_system != {"id": "debian", "version_id": "12"}:
        raise RuntimeLockError("production billing profile must target Debian 12")
    python = profile["python"]
    if not isinstance(python, dict):
        raise RuntimeLockError("python profile must be an object")
    _exact_keys(
        python,
        {"abi", "executable", "implementation", "major", "minor"},
        label="python profile",
    )
    if python != {
        "abi": "cp311",
        "executable": "/usr/bin/python3",
        "implementation": "cpython",
        "major": 3,
        "minor": 11,
    }:
        raise RuntimeLockError("production billing profile must target /usr/bin CPython 3.11")
    download = profile["download_target"]
    if not isinstance(download, dict):
        raise RuntimeLockError("download_target must be an object")
    _exact_keys(
        download,
        {"abi", "implementation", "platform", "python_version"},
        label="download_target",
    )
    if download != {
        "abi": "cp311",
        "implementation": "cp",
        "platform": "manylinux2014_x86_64",
        "python_version": "3.11",
    }:
        raise RuntimeLockError("download target is not the reviewed cp311 Linux target")
    tags = profile["accepted_wheel_tags"]
    if (
        not isinstance(tags, list)
        or not tags
        or len(tags) != len(set(tags))
        or any(not isinstance(tag, str) or TAG_RE.fullmatch(tag) is None for tag in tags)
    ):
        raise RuntimeLockError("accepted wheel tags are malformed")
    for key in ("requirements_sha256", "lock_sha256", "bootstrap_lock_sha256"):
        if not isinstance(profile[key], str) or HASH_RE.fullmatch(profile[key]) is None:
            raise RuntimeLockError(f"runtime profile {key} is malformed")
    return profile, raw


def load_manifest(path: pathlib.Path) -> tuple[dict[str, object], bytes, list[Artifact]]:
    manifest, raw = _load_json(path, label="wheelhouse manifest")
    _exact_keys(
        manifest,
        {
            "artifacts",
            "bootstrap_lock_sha256",
            "lock_sha256",
            "profile_id",
            "profile_sha256",
            "requirements_sha256",
            "schema_version",
        },
        label="wheelhouse manifest",
    )
    if manifest["schema_version"] != 1:
        raise RuntimeLockError("unsupported wheelhouse manifest schema")
    artifacts_value = manifest["artifacts"]
    if not isinstance(artifacts_value, list) or not artifacts_value or len(artifacts_value) > 128:
        raise RuntimeLockError("wheelhouse artifact list is invalid")
    artifacts: list[Artifact] = []
    filenames: set[str] = set()
    names: set[str] = set()
    for index, item in enumerate(artifacts_value):
        if not isinstance(item, dict):
            raise RuntimeLockError(f"wheelhouse artifact {index} must be an object")
        _exact_keys(
            item,
            {"filename", "name", "role", "sha256", "size", "version"},
            label=f"wheelhouse artifact {index}",
        )
        filename = item["filename"]
        name = item["name"]
        version = item["version"]
        digest = item["sha256"]
        size = item["size"]
        role = item["role"]
        if (
            not isinstance(filename, str)
            or pathlib.PurePosixPath(filename).name != filename
            or not filename.endswith(".whl")
            or len(filename) > 255
        ):
            raise RuntimeLockError(f"wheelhouse artifact {index} filename is unsafe")
        if not isinstance(name, str) or NAME_RE.fullmatch(name) is None or normalize_name(name) != name:
            raise RuntimeLockError(f"wheelhouse artifact {index} name is not normalized")
        if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
            raise RuntimeLockError(f"wheelhouse artifact {index} version is malformed")
        if not isinstance(digest, str) or HASH_RE.fullmatch(digest) is None:
            raise RuntimeLockError(f"wheelhouse artifact {index} hash is malformed")
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_WHEEL_BYTES:
            raise RuntimeLockError(f"wheelhouse artifact {index} size is invalid")
        if role not in {"bootstrap", "runtime"}:
            raise RuntimeLockError(f"wheelhouse artifact {index} role is invalid")
        if filename in filenames or name in names:
            raise RuntimeLockError("wheelhouse manifest duplicates a filename or distribution")
        filenames.add(filename)
        names.add(name)
        artifacts.append(Artifact(filename, name, version, digest, size, role))
    return manifest, raw, artifacts


def verify_metadata(
    *,
    profile_path: pathlib.Path = DEFAULT_PROFILE,
    requirements_path: pathlib.Path = DEFAULT_REQUIREMENTS,
    lock_path: pathlib.Path = DEFAULT_LOCK,
    bootstrap_lock_path: pathlib.Path = DEFAULT_BOOTSTRAP_LOCK,
    manifest_path: pathlib.Path = DEFAULT_MANIFEST,
) -> tuple[dict[str, object], list[Artifact], dict[str, LockedRequirement]]:
    profile, profile_raw = load_profile(profile_path)
    manifest, _manifest_raw, artifacts = load_manifest(manifest_path)
    requirements_raw = _read_regular(
        requirements_path, label="direct requirements", limit=MAX_METADATA_BYTES
    )
    lock_raw = _read_regular(lock_path, label="runtime lock", limit=MAX_METADATA_BYTES)
    bootstrap_raw = _read_regular(
        bootstrap_lock_path, label="bootstrap lock", limit=MAX_METADATA_BYTES
    )
    runtime = _parse_records(lock_raw)
    bootstrap = _parse_records(bootstrap_raw, bootstrap=True)
    direct = _parse_direct_requirements(requirements_raw)
    expected_hashes = {
        "requirements_sha256": _sha256_bytes(requirements_raw),
        "lock_sha256": _sha256_bytes(lock_raw),
        "bootstrap_lock_sha256": _sha256_bytes(bootstrap_raw),
    }
    for key, expected in expected_hashes.items():
        if profile[key] != expected or manifest[key] != expected:
            raise RuntimeLockError(f"{key} does not bind the current input file")
    if manifest["profile_id"] != profile["profile_id"]:
        raise RuntimeLockError("manifest profile ID does not match runtime profile")
    if manifest["profile_sha256"] != _sha256_bytes(profile_raw):
        raise RuntimeLockError("manifest does not bind the current runtime profile")
    for name, direct_record in direct.items():
        record = runtime.get(name)
        if record is None or record.version != direct_record.version:
            raise RuntimeLockError(f"direct requirement {name} is absent or version-skewed")
    runtime_artifacts = {item.name: item for item in artifacts if item.role == "runtime"}
    bootstrap_artifacts = {item.name: item for item in artifacts if item.role == "bootstrap"}
    if set(runtime_artifacts) != set(runtime):
        raise RuntimeLockError("runtime manifest distributions do not equal the lock")
    if set(bootstrap_artifacts) != set(bootstrap):
        raise RuntimeLockError("bootstrap manifest distributions do not equal the bootstrap lock")
    for records, artifact_map in (
        (runtime, runtime_artifacts),
        (bootstrap, bootstrap_artifacts),
    ):
        for name, record in records.items():
            artifact = artifact_map[name]
            if artifact.version != record.version or artifact.sha256 != record.sha256:
                raise RuntimeLockError(f"manifest artifact does not match locked {name}")
    return profile, artifacts, runtime


def _wheel_metadata(
    raw: bytes, *, filename: str, accepted_tags: set[str]
) -> tuple[str, str, set[str], list[str]]:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_WHEEL_MEMBERS:
                raise RuntimeLockError(f"wheel member count is invalid: {filename}")
            uncompressed = 0
            metadata_members: list[zipfile.ZipInfo] = []
            wheel_members: list[zipfile.ZipInfo] = []
            record_members: list[zipfile.ZipInfo] = []
            for member in members:
                member_path = pathlib.PurePosixPath(member.filename)
                if (
                    member.filename.startswith("/")
                    or "\\" in member.filename
                    or "\x00" in member.filename
                    or ".." in member_path.parts
                ):
                    raise RuntimeLockError(f"wheel contains an unsafe member: {filename}")
                file_type = (member.external_attr >> 16) & 0o170000
                if file_type == stat.S_IFLNK:
                    raise RuntimeLockError(f"wheel contains a symlink: {filename}")
                if member.filename.endswith(".pth"):
                    raise RuntimeLockError(f"wheel contains executable path configuration: {filename}")
                uncompressed += member.file_size
                if uncompressed > MAX_WHEEL_UNCOMPRESSED_BYTES:
                    raise RuntimeLockError(f"wheel expands beyond its limit: {filename}")
                if member.filename.endswith(".dist-info/METADATA"):
                    metadata_members.append(member)
                elif member.filename.endswith(".dist-info/WHEEL"):
                    wheel_members.append(member)
                elif member.filename.endswith(".dist-info/RECORD"):
                    record_members.append(member)
            if not (
                len(metadata_members) == len(wheel_members) == len(record_members) == 1
            ):
                raise RuntimeLockError(f"wheel metadata layout is invalid: {filename}")
            prefixes = {
                member.filename.rsplit("/", 1)[0]
                for member in (metadata_members[0], wheel_members[0], record_members[0])
            }
            if len(prefixes) != 1:
                raise RuntimeLockError(f"wheel dist-info directories disagree: {filename}")
            metadata_raw = archive.read(metadata_members[0])
            wheel_raw = archive.read(wheel_members[0])
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, RuntimeLockError):
            raise
        raise RuntimeLockError(f"wheel cannot be safely inspected: {filename}") from error
    message = BytesParser().parsebytes(metadata_raw)
    name = normalize_name(str(message.get("Name", "")).strip())
    version = str(message.get("Version", "")).strip()
    if NAME_RE.fullmatch(name) is None or VERSION_RE.fullmatch(version) is None:
        raise RuntimeLockError(f"wheel package metadata is malformed: {filename}")
    try:
        wheel_message = BytesParser().parsebytes(wheel_raw)
        tags = {tag.strip() for tag in wheel_message.get_all("Tag", []) if tag.strip()}
    except (UnicodeDecodeError, ValueError) as error:
        raise RuntimeLockError(f"wheel tag metadata is malformed: {filename}") from error
    if not tags or not tags.issubset(accepted_tags):
        raise RuntimeLockError(f"wheel has an unauthorized compatibility tag: {filename}")
    requires_dist = [str(value).strip() for value in message.get_all("Requires-Dist", [])]
    if any(not value or len(value) > 2048 for value in requires_dist):
        raise RuntimeLockError(f"wheel dependency metadata is malformed: {filename}")
    return name, version, tags, requires_dist


def verify_wheelhouse(
    wheelhouse: pathlib.Path,
    *,
    production_permissions: bool = False,
    profile_path: pathlib.Path = DEFAULT_PROFILE,
    requirements_path: pathlib.Path = DEFAULT_REQUIREMENTS,
    lock_path: pathlib.Path = DEFAULT_LOCK,
    bootstrap_lock_path: pathlib.Path = DEFAULT_BOOTSTRAP_LOCK,
    manifest_path: pathlib.Path = DEFAULT_MANIFEST,
) -> tuple[list[Artifact], pathlib.Path]:
    profile, artifacts, runtime = verify_metadata(
        profile_path=profile_path,
        requirements_path=requirements_path,
        lock_path=lock_path,
        bootstrap_lock_path=bootstrap_lock_path,
        manifest_path=manifest_path,
    )
    try:
        root_metadata = wheelhouse.lstat()
    except OSError as error:
        raise RuntimeLockError(f"wheelhouse is unavailable: {wheelhouse}") from error
    if wheelhouse.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise RuntimeLockError("wheelhouse must be a real directory")
    if production_permissions and (
        root_metadata.st_uid != 0 or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise RuntimeLockError("production wheelhouse must be root-owned mode 0700")
    try:
        children = list(wheelhouse.iterdir())
    except OSError as error:
        raise RuntimeLockError("wheelhouse cannot be enumerated") from error
    expected = {item.filename: item for item in artifacts}
    if {child.name for child in children} != set(expected):
        raise RuntimeLockError("wheelhouse files do not exactly equal the reviewed manifest")
    accepted_tags = set(profile["accepted_wheel_tags"])
    bootstrap_path: pathlib.Path | None = None
    requires_dist: dict[str, list[str]] = {}
    for child in children:
        artifact = expected[child.name]
        try:
            metadata = child.lstat()
        except OSError as error:
            raise RuntimeLockError(f"wheel is unavailable: {child.name}") from error
        if (
            child.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise RuntimeLockError(f"wheel must be a private regular file: {child.name}")
        if production_permissions and (
            metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o222
        ):
            raise RuntimeLockError(f"production wheel must be root-owned and immutable: {child.name}")
        if metadata.st_size != artifact.size:
            raise RuntimeLockError(f"wheel size differs from manifest: {child.name}")
        raw = _read_regular(child, label=f"wheel {child.name}", limit=MAX_WHEEL_BYTES)
        if _sha256_bytes(raw) != artifact.sha256:
            raise RuntimeLockError(f"wheel hash differs from manifest: {child.name}")
        name, version, _tags, dependencies = _wheel_metadata(
            raw, filename=child.name, accepted_tags=accepted_tags
        )
        if name != artifact.name or version != artifact.version:
            raise RuntimeLockError(f"wheel metadata differs from manifest: {child.name}")
        if artifact.role == "bootstrap":
            if bootstrap_path is not None:
                raise RuntimeLockError("wheelhouse has multiple bootstrap artifacts")
            bootstrap_path = child.resolve(strict=True)
        else:
            requires_dist[name] = dependencies
    if bootstrap_path is None:
        raise RuntimeLockError("wheelhouse lacks its bootstrap artifact")
    direct_raw = _read_regular(
        requirements_path, label="direct requirements", limit=MAX_METADATA_BYTES
    )
    verify_dependency_closure(
        _parse_direct_requirements(direct_raw), runtime, requires_dist
    )
    return artifacts, bootstrap_path


def _parse_os_release(path: pathlib.Path) -> tuple[str, str]:
    raw = _read_regular(path, label="OS release metadata", limit=64 * 1024)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeLockError("OS release metadata must be UTF-8") from error
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            raise RuntimeLockError(f"OS release key is duplicated: {key}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values.get("ID", ""), values.get("VERSION_ID", "")


def collect_host_facts(
    os_release_path: pathlib.Path = pathlib.Path("/usr/lib/os-release"),
) -> HostFacts:
    os_id, os_version_id = _parse_os_release(os_release_path)
    return HostFacts(
        kernel=sys.platform,
        machine=platform.machine(),
        os_id=os_id,
        os_version_id=os_version_id,
        implementation=sys.implementation.name,
        major=sys.version_info.major,
        minor=sys.version_info.minor,
        soabi=str(sysconfig.get_config_var("SOABI") or ""),
        executable=os.path.abspath(sys.executable),
    )


def verify_host_facts(profile: dict[str, object], facts: HostFacts) -> None:
    python = profile["python"]
    operating_system = profile["operating_system"]
    assert isinstance(python, dict)
    assert isinstance(operating_system, dict)
    expected = {
        "kernel": profile["kernel"],
        "machine": profile["machine"],
        "os_id": operating_system["id"],
        "os_version_id": operating_system["version_id"],
        "implementation": python["implementation"],
        "major": python["major"],
        "minor": python["minor"],
        "executable": python["executable"],
    }
    actual = {
        "kernel": facts.kernel,
        "machine": facts.machine,
        "os_id": facts.os_id,
        "os_version_id": facts.os_version_id,
        "implementation": facts.implementation,
        "major": facts.major,
        "minor": facts.minor,
        "executable": facts.executable,
    }
    mismatches = [key for key in expected if actual[key] != expected[key]]
    if mismatches:
        raise RuntimeLockError(
            "host does not match the reviewed runtime profile: " + ", ".join(mismatches)
        )
    if not facts.soabi.startswith("cpython-311-"):
        raise RuntimeLockError("host Python SOABI is not the reviewed CPython 3.11 ABI")


def _base_runtime_paths() -> tuple[set[pathlib.Path], dict[pathlib.Path, str]]:
    fixed = {
        pathlib.Path("/usr/bin/bash"): "loader_tool",
        pathlib.Path("/usr/bin/python3.11"): "interpreter",
        pathlib.Path("/usr/bin/ldd"): "loader_tool",
        pathlib.Path("/usr/lib/os-release"): "os_release",
    }
    stdlib = pathlib.Path("/usr/lib/python3.11")
    try:
        stdlib_metadata = stdlib.lstat()
    except OSError as error:
        raise RuntimeLockError("reviewed Python standard library root is unavailable") from error
    if stdlib.is_symlink() or not stat.S_ISDIR(stdlib_metadata.st_mode):
        raise RuntimeLockError("reviewed Python standard library root must be a real directory")
    paths = set(fixed)
    categories = dict(fixed)
    for current, directory_names, file_names in os.walk(stdlib, followlinks=False):
        current_path = pathlib.Path(current)
        for name in directory_names:
            candidate = current_path / name
            if candidate.is_symlink():
                raise RuntimeLockError("standard library contains an unmodeled directory symlink")
        for name in file_names:
            candidate = current_path / name
            try:
                metadata = candidate.lstat()
            except OSError as error:
                raise RuntimeLockError("standard library changed during enumeration") from error
            if candidate.is_symlink():
                raise RuntimeLockError("standard library contains an unmodeled file symlink")
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RuntimeLockError("standard library contains a non-private regular file")
            paths.add(candidate)
            categories[candidate] = "stdlib"
            if len(paths) > MAX_HOST_RUNTIME_FILES:
                raise RuntimeLockError("host runtime inventory exceeds its file limit")
    return paths, categories


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_runtime_directory_metadata(
    path: pathlib.Path, metadata: os.stat_result
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeLockError(f"host runtime parent must be a real directory: {path}")
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise RuntimeLockError(f"host runtime parent must be root-owned: {path}")
    if mode & 0o022:
        raise RuntimeLockError(
            f"host runtime parent cannot be group/world writable: {path}"
        )


def _validate_runtime_file_metadata(path: pathlib.Path, metadata: os.stat_result) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeLockError(f"host runtime file must be a regular non-symlink: {path}")
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise RuntimeLockError(f"host runtime file must be root-owned: {path}")
    if metadata.st_nlink != 1:
        raise RuntimeLockError(f"host runtime file must have exactly one link: {path}")
    if mode & 0o022:
        raise RuntimeLockError(
            f"host runtime file cannot be group/world writable: {path}"
        )


def _safe_parent_chain(path: pathlib.Path) -> tuple[list[dict[str, object]], str]:
    """Validate and bind every directory used to reach an inventory file."""

    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeLockError(f"host runtime path is not canonical and absolute: {path}")
    try:
        if path.resolve(strict=True) != path:
            raise RuntimeLockError(f"host runtime path traverses a symlink: {path}")
    except OSError as error:
        raise RuntimeLockError(f"host runtime path is unavailable: {path}") from error
    parents = list(reversed(path.parents))
    chain: list[dict[str, object]] = []
    for parent in parents:
        try:
            metadata = parent.lstat()
        except OSError as error:
            raise RuntimeLockError(f"host runtime parent is unavailable: {parent}") from error
        _validate_runtime_directory_metadata(parent, metadata)
        mode = stat.S_IMODE(metadata.st_mode)
        chain.append(
            {
                "gid": metadata.st_gid,
                "mode": mode,
                "path": str(parent),
                "uid": metadata.st_uid,
            }
        )
    return chain, _sha256_bytes(_canonical_json_bytes(chain))


def _secure_runtime_file_facts(
    path: pathlib.Path,
) -> tuple[os.stat_result, str]:
    _chain, parent_chain_sha256 = _safe_parent_chain(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RuntimeLockError(f"host runtime file is unavailable: {path}") from error
    _validate_runtime_file_metadata(path, metadata)
    return metadata, parent_chain_sha256


def _runtime_entry(path: pathlib.Path, category: str) -> dict[str, object]:
    before, parent_chain_sha256 = _secure_runtime_file_facts(path)
    raw = _read_regular(path, label=f"host runtime file {path}", limit=MAX_WHEEL_BYTES)
    after, after_parent_chain_sha256 = _secure_runtime_file_facts(path)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or after_parent_chain_sha256 != parent_chain_sha256
    ):
        raise RuntimeLockError(f"host runtime file or parent chain changed: {path}")
    return {
        "category": category,
        "gid": after.st_gid,
        "mode": stat.S_IMODE(after.st_mode),
        "nlink": after.st_nlink,
        "parent_chain_sha256": parent_chain_sha256,
        "path": str(path),
        "sha256": _sha256_bytes(raw),
        "size": len(raw),
        "uid": after.st_uid,
    }


def _is_elf(path: pathlib.Path) -> bool:
    raw = _read_regular(path, label=f"host ELF candidate {path}", limit=MAX_WHEEL_BYTES)
    return raw.startswith(b"\x7fELF")


def _ldd_dependencies(inputs: set[pathlib.Path]) -> set[pathlib.Path]:
    dependencies: set[pathlib.Path] = set()
    pending: list[pathlib.Path] = []
    for path in sorted(inputs):
        _secure_runtime_file_facts(path)
        if _is_elf(path):
            pending.append(path)
    inspected: set[pathlib.Path] = set()
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ": "UTC",
    }
    while pending:
        candidate = pending.pop()
        resolved_candidate = candidate.resolve(strict=True)
        if resolved_candidate in inspected:
            continue
        inspected.add(resolved_candidate)
        if len(inspected) > 2048:
            raise RuntimeLockError("host shared-library dependency graph exceeds its limit")
        result = subprocess.run(
            ("/usr/bin/ldd", str(resolved_candidate)),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0 or "not found" in result.stdout:
            raise RuntimeLockError(f"ldd could not resolve host runtime input: {candidate}")
        for raw_path in re.findall(r"(?:=>\s*)?(/[^\s(]+)", result.stdout):
            try:
                dependency = pathlib.Path(raw_path).resolve(strict=True)
                metadata = dependency.lstat()
            except OSError as error:
                raise RuntimeLockError("ldd reported an unavailable dependency") from error
            if dependency.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise RuntimeLockError("ldd dependency does not resolve to a regular file")
            _secure_runtime_file_facts(dependency)
            if dependency not in dependencies:
                dependencies.add(dependency)
                pending.append(dependency)
    return dependencies


def _secure_runtime_tree_paths(
    root: pathlib.Path, *, category: str
) -> tuple[set[pathlib.Path], dict[pathlib.Path, str]]:
    if not root.is_absolute() or ".." in root.parts:
        raise RuntimeLockError("runtime tree root must be canonical and absolute")
    _safe_parent_chain(root)
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise RuntimeLockError(f"runtime tree is unavailable: {root}") from error
    _validate_runtime_directory_metadata(root, root_metadata)

    paths: set[pathlib.Path] = set()
    categories: dict[pathlib.Path, str] = {}
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        current_path = pathlib.Path(current)
        try:
            current_metadata = current_path.lstat()
        except OSError as error:
            raise RuntimeLockError("runtime tree changed during enumeration") from error
        _validate_runtime_directory_metadata(current_path, current_metadata)
        for name in directory_names:
            candidate = current_path / name
            try:
                metadata = candidate.lstat()
            except OSError as error:
                raise RuntimeLockError("runtime tree changed during enumeration") from error
            _validate_runtime_directory_metadata(candidate, metadata)
        for name in file_names:
            candidate = current_path / name
            _secure_runtime_file_facts(candidate)
            paths.add(candidate)
            categories[candidate] = category
            if len(paths) > MAX_HOST_RUNTIME_FILES:
                raise RuntimeLockError("host runtime inventory exceeds its file limit")
    if not paths:
        raise RuntimeLockError(f"runtime tree is empty: {root}")
    return paths, categories


def _collect_inventory(
    input_paths: set[pathlib.Path], categories: dict[pathlib.Path, str]
) -> list[dict[str, object]]:
    # Hash every explicit input before ldd is allowed to inspect it.  ldd's
    # outputs are then permission-checked before they enter the recursive graph.
    entries_by_path = {
        path: _runtime_entry(path, categories.get(path, "shared_library"))
        for path in sorted(input_paths)
    }
    dependencies = _ldd_dependencies(input_paths)
    all_paths = input_paths | dependencies
    total = 0
    entries: list[dict[str, object]] = []
    for path in sorted(all_paths):
        entry = entries_by_path.get(path)
        if entry is None:
            entry = _runtime_entry(path, categories.get(path, "shared_library"))
        total += int(entry["size"])
        if total > MAX_HOST_RUNTIME_BYTES or len(entries) >= MAX_HOST_RUNTIME_FILES:
            raise RuntimeLockError("host runtime inventory exceeds its byte or file limit")
        entries.append(entry)
    return entries


def collect_host_runtime_inventory() -> list[dict[str, object]]:
    base_paths, categories = _base_runtime_paths()
    return _collect_inventory(base_paths, categories)


def collect_production_runtime_inventory(
    venv_root: pathlib.Path = DEFAULT_VENV_ROOT,
    node_binary: pathlib.Path = DEFAULT_NODE_BINARY,
    *,
    expected_node_sha256: str = DEFAULT_NODE_SHA256,
) -> list[dict[str, object]]:
    if HASH_RE.fullmatch(expected_node_sha256) is None:
        raise RuntimeLockError("expected Node binary hash is malformed")
    base_paths, categories = _base_runtime_paths()
    venv_paths, venv_categories = _secure_runtime_tree_paths(
        venv_root, category="venv_runtime"
    )
    if not node_binary.is_absolute() or ".." in node_binary.parts:
        raise RuntimeLockError("Node binary path must be canonical and absolute")
    node_entry = _runtime_entry(node_binary, "node_binary")
    if node_entry["sha256"] != expected_node_sha256:
        raise RuntimeLockError("production Node binary differs from its reviewed pin")
    input_paths = base_paths | venv_paths | {node_binary}
    categories.update(venv_categories)
    categories[node_binary] = "node_binary"
    return _collect_inventory(input_paths, categories)


def runtime_inventory_identity(
    entries: list[dict[str, object]],
    *,
    profile_id: str,
    profile_sha256: str,
    scope: str,
) -> RuntimeIdentity:
    if scope not in {"base_host_runtime", "production_runtime"}:
        raise RuntimeLockError("runtime identity scope is invalid")
    if not isinstance(profile_id, str) or re.fullmatch(
        r"tinyzkp-billing-[a-z0-9_-]+-v[1-9][0-9]*", profile_id
    ) is None:
        raise RuntimeLockError("runtime identity profile ID is malformed")
    if not isinstance(profile_sha256, str) or HASH_RE.fullmatch(profile_sha256) is None:
        raise RuntimeLockError("runtime identity profile hash is malformed")
    parsed = _parse_provenance_entries(entries)
    ordered = [parsed[path] for path in sorted(parsed)]
    byte_count = sum(int(entry["size"]) for entry in ordered)
    if byte_count > MAX_HOST_RUNTIME_BYTES:
        raise RuntimeLockError("runtime identity exceeds its byte limit")
    payload = {
        "files": ordered,
        "profile_id": profile_id,
        "profile_sha256": profile_sha256,
        "schema_version": 1,
        "scope": scope,
    }
    return RuntimeIdentity(
        file_count=len(ordered),
        byte_count=byte_count,
        identity_sha256=_sha256_bytes(_canonical_json_bytes(payload)),
    )


def _parse_provenance_entries(value: object) -> dict[str, dict[str, object]]:
    if not isinstance(value, list) or not value or len(value) > MAX_HOST_RUNTIME_FILES:
        raise RuntimeLockError("host runtime provenance file list is invalid")
    entries: dict[str, dict[str, object]] = {}
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise RuntimeLockError(f"host runtime provenance entry {index} is invalid")
        _exact_keys(
            entry,
            {
                "category",
                "gid",
                "mode",
                "nlink",
                "parent_chain_sha256",
                "path",
                "sha256",
                "size",
                "uid",
            },
            label=f"host runtime entry {index}",
        )
        path = entry["path"]
        category = entry["category"]
        digest = entry["sha256"]
        size = entry["size"]
        if (
            not isinstance(path, str)
            or not pathlib.PurePosixPath(path).is_absolute()
            or ".." in pathlib.PurePosixPath(path).parts
            or str(pathlib.PurePosixPath(path)) != path
            or path in entries
            or len(path) > 4096
        ):
            raise RuntimeLockError(f"host runtime provenance path {index} is invalid")
        if category not in {
            "interpreter",
            "loader_tool",
            "node_binary",
            "os_release",
            "shared_library",
            "stdlib",
            "venv_runtime",
        }:
            raise RuntimeLockError(f"host runtime provenance category {index} is invalid")
        if not isinstance(digest, str) or HASH_RE.fullmatch(digest) is None:
            raise RuntimeLockError(f"host runtime provenance hash {index} is invalid")
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_WHEEL_BYTES:
            raise RuntimeLockError(f"host runtime provenance size {index} is invalid")
        if entry["uid"] != 0 or entry["gid"] != 0:
            raise RuntimeLockError(f"host runtime provenance ownership {index} is invalid")
        mode = entry["mode"]
        if (
            not isinstance(mode, int)
            or isinstance(mode, bool)
            or not 0 <= mode <= 0o7777
            or mode & 0o022
        ):
            raise RuntimeLockError(f"host runtime provenance mode {index} is invalid")
        if entry["nlink"] != 1:
            raise RuntimeLockError(f"host runtime provenance link count {index} is invalid")
        parent_digest = entry["parent_chain_sha256"]
        if not isinstance(parent_digest, str) or HASH_RE.fullmatch(parent_digest) is None:
            raise RuntimeLockError(
                f"host runtime provenance parent-chain hash {index} is invalid"
            )
        entries[path] = entry
    return entries


def verify_host_runtime_provenance(
    provenance_path: pathlib.Path,
    profile_path: pathlib.Path = DEFAULT_PROFILE,
) -> RuntimeIdentity:
    profile, profile_raw = load_profile(profile_path)
    verify_host_facts(profile, collect_host_facts())
    provenance, _raw = _load_json(provenance_path, label="host runtime provenance")
    if provenance.get("status") == "unconfigured":
        _exact_keys(
            provenance,
            {"profile_id", "reason", "schema_version", "status"},
            label="unconfigured host runtime provenance",
        )
        if provenance.get("schema_version") != 1 or provenance.get("profile_id") != profile["profile_id"]:
            raise RuntimeLockError("unconfigured host provenance does not match the runtime profile")
        raise RuntimeLockError("host interpreter/stdlib/shared-library provenance is unconfigured")
    _exact_keys(
        provenance,
        {
            "captured_at",
            "files",
            "inventory_sha256",
            "profile_id",
            "profile_sha256",
            "reviewed_at",
            "reviewer",
            "schema_version",
            "status",
        },
        label="host runtime provenance",
    )
    if provenance["schema_version"] != 2 or provenance["status"] != "reviewed":
        raise RuntimeLockError("host runtime provenance has not been independently reviewed")
    if (
        provenance["profile_id"] != profile["profile_id"]
        or provenance["profile_sha256"] != _sha256_bytes(profile_raw)
    ):
        raise RuntimeLockError("host runtime provenance does not bind the reviewed profile")
    reviewer = provenance["reviewer"]
    reviewed_at = provenance["reviewed_at"]
    captured_at = provenance["captured_at"]
    if not isinstance(reviewer, str) or not 3 <= len(reviewer.strip()) <= 200:
        raise RuntimeLockError("host runtime provenance reviewer is missing")
    if not isinstance(reviewed_at, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", reviewed_at
    ) is None:
        raise RuntimeLockError("host runtime provenance review timestamp is malformed")
    if not isinstance(captured_at, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", captured_at
    ) is None:
        raise RuntimeLockError("host runtime provenance capture timestamp is malformed")
    expected = _parse_provenance_entries(provenance["files"])
    base_paths, categories = _base_runtime_paths()
    # Verify every executable input, including ldd itself, before executing it.
    for path in base_paths:
        entry = expected.get(str(path))
        actual = _runtime_entry(path, categories[path])
        if entry != actual:
            raise RuntimeLockError(f"host base-runtime file differs from review: {path}")
    actual_entries = {entry["path"]: entry for entry in collect_host_runtime_inventory()}
    if actual_entries != expected:
        raise RuntimeLockError("host runtime inventory differs from independent review")
    identity = runtime_inventory_identity(
        list(actual_entries.values()),
        profile_id=str(profile["profile_id"]),
        profile_sha256=_sha256_bytes(profile_raw),
        scope="base_host_runtime",
    )
    if provenance["inventory_sha256"] != identity.identity_sha256:
        raise RuntimeLockError("host runtime provenance inventory identity is invalid")
    return identity


def capture_host_runtime_provenance(
    output: pathlib.Path,
    profile_path: pathlib.Path = DEFAULT_PROFILE,
) -> RuntimeIdentity:
    if output.exists() or output.is_symlink():
        raise RuntimeLockError("host runtime provenance output must not already exist")
    profile, profile_raw = load_profile(profile_path)
    verify_host_facts(profile, collect_host_facts())
    entries = collect_host_runtime_inventory()
    identity = runtime_inventory_identity(
        entries,
        profile_id=str(profile["profile_id"]),
        profile_sha256=_sha256_bytes(profile_raw),
        scope="base_host_runtime",
    )
    payload = {
        "captured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "files": entries,
        "inventory_sha256": identity.identity_sha256,
        "profile_id": profile["profile_id"],
        "profile_sha256": _sha256_bytes(profile_raw),
        "reviewed_at": "",
        "reviewer": "",
        "schema_version": 2,
        "status": "captured",
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise RuntimeLockError("host runtime provenance write failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return identity


def verify_production_runtime_identity(
    provenance_path: pathlib.Path,
    profile_path: pathlib.Path = DEFAULT_PROFILE,
    *,
    venv_root: pathlib.Path = DEFAULT_VENV_ROOT,
    node_binary: pathlib.Path = DEFAULT_NODE_BINARY,
) -> RuntimeIdentity:
    """Verify reviewed base provenance and identify every production runtime byte."""

    verify_host_runtime_provenance(provenance_path, profile_path)
    profile, profile_raw = load_profile(profile_path)
    entries = collect_production_runtime_inventory(venv_root, node_binary)
    return runtime_inventory_identity(
        entries,
        profile_id=str(profile["profile_id"]),
        profile_sha256=_sha256_bytes(profile_raw),
        scope="production_runtime",
    )


def verify_installed(lock_path: pathlib.Path = DEFAULT_LOCK) -> dict[str, str]:
    lock_raw = _read_regular(lock_path, label="runtime lock", limit=MAX_METADATA_BYTES)
    locked = _parse_records(lock_raw)
    installed: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = normalize_name(str(distribution.metadata.get("Name", "")).strip())
        version = str(distribution.version).strip()
        if not name or name in installed:
            raise RuntimeLockError("installed runtime has duplicate or malformed distributions")
        installed[name] = version
    expected = {name: record.version for name, record in locked.items()}
    if installed != expected:
        missing = sorted(set(expected) - set(installed))
        extra = sorted(set(installed) - set(expected))
        skewed = sorted(
            name for name in set(expected) & set(installed) if expected[name] != installed[name]
        )
        raise RuntimeLockError(
            f"installed distributions differ from lock (missing={missing}; extra={extra}; skewed={skewed})"
        )
    for module in ("flask", "gunicorn", "psycopg", "pytest", "stripe"):
        __import__(module)
    return installed


def _atomic_replace_bytes(path: pathlib.Path, raw: bytes, mode: int) -> None:
    temporary = path.with_name(f".{path.name}.tinyzkp-runtime-lock.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeLockError(f"runtime relocation temporary exists: {temporary}")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary, flags, mode)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise RuntimeLockError(f"runtime relocation write failed: {path}")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def relocate_venv(staging: pathlib.Path, destination: pathlib.Path) -> int:
    """Rewrite deterministic venv path records before the final atomic rename."""

    if not staging.is_absolute() or not destination.is_absolute():
        raise RuntimeLockError("venv relocation paths must be absolute")
    if staging.parent != destination.parent or staging == destination:
        raise RuntimeLockError("venv relocation paths must be distinct siblings")
    try:
        root_metadata = staging.lstat()
    except OSError as error:
        raise RuntimeLockError("staging venv is unavailable") from error
    if staging.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise RuntimeLockError("staging venv must be a real directory")
    if destination.is_symlink():
        raise RuntimeLockError("venv destination cannot be a symlink")
    if destination.exists() and not destination.is_dir():
        raise RuntimeLockError("existing venv destination must be a real directory")
    source_bytes = os.fsencode(str(staging))
    destination_bytes = os.fsencode(str(destination))
    bin_directory = staging / "bin"
    if bin_directory.is_symlink() or not bin_directory.is_dir():
        raise RuntimeLockError("staging venv bin directory is unavailable")
    rewritten = 0
    required_entry_points = {"flask", "gunicorn", "py.test", "pytest"}
    found_entry_points: set[str] = set()
    for child in bin_directory.iterdir():
        if child.is_symlink() or not child.is_file():
            continue
        raw = _read_regular(child, label=f"venv entry {child.name}", limit=16 * 1024 * 1024)
        prefix = b"#!" + source_bytes + b"/bin/python"
        if raw.startswith(prefix):
            raw = b"#!" + destination_bytes + raw[2 + len(source_bytes) :]
            _atomic_replace_bytes(child, raw, stat.S_IMODE(child.stat().st_mode))
            rewritten += 1
            if child.name in required_entry_points:
                found_entry_points.add(child.name)
    if found_entry_points != required_entry_points:
        raise RuntimeLockError("required billing entry points were not relocated")
    configuration = staging / "pyvenv.cfg"
    configuration_raw = _read_regular(
        configuration, label="staging pyvenv.cfg", limit=64 * 1024
    )
    if source_bytes in configuration_raw:
        configuration_raw = configuration_raw.replace(source_bytes, destination_bytes)
        _atomic_replace_bytes(
            configuration,
            configuration_raw,
            stat.S_IMODE(configuration.stat().st_mode),
        )
    for child in bin_directory.iterdir():
        if child.is_symlink() or not child.is_file():
            continue
        raw = _read_regular(child, label=f"relocated venv entry {child.name}", limit=16 * 1024 * 1024)
        if source_bytes in raw:
            raise RuntimeLockError(f"staging path remains in venv entry: {child.name}")
    if source_bytes in _read_regular(
        configuration, label="relocated pyvenv.cfg", limit=64 * 1024
    ):
        raise RuntimeLockError("staging path remains in pyvenv.cfg")
    return rewritten


def _download(
    output: pathlib.Path,
    *,
    profile_path: pathlib.Path,
    requirements_path: pathlib.Path,
    lock_path: pathlib.Path,
    bootstrap_lock_path: pathlib.Path,
    manifest_path: pathlib.Path,
) -> None:
    profile, _artifacts, _runtime = verify_metadata(
        profile_path=profile_path,
        requirements_path=requirements_path,
        lock_path=lock_path,
        bootstrap_lock_path=bootstrap_lock_path,
        manifest_path=manifest_path,
    )
    if output.exists() or output.is_symlink():
        raise RuntimeLockError("output wheelhouse must not already exist")
    parent = output.absolute().parent
    if not parent.is_dir() or parent.is_symlink():
        raise RuntimeLockError("output parent must be a real existing directory")
    target = profile["download_target"]
    assert isinstance(target, dict)
    work_root = pathlib.Path(tempfile.mkdtemp(prefix=".tinyzkp-wheelhouse-", dir=parent))
    work_root.chmod(0o700)
    temporary = work_root / "wheelhouse"
    home = work_root / "home"
    temporary.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    environment = {
        "CARGO_HOME": str(home / ".cargo"),
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PIP_CONFIG_FILE": os.devnull,
        "PYTHONNOUSERSITE": "1",
        "RUSTUP_HOME": str(home / ".rustup"),
    }
    base = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--isolated",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--only-binary=:all:",
        "--require-hashes",
        "--index-url",
        "https://pypi.org/simple",
        "--dest",
        str(temporary),
    ]
    target_args = [
        "--platform",
        str(target["platform"]),
        "--python-version",
        str(target["python_version"]),
        "--implementation",
        str(target["implementation"]),
        "--abi",
        str(target["abi"]),
    ]
    commands = [
        [*base, "--no-deps", "-r", str(bootstrap_lock_path)],
        [*base, *target_args, "-r", str(lock_path)],
    ]
    try:
        for command in commands:
            result = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=300,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeLockError(
                    "pip could not materialize the reviewed wheel set: " + result.stdout[-2000:]
                )
        verify_wheelhouse(
            temporary,
            profile_path=profile_path,
            requirements_path=requirements_path,
            lock_path=lock_path,
            bootstrap_lock_path=bootstrap_lock_path,
            manifest_path=manifest_path,
        )
        for child in temporary.iterdir():
            child.chmod(0o400)
        os.replace(temporary, output)
    finally:
        if work_root.exists():
            def make_removable(function: object, target: str, _error: object) -> None:
                try:
                    os.chmod(target, 0o700)
                    function(target)  # type: ignore[operator]
                except OSError:
                    pass
            try:
                shutil.rmtree(work_root, onerror=make_removable)
            except OSError:
                pass


def _common_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", type=pathlib.Path, default=DEFAULT_PROFILE)
    parser.add_argument("--requirements", type=pathlib.Path, default=DEFAULT_REQUIREMENTS)
    parser.add_argument("--lock", type=pathlib.Path, default=DEFAULT_LOCK)
    parser.add_argument(
        "--bootstrap-lock", type=pathlib.Path, default=DEFAULT_BOOTSTRAP_LOCK
    )
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_MANIFEST)


def _report(profile: dict[str, object], artifacts: list[Artifact], status: str) -> str:
    return json.dumps(
        {
            "artifact_count": len(artifacts),
            "profile_id": profile["profile_id"],
            "status": status,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    metadata_parser = subparsers.add_parser("verify-metadata")
    _common_paths(metadata_parser)
    wheelhouse_parser = subparsers.add_parser("verify-wheelhouse")
    _common_paths(wheelhouse_parser)
    wheelhouse_parser.add_argument("--wheelhouse", required=True, type=pathlib.Path)
    wheelhouse_parser.add_argument("--production-permissions", action="store_true")
    bootstrap_parser = subparsers.add_parser("bootstrap-path")
    _common_paths(bootstrap_parser)
    bootstrap_parser.add_argument("--wheelhouse", required=True, type=pathlib.Path)
    bootstrap_parser.add_argument("--production-permissions", action="store_true")
    host_parser = subparsers.add_parser("verify-host")
    host_parser.add_argument("--profile", type=pathlib.Path, default=DEFAULT_PROFILE)
    host_parser.add_argument(
        "--os-release", type=pathlib.Path, default=pathlib.Path("/usr/lib/os-release")
    )
    installed_parser = subparsers.add_parser("verify-installed")
    installed_parser.add_argument("--lock", type=pathlib.Path, default=DEFAULT_LOCK)
    relocate_parser = subparsers.add_parser("relocate-venv")
    relocate_parser.add_argument("--staging", required=True, type=pathlib.Path)
    relocate_parser.add_argument("--destination", required=True, type=pathlib.Path)
    provenance_parser = subparsers.add_parser("verify-host-provenance")
    provenance_parser.add_argument(
        "--provenance", type=pathlib.Path, default=DEFAULT_HOST_PROVENANCE
    )
    provenance_parser.add_argument("--profile", type=pathlib.Path, default=DEFAULT_PROFILE)
    capture_parser = subparsers.add_parser("capture-host-provenance")
    capture_parser.add_argument("--output", required=True, type=pathlib.Path)
    capture_parser.add_argument("--profile", type=pathlib.Path, default=DEFAULT_PROFILE)
    runtime_identity_parser = subparsers.add_parser("verify-production-runtime")
    runtime_identity_parser.add_argument(
        "--provenance", type=pathlib.Path, default=DEFAULT_HOST_PROVENANCE
    )
    runtime_identity_parser.add_argument(
        "--profile", type=pathlib.Path, default=DEFAULT_PROFILE
    )
    runtime_identity_parser.add_argument(
        "--venv-root", type=pathlib.Path, default=DEFAULT_VENV_ROOT
    )
    runtime_identity_parser.add_argument(
        "--node-binary", type=pathlib.Path, default=DEFAULT_NODE_BINARY
    )
    download_parser = subparsers.add_parser("download")
    _common_paths(download_parser)
    download_parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-metadata":
            profile, artifacts, _runtime = verify_metadata(
                profile_path=args.profile,
                requirements_path=args.requirements,
                lock_path=args.lock,
                bootstrap_lock_path=args.bootstrap_lock,
                manifest_path=args.manifest,
            )
            print(_report(profile, artifacts, "metadata_verified"))
        elif args.command in {"verify-wheelhouse", "bootstrap-path"}:
            artifacts, bootstrap = verify_wheelhouse(
                args.wheelhouse,
                production_permissions=args.production_permissions,
                profile_path=args.profile,
                requirements_path=args.requirements,
                lock_path=args.lock,
                bootstrap_lock_path=args.bootstrap_lock,
                manifest_path=args.manifest,
            )
            if args.command == "bootstrap-path":
                print(bootstrap)
            else:
                profile, _raw = load_profile(args.profile)
                print(_report(profile, artifacts, "wheelhouse_verified"))
        elif args.command == "verify-host":
            profile, _raw = load_profile(args.profile)
            verify_host_facts(profile, collect_host_facts(args.os_release))
            print(
                json.dumps(
                    {"profile_id": profile["profile_id"], "status": "host_verified"},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.command == "verify-installed":
            installed = verify_installed(args.lock)
            print(
                json.dumps(
                    {"distribution_count": len(installed), "status": "installed_verified"},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.command == "relocate-venv":
            rewritten = relocate_venv(args.staging, args.destination)
            print(
                json.dumps(
                    {"entry_points_rewritten": rewritten, "status": "venv_relocated"},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.command == "verify-host-provenance":
            identity = verify_host_runtime_provenance(args.provenance, args.profile)
            print(
                json.dumps(
                    {
                        "byte_count": identity.byte_count,
                        "file_count": identity.file_count,
                        "identity_sha256": identity.identity_sha256,
                        "status": "host_provenance_verified",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.command == "capture-host-provenance":
            identity = capture_host_runtime_provenance(args.output, args.profile)
            print(
                json.dumps(
                    {
                        "byte_count": identity.byte_count,
                        "file_count": identity.file_count,
                        "identity_sha256": identity.identity_sha256,
                        "status": "host_provenance_captured",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.command == "verify-production-runtime":
            identity = verify_production_runtime_identity(
                args.provenance,
                args.profile,
                venv_root=args.venv_root,
                node_binary=args.node_binary,
            )
            profile, _raw = load_profile(args.profile)
            print(
                json.dumps(
                    {
                        "byte_count": identity.byte_count,
                        "file_count": identity.file_count,
                        "identity_sha256": identity.identity_sha256,
                        "node_sha256": DEFAULT_NODE_SHA256,
                        "profile_id": profile["profile_id"],
                        "status": "production_runtime_verified",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.command == "download":
            _download(
                args.output,
                profile_path=args.profile,
                requirements_path=args.requirements,
                lock_path=args.lock,
                bootstrap_lock_path=args.bootstrap_lock,
                manifest_path=args.manifest,
            )
            print(json.dumps({"status": "download_verified"}, separators=(",", ":")))
        else:  # pragma: no cover - argparse enforces the command set.
            raise RuntimeLockError("unknown command")
    except (RuntimeLockError, OSError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
