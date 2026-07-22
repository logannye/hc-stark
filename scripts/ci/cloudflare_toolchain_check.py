#!/usr/bin/env python3
"""Validate TinyZKP's exact production Node and Wrangler toolchain.

Static validation binds the reviewed profile to the committed npm lock. Runtime
validation additionally proves that the explicit production Node executable and
the complete, read-only npm installation match that profile. No command is
resolved through PATH and no Cloudflare API is contacted by this check.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import platform
import re
import stat
import subprocess
import sys
import tempfile
import urllib.parse
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "release" / "cloudflare-production-toolchain-v1.json"
PROFILE_ID = "tinyzkp-cloudflare-production-v1"
TRUSTED_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_NODE_BYTES = 256 * 1024 * 1024
MAX_INSTALL_BYTES = 1024 * 1024 * 1024
MAX_INSTALL_FILES = 50_000
MATERIALIZATION_FILENAME = "materialization.json"
MATERIALIZATION_SCHEMA_VERSION = 1
PRODUCTION_RUNTIME_ROOT = pathlib.Path("/var/lib/tinyzkp-runtime")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
NODE_VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
PACKAGE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
LOCKED_VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
PACKAGE_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")


class ToolchainError(ValueError):
    """The production JavaScript toolchain is unpinned, unsafe, or changed."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ToolchainError(f"JSON object duplicates {key!r}")
        result[key] = value
    return result


def _strict_json_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    if len(raw) > MAX_JSON_BYTES:
        raise ToolchainError(f"{label} exceeds the {MAX_JSON_BYTES}-byte limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ToolchainError(f"{label} contains invalid JSON number {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolchainError(f"{label} must be strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ToolchainError(f"{label} must contain one JSON object")
    return value


def _read_source_json(
    path: pathlib.Path, *, label: str
) -> tuple[dict[str, Any], bytes]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ToolchainError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ToolchainError(f"{label} must be a non-symlink regular file")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ToolchainError(f"{label} is unreadable") from error
    return _strict_json_bytes(raw, label=label), raw


def validate_root_materialization_source(path: pathlib.Path, *, label: str) -> None:
    """Require one immutable root-controlled source and its complete path chain.

    The production materializer runs with root privileges.  Its reviewed profile
    and npm inputs therefore cannot safely come through a checkout directory
    that another account can rename or edit, even when the leaf itself happens
    to be read-only.  Validate every component through the filesystem root
    before any privileged materialization consumes the source.
    """

    if not path.is_absolute():
        raise ToolchainError(f"{label} must use an absolute path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ToolchainError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ToolchainError(
            f"{label} must be a root-owned, non-linked, non-group/world-writable "
            "regular file"
        )

    current = path.parent
    while True:
        try:
            parent_metadata = current.lstat()
        except OSError as error:
            raise ToolchainError(f"{label} parent chain is unavailable") from error
        if (
            current.is_symlink()
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != 0
            or stat.S_IMODE(parent_metadata.st_mode) & 0o022
        ):
            raise ToolchainError(
                f"{label} parent chain must contain only root-owned real "
                "non-group/world-writable directories"
            )
        if current == current.parent:
            break
        current = current.parent


def _exact_keys(value: dict[str, Any], expected: set[str], *, label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unexpected = sorted(set(value) - expected)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise ToolchainError(f"{label} fields are invalid ({'; '.join(details)})")


def _safe_repo_relative(value: object, *, label: str) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ToolchainError(f"{label} must be a non-empty relative path")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ToolchainError(f"{label} must not contain traversal or an absolute path")
    return path


def _absolute_path(value: object, *, label: str) -> pathlib.Path:
    if not isinstance(value, str) or not value:
        raise ToolchainError(f"{label} must be an absolute path")
    path = pathlib.Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ToolchainError(f"{label} must be an absolute path without traversal")
    return path


def load_profile(
    *, root: pathlib.Path = ROOT, profile_path: pathlib.Path = PROFILE_PATH
) -> tuple[dict[str, Any], bytes, pathlib.Path, pathlib.Path]:
    profile, profile_raw = _read_source_json(profile_path, label="toolchain profile")
    _exact_keys(
        profile,
        {
            "schema_version",
            "profile_id",
            "release_status",
            "platform",
            "node",
            "wrangler",
            "package_manifest_path",
            "package_lock_path",
            "package_lock_sha256",
            "install_script_metadata_allowlist",
        },
        label="toolchain profile",
    )
    if profile["schema_version"] != 1 or profile["profile_id"] != PROFILE_ID:
        raise ToolchainError("toolchain profile schema or ID is unsupported")
    if profile["release_status"] != "backend_recovery":
        raise ToolchainError("toolchain profile must remain in backend_recovery")

    platform_profile = profile["platform"]
    if not isinstance(platform_profile, dict):
        raise ToolchainError("toolchain platform must be an object")
    _exact_keys(platform_profile, {"os", "architecture"}, label="toolchain platform")
    if platform_profile != {"os": "linux", "architecture": "x86_64"}:
        raise ToolchainError(
            "toolchain platform must be the reviewed linux/x86_64 host"
        )

    node = profile["node"]
    if not isinstance(node, dict):
        raise ToolchainError("Node profile must be an object")
    _exact_keys(
        node,
        {
            "version",
            "production_path",
            "archive_url",
            "archive_sha256",
            "binary_sha256",
            "bundled_npm_version",
        },
        label="Node profile",
    )
    if (
        not isinstance(node["version"], str)
        or NODE_VERSION.fullmatch(node["version"]) is None
    ):
        raise ToolchainError("Node version must be an exact canonical version")
    _absolute_path(node["production_path"], label="Node production path")
    expected_archive_url = (
        f"https://nodejs.org/dist/{node['version']}/"
        f"node-{node['version']}-linux-x64.tar.xz"
    )
    if node["archive_url"] != expected_archive_url:
        raise ToolchainError(
            "Node archive URL must be the exact official release artifact"
        )
    for key in ("archive_sha256", "binary_sha256"):
        if not isinstance(node[key], str) or SHA256.fullmatch(node[key]) is None:
            raise ToolchainError(f"Node {key} is not a canonical SHA-256")
    if (
        not isinstance(node["bundled_npm_version"], str)
        or PACKAGE_VERSION.fullmatch(node["bundled_npm_version"]) is None
    ):
        raise ToolchainError("bundled npm version must be exact")

    wrangler = profile["wrangler"]
    if not isinstance(wrangler, dict):
        raise ToolchainError("Wrangler profile must be an object")
    _exact_keys(
        wrangler,
        {"package", "version", "production_install_root", "entrypoint"},
        label="Wrangler profile",
    )
    if wrangler["package"] != "wrangler":
        raise ToolchainError("Wrangler package name is unsupported")
    if (
        not isinstance(wrangler["version"], str)
        or PACKAGE_VERSION.fullmatch(wrangler["version"]) is None
    ):
        raise ToolchainError("Wrangler version must be an exact canonical version")
    _absolute_path(wrangler["production_install_root"], label="Wrangler install root")
    _safe_repo_relative(wrangler["entrypoint"], label="Wrangler entrypoint")

    manifest_relative = _safe_repo_relative(
        profile["package_manifest_path"], label="package manifest path"
    )
    lock_relative = _safe_repo_relative(
        profile["package_lock_path"], label="package lock path"
    )
    manifest_path = root.joinpath(*manifest_relative.parts)
    lock_path = root.joinpath(*lock_relative.parts)
    lock_hash = profile["package_lock_sha256"]
    if not isinstance(lock_hash, str) or SHA256.fullmatch(lock_hash) is None:
        raise ToolchainError("package lock SHA-256 is not canonical")
    allowed_scripts = profile["install_script_metadata_allowlist"]
    if not isinstance(allowed_scripts, list):
        raise ToolchainError("allowed install scripts must be a reviewed list")
    seen_scripts: set[str] = set()
    for item in allowed_scripts:
        if not isinstance(item, dict):
            raise ToolchainError("allowed install script record must be an object")
        _exact_keys(
            item, {"package", "version", "integrity"}, label="install script record"
        )
        if (
            not isinstance(item["package"], str)
            or PACKAGE_NAME.fullmatch(item["package"]) is None
            or item["package"] in seen_scripts
            or not isinstance(item["version"], str)
            or LOCKED_VERSION.fullmatch(item["version"]) is None
            or not isinstance(item["integrity"], str)
        ):
            raise ToolchainError(
                "allowed install script record is invalid or duplicate"
            )
        seen_scripts.add(item["package"])
    return profile, profile_raw, manifest_path, lock_path


def _validate_integrity(value: object, *, label: str) -> None:
    if not isinstance(value, str) or not value.startswith("sha512-"):
        raise ToolchainError(f"{label} must use one sha512 integrity digest")
    encoded = value.removeprefix("sha512-")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ToolchainError(f"{label} integrity digest is malformed") from error
    if len(decoded) != 64:
        raise ToolchainError(f"{label} integrity digest is not SHA-512")


def _validate_locked_packages(
    profile: dict[str, Any], packages: dict[str, Any]
) -> None:
    reviewed_scripts = {
        item["package"]: (item["version"], item["integrity"])
        for item in profile["install_script_metadata_allowlist"]
    }
    actual_scripts: dict[str, tuple[str, str]] = {}
    for key, record in packages.items():
        if key == "":
            continue
        if not isinstance(key, str) or not key.startswith("node_modules/"):
            raise ToolchainError("package lock contains an unsafe package key")
        name = key.removeprefix("node_modules/")
        if "/node_modules/" in name or PACKAGE_NAME.fullmatch(name) is None:
            raise ToolchainError("package lock contains an unsafe package key")
        if not isinstance(record, dict):
            raise ToolchainError(f"locked package {name} must be an object")
        if record.get("link") is not None or record.get("inBundle") is not None:
            raise ToolchainError(f"locked package {name} may not be linked or bundled")
        version = record.get("version")
        resolved = record.get("resolved")
        integrity = record.get("integrity")
        if not isinstance(version, str) or LOCKED_VERSION.fullmatch(version) is None:
            raise ToolchainError(f"locked package {name} version is not exact")
        if not isinstance(resolved, str):
            raise ToolchainError(f"locked package {name} has no registry resolution")
        parsed = urllib.parse.urlsplit(resolved)
        basename = name.split("/")[-1]
        expected_path = f"/{name}/-/{basename}-{version}.tgz"
        if (
            parsed.scheme != "https"
            or parsed.netloc != "registry.npmjs.org"
            or parsed.path != expected_path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
        ):
            raise ToolchainError(
                f"locked package {name} must resolve to its canonical HTTPS npm registry tarball"
            )
        _validate_integrity(integrity, label=f"locked package {name}")
        if record.get("hasInstallScript") is not None:
            if record.get("hasInstallScript") is not True:
                raise ToolchainError(
                    f"locked package {name} has malformed install-script metadata"
                )
            actual_scripts[name] = (version, integrity)
    if actual_scripts != reviewed_scripts:
        raise ToolchainError(
            "install-script-bearing package set differs from the explicit reviewed allowlist"
        )


def validate_static(
    *, root: pathlib.Path = ROOT, profile_path: pathlib.Path = PROFILE_PATH
) -> dict[str, object]:
    profile, profile_raw, package_path, lock_path = load_profile(
        root=root, profile_path=profile_path
    )
    package, _package_raw = _read_source_json(
        package_path, label="toolchain package.json"
    )
    _exact_keys(
        package,
        {"name", "version", "private", "description", "engines", "devDependencies"},
        label="toolchain package.json",
    )
    expected_wrangler = profile["wrangler"]["version"]
    expected_node = profile["node"]["version"].removeprefix("v")
    if (
        package["name"] != "tinyzkp-cloudflare-production-toolchain"
        or package["version"] != "1.0.0"
        or package["private"] is not True
        or package["engines"] != {"node": expected_node}
        or package["devDependencies"] != {"wrangler": expected_wrangler}
    ):
        raise ToolchainError("toolchain package.json differs from the reviewed profile")

    lock, lock_raw = _read_source_json(lock_path, label="toolchain package-lock.json")
    if _sha256(lock_raw) != profile["package_lock_sha256"]:
        raise ToolchainError(
            "toolchain package-lock.json SHA-256 differs from the profile"
        )
    if (
        lock.get("name") != package["name"]
        or lock.get("version") != package["version"]
        or lock.get("lockfileVersion") != 3
        or lock.get("requires") is not True
        or not isinstance(lock.get("packages"), dict)
    ):
        raise ToolchainError("toolchain package-lock.json header is invalid")
    packages = lock["packages"]
    _validate_locked_packages(profile, packages)
    root_package = packages.get("")
    wrangler_package = packages.get("node_modules/wrangler")
    if not isinstance(root_package, dict) or not isinstance(wrangler_package, dict):
        raise ToolchainError("toolchain lock omits its root or Wrangler package")
    if (
        root_package.get("name") != package["name"]
        or root_package.get("version") != package["version"]
        or root_package.get("engines") != package["engines"]
        or root_package.get("devDependencies") != package["devDependencies"]
    ):
        raise ToolchainError("toolchain lock root differs from package.json")
    expected_resolved = (
        f"https://registry.npmjs.org/wrangler/-/wrangler-{expected_wrangler}.tgz"
    )
    integrity = wrangler_package.get("integrity")
    if (
        wrangler_package.get("version") != expected_wrangler
        or wrangler_package.get("resolved") != expected_resolved
        or not isinstance(integrity, str)
        or not integrity.startswith("sha512-")
        or wrangler_package.get("dev") is not True
    ):
        raise ToolchainError(
            "Wrangler lock resolution is not exact or registry-integrity-bound"
        )
    return {
        "profile_id": PROFILE_ID,
        "profile_sha256": _sha256(profile_raw),
        "package_lock_sha256": _sha256(lock_raw),
        "node_version": profile["node"]["version"],
        "wrangler_version": expected_wrangler,
    }


def _runtime_platform() -> tuple[str, str]:
    architecture = platform.machine().lower()
    if architecture == "amd64":
        architecture = "x86_64"
    return sys.platform, architecture


def _runtime_owner_uid(expected_owner_uid: int | None) -> int:
    if expected_owner_uid is None:
        return os.geteuid()
    if (
        type(expected_owner_uid) is not int
        or expected_owner_uid < 0
        or expected_owner_uid > 2**32 - 1
    ):
        raise ToolchainError("runtime owner UID is invalid")
    return expected_owner_uid


def _validate_directory_parent_chain(
    directory: pathlib.Path, *, label: str, expected_owner_uid: int
) -> None:
    if not directory.is_absolute() or ".." in directory.parts:
        raise ToolchainError(f"{label} parent chain must be absolute without traversal")
    current = directory
    while True:
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ToolchainError(f"{label} parent chain is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ToolchainError(f"{label} parent chain contains a symbolic link")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ToolchainError(f"{label} parent chain contains a non-directory")
        if metadata.st_uid != expected_owner_uid:
            raise ToolchainError(
                f"{label} parent chain directory {current} is not owned by "
                f"UID {expected_owner_uid}"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ToolchainError(
                f"{label} parent chain directory {current} is group/world-writable"
            )
        if current == current.parent:
            break
        current = current.parent


def _validate_production_runtime_parent_chains(
    node_executable: pathlib.Path,
    wrangler_entrypoint: pathlib.Path,
    *,
    expected_owner_uid: int,
) -> None:
    if expected_owner_uid != 0:
        raise ToolchainError("production runtime parent chains must be root-owned")
    for path, label in (
        (node_executable, "Node executable"),
        (wrangler_entrypoint, "Wrangler entrypoint"),
    ):
        try:
            path.relative_to(PRODUCTION_RUNTIME_ROOT)
        except ValueError as error:
            raise ToolchainError(
                f"{label} is outside the fixed production runtime root"
            ) from error
        _validate_directory_parent_chain(
            path.parent,
            label=label,
            expected_owner_uid=expected_owner_uid,
        )


def _read_runtime_file(
    path: pathlib.Path,
    *,
    label: str,
    max_bytes: int,
    executable: bool = False,
    read_only: bool = False,
    expected_owner_uid: int | None = None,
) -> tuple[bytes, os.stat_result]:
    owner_uid = _runtime_owner_uid(expected_owner_uid)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ToolchainError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ToolchainError(
            f"{label} must be owned by UID {owner_uid} and be a non-symlink "
            "regular file"
        )
    if executable and not metadata.st_mode & stat.S_IXUSR:
        raise ToolchainError(f"{label} must be executable")
    if read_only and stat.S_IMODE(metadata.st_mode) & 0o222:
        raise ToolchainError(f"{label} must be read-only")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ToolchainError(f"{label} is unavailable or unsafe") from error
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            raise ToolchainError(f"{label} changed while it was opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ToolchainError(f"{label} exceeds its identity size limit")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks), metadata


def _installation_identity(
    install_root: pathlib.Path, *, expected_owner_uid: int | None = None
) -> dict[str, object]:
    owner_uid = _runtime_owner_uid(expected_owner_uid)
    try:
        root_metadata = install_root.lstat()
    except OSError as error:
        raise ToolchainError("Wrangler installation root is unavailable") from error
    if (
        install_root.is_symlink()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != owner_uid
        or stat.S_IMODE(root_metadata.st_mode) & 0o222
    ):
        raise ToolchainError(
            f"Wrangler installation root must be owned by UID {owner_uid} "
            "and read-only"
        )

    records: list[dict[str, object]] = []
    total_bytes = 0
    file_count = 0
    for current, directory_names, file_names in os.walk(
        install_root, followlinks=False
    ):
        current_path = pathlib.Path(current)
        current_metadata = current_path.lstat()
        if (
            current_path.is_symlink()
            or not stat.S_ISDIR(current_metadata.st_mode)
            or current_metadata.st_uid != owner_uid
            or stat.S_IMODE(current_metadata.st_mode) & 0o222
        ):
            raise ToolchainError(
                "Wrangler installation contains a mutable or unsafe directory"
            )
        records.append(
            {
                "kind": "directory",
                "path": (
                    "."
                    if current_path == install_root
                    else current_path.relative_to(install_root).as_posix()
                ),
                "mode": stat.S_IMODE(current_metadata.st_mode),
            }
        )
        if len(records) > MAX_INSTALL_FILES:
            raise ToolchainError(
                "Wrangler installation exceeds its identity limits"
            )
        for name in sorted(directory_names):
            if (current_path / name).is_symlink():
                raise ToolchainError("Wrangler installation contains a symlink")
        for name in sorted(file_names):
            candidate = current_path / name
            raw, metadata = _read_runtime_file(
                candidate,
                label="Wrangler installation file",
                max_bytes=MAX_INSTALL_BYTES,
                expected_owner_uid=owner_uid,
            )
            if stat.S_IMODE(metadata.st_mode) & 0o222:
                raise ToolchainError("Wrangler installation contains a writable file")
            total_bytes += len(raw)
            if total_bytes > MAX_INSTALL_BYTES or len(records) >= MAX_INSTALL_FILES:
                raise ToolchainError(
                    "Wrangler installation exceeds its identity limits"
                )
            file_count += 1
            records.append(
                {
                    "kind": "file",
                    "path": candidate.relative_to(install_root).as_posix(),
                    "size": len(raw),
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "sha256": _sha256(raw),
                }
            )
    if file_count == 0:
        raise ToolchainError("Wrangler installation is empty")
    canonical = json.dumps(
        sorted(records, key=lambda item: str(item["path"])),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "wrangler_tree_sha256": _sha256(canonical),
        "wrangler_file_count": file_count,
        "wrangler_total_bytes": total_bytes,
    }


def materialization_document(
    *,
    static_identity: dict[str, object],
    node_sha256: str,
    wrangler_version: str,
    installation_identity: dict[str, object],
) -> dict[str, object]:
    """Build the deterministic statement that binds one installed toolchain."""

    return {
        "schema_version": MATERIALIZATION_SCHEMA_VERSION,
        "profile_id": static_identity["profile_id"],
        "profile_sha256": static_identity["profile_sha256"],
        "package_lock_sha256": static_identity["package_lock_sha256"],
        "node_sha256": node_sha256,
        "wrangler_version": wrangler_version,
        "wrangler_tree_sha256": installation_identity["wrangler_tree_sha256"],
        "wrangler_file_count": installation_identity["wrangler_file_count"],
        "wrangler_total_bytes": installation_identity["wrangler_total_bytes"],
    }


def canonical_materialization_bytes(document: dict[str, object]) -> bytes:
    """Return the one accepted byte representation of materialization evidence."""

    return (
        json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _validate_materialization(
    install_root: pathlib.Path,
    *,
    static_identity: dict[str, object],
    node_sha256: str,
    wrangler_version: str,
    installation_identity: dict[str, object],
    expected_owner_uid: int | None = None,
) -> str:
    owner_uid = _runtime_owner_uid(expected_owner_uid)
    evidence_path = install_root.parent / MATERIALIZATION_FILENAME
    try:
        parent_metadata = evidence_path.parent.lstat()
    except OSError as error:
        raise ToolchainError("toolchain materialization parent is unavailable") from error
    if (
        evidence_path.parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != owner_uid
        or stat.S_IMODE(parent_metadata.st_mode) & 0o222
    ):
        raise ToolchainError(
            f"toolchain materialization parent must be owned by UID {owner_uid} "
            "and read-only"
        )
    raw, _metadata = _read_runtime_file(
        evidence_path,
        label="toolchain materialization evidence",
        max_bytes=MAX_JSON_BYTES,
        read_only=True,
        expected_owner_uid=owner_uid,
    )
    document = _strict_json_bytes(raw, label="toolchain materialization evidence")
    expected = materialization_document(
        static_identity=static_identity,
        node_sha256=node_sha256,
        wrangler_version=wrangler_version,
        installation_identity=installation_identity,
    )
    _exact_keys(document, set(expected), label="toolchain materialization evidence")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != MATERIALIZATION_SCHEMA_VERSION
        or not all(
            isinstance(document[key], str) and SHA256.fullmatch(document[key])
            for key in (
                "profile_sha256",
                "package_lock_sha256",
                "node_sha256",
                "wrangler_tree_sha256",
            )
        )
        or not isinstance(document["profile_id"], str)
        or not isinstance(document["wrangler_version"], str)
        or any(
            type(document[key]) is not int or document[key] < 0
            for key in ("wrangler_file_count", "wrangler_total_bytes")
        )
    ):
        raise ToolchainError("toolchain materialization evidence fields are invalid")
    if document != expected:
        raise ToolchainError(
            "toolchain materialization evidence differs from installed bytes or reviewed sources"
        )
    if raw != canonical_materialization_bytes(document):
        raise ToolchainError("toolchain materialization evidence is not canonical JSON")
    return _sha256(raw)


def _runtime_environment() -> dict[str, str]:
    return {
        "PATH": TRUSTED_SYSTEM_PATH,
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "WRANGLER_SEND_METRICS": "false",
    }


def _exact_version(command: tuple[str, ...], *, label: str, expected: str) -> None:
    try:
        with tempfile.TemporaryDirectory(prefix="tinyzkp-tool-version-") as raw_scratch:
            scratch = pathlib.Path(raw_scratch)
            environment = _runtime_environment()
            # Wrangler 4.85 writes a debug log even for `--version`. Give that
            # exact process a private, automatically removed destination so a
            # root materialization probe cannot leave `/nonexistent` owned by
            # root and make the later unprivileged production probe fail.
            environment["WRANGLER_LOG_PATH"] = str(scratch / "wrangler.log")
            completed = subprocess.run(
                command,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            for entry in scratch.iterdir():
                metadata = entry.lstat()
                if (
                    entry.name != "wrangler.log"
                    or entry.is_symlink()
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_size > MAX_JSON_BYTES
                ):
                    raise ToolchainError(
                        f"{label} version check wrote outside its bounded log"
                    )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ToolchainError(f"cannot execute {label} version check") from error
    if (
        completed.returncode != 0
        or completed.stdout.strip() != expected
        or completed.stderr.strip()
    ):
        raise ToolchainError(f"{label} runtime version differs from the pinned profile")


def validate_runtime(
    node_executable: pathlib.Path,
    wrangler_entrypoint: pathlib.Path,
    *,
    install_root: pathlib.Path | None = None,
    enforce_profile_paths: bool = True,
    root: pathlib.Path = ROOT,
    profile_path: pathlib.Path = PROFILE_PATH,
    expected_owner_uid: int | None = None,
    require_root_parent_chain: bool = False,
) -> dict[str, object]:
    owner_uid = _runtime_owner_uid(expected_owner_uid)
    static_identity = validate_static(root=root, profile_path=profile_path)
    profile, _raw, _package_path, _lock_path = load_profile(
        root=root, profile_path=profile_path
    )
    if _runtime_platform() != ("linux", "x86_64"):
        raise ToolchainError("production Cloudflare toolchain requires linux/x86_64")

    expected_node = pathlib.Path(profile["node"]["production_path"])
    profile_install_root = pathlib.Path(profile["wrangler"]["production_install_root"])
    runtime_install_root = install_root or profile_install_root
    relative_entrypoint = pathlib.PurePosixPath(profile["wrangler"]["entrypoint"])
    expected_entrypoint = runtime_install_root.joinpath(*relative_entrypoint.parts)
    if enforce_profile_paths:
        if install_root is not None and install_root != profile_install_root:
            raise ToolchainError(
                "Wrangler install root differs from the production profile"
            )
        if node_executable != expected_node:
            raise ToolchainError(
                "Node executable path differs from the production profile"
            )
        if wrangler_entrypoint != expected_entrypoint:
            raise ToolchainError(
                "Wrangler entrypoint path differs from the production profile"
            )
    elif wrangler_entrypoint != expected_entrypoint:
        raise ToolchainError(
            "Wrangler entrypoint is outside the supplied installation root"
        )
    if require_root_parent_chain:
        if not enforce_profile_paths:
            raise ToolchainError(
                "production parent-chain validation requires enforced profile paths"
            )
        _validate_production_runtime_parent_chains(
            node_executable,
            wrangler_entrypoint,
            expected_owner_uid=owner_uid,
        )

    node_raw, _node_metadata = _read_runtime_file(
        node_executable,
        label="Node executable",
        max_bytes=MAX_NODE_BYTES,
        executable=True,
        read_only=True,
        expected_owner_uid=owner_uid,
    )
    if _sha256(node_raw) != profile["node"]["binary_sha256"]:
        raise ToolchainError(
            "Node executable bytes differ from the reviewed release artifact"
        )
    node_sha256 = _sha256(node_raw)
    installation = _installation_identity(
        runtime_install_root, expected_owner_uid=owner_uid
    )
    entrypoint_raw, _entrypoint_metadata = _read_runtime_file(
        wrangler_entrypoint,
        label="Wrangler entrypoint",
        max_bytes=MAX_JSON_BYTES,
        expected_owner_uid=owner_uid,
    )
    package_path = runtime_install_root / "wrangler" / "package.json"
    package_raw, _package_metadata = _read_runtime_file(
        package_path,
        label="installed Wrangler package.json",
        max_bytes=MAX_JSON_BYTES,
        expected_owner_uid=owner_uid,
    )
    package = _strict_json_bytes(package_raw, label="installed Wrangler package.json")
    if package.get("version") != profile["wrangler"]["version"]:
        raise ToolchainError(
            "installed Wrangler package version differs from the profile"
        )
    bin_mapping = package.get("bin")
    if (
        not isinstance(bin_mapping, dict)
        or bin_mapping.get("wrangler") != "./bin/wrangler.js"
    ):
        raise ToolchainError("installed Wrangler package has an unexpected entrypoint")

    materialization_sha256 = _validate_materialization(
        runtime_install_root,
        static_identity=static_identity,
        node_sha256=node_sha256,
        wrangler_version=profile["wrangler"]["version"],
        installation_identity=installation,
        expected_owner_uid=owner_uid,
    )

    _exact_version(
        (str(node_executable), "--version"),
        label="Node",
        expected=profile["node"]["version"],
    )
    _exact_version(
        (str(node_executable), str(wrangler_entrypoint), "--version"),
        label="Wrangler",
        expected=profile["wrangler"]["version"],
    )
    return {
        **static_identity,
        "node_realpath": str(node_executable.resolve(strict=True)),
        "node_sha256": node_sha256,
        "wrangler_install_root": str(runtime_install_root.resolve(strict=True)),
        "wrangler_entrypoint_realpath": str(wrangler_entrypoint.resolve(strict=True)),
        "wrangler_entrypoint_sha256": _sha256(entrypoint_raw),
        "materialization_sha256": materialization_sha256,
        **installation,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime", action="store_true", help="validate installed production bytes"
    )
    parser.add_argument("--node-executable", type=pathlib.Path)
    parser.add_argument("--wrangler-entrypoint", type=pathlib.Path)
    parser.add_argument(
        "--json", action="store_true", help="emit the validated identity"
    )
    args = parser.parse_args(argv)
    if args.runtime and (
        args.node_executable is None or args.wrangler_entrypoint is None
    ):
        parser.error("--runtime requires --node-executable and --wrangler-entrypoint")
    if not args.runtime and (
        args.node_executable is not None or args.wrangler_entrypoint is not None
    ):
        parser.error("runtime paths require --runtime")
    try:
        identity = (
            validate_runtime(
                args.node_executable,
                args.wrangler_entrypoint,
                expected_owner_uid=0,
                require_root_parent_chain=True,
            )
            if args.runtime
            else validate_static()
        )
    except (OSError, ToolchainError) as error:
        print(f"FAIL Cloudflare production toolchain - {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(identity, sort_keys=True))
    else:
        mode = "runtime" if args.runtime else "static"
        print(
            f"PASS Cloudflare production toolchain ({mode}; "
            f"Node {identity['node_version']}; Wrangler {identity['wrangler_version']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
