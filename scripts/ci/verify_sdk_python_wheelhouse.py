#!/usr/bin/env python3
"""Verify and materialize the fixed Python wheelhouse used by SDK evidence."""

from __future__ import annotations

import argparse
from email import policy as email_policy
from email.parser import BytesParser
import hashlib
import json
import os
import fcntl
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import tomllib
from typing import Callable
from urllib.parse import unquote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)
import zipfile

import strict_json


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = "release/sdk-python-evidence-lock-v1.json"
REQUIREMENTS_PATH = (
    "release/python/sdk-evidence-requirements-linux-x86_64-cp312-v1.txt"
)
MANIFEST_PATH = (
    "release/python/sdk-evidence-wheelhouse-linux-x86_64-cp312-v1.json"
)
PYPROJECT_PATH = "clients/python/pyproject.toml"
TARGET = {
    "abi": "cp312",
    "architecture": "x86_64",
    "implementation": "cpython",
    "libc": "glibc>=2.17",
    "platform": "manylinux_2_17_x86_64",
    "python_version": "3.12",
}
EXPECTED_ROOTS = {
    "build": ["hatchling==1.27.0"],
    "runtime": ["blake3==1.0.9"],
    "dev": ["pytest==8.4.2"],
    "test": ["pytest==8.4.2"],
}
EXPECTED_PACKAGES = [
    "blake3==1.0.9",
    "hatchling==1.27.0",
    "iniconfig==2.3.0",
    "packaging==26.2",
    "pathspec==1.1.1",
    "pip==25.2",
    "pluggy==1.6.0",
    "pygments==2.20.0",
    "pytest==8.4.2",
    "trove-classifiers==2026.6.1.19",
]
MAX_WHEELS = 16
MAX_WHEEL_BYTES = 4 * 1024 * 1024
MAX_WHEELHOUSE_BYTES = 8 * 1024 * 1024
MAX_ZIP_ENTRIES = 4096
MAX_ZIP_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 512 * 1024
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
VERSION = re.compile(r"^[0-9A-Za-z]+(?:[._+-][0-9A-Za-z]+)*$")


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ValueError("wheel download redirected away from its committed URL")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} has missing or unknown fields")
    return value


def _lower_hex(value: object) -> bool:
    return isinstance(value, str) and HEX_64.fullmatch(value) is not None


def _exact_int(value: object, *, minimum: int = 0, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def render_requirements(wheels: list[dict[str, object]]) -> bytes:
    lines = [
        "# TinyZKP SDK evidence dependencies: CPython 3.12, Linux x86_64, glibc >= 2.17.",
        "# Generated from the reviewed wheel manifest; do not add indexes, URLs, or markers.",
        "--only-binary=:all:",
    ]
    for wheel in wheels:
        lines.append(
            f"{wheel['distribution']}=={wheel['version']} "
            f"--hash=sha256:{wheel['sha256']}"
        )
    return ("\n".join(lines) + "\n").encode("ascii")


def _validate_pyproject(payload: bytes) -> None:
    try:
        value = tomllib.loads(payload.decode("utf-8"))
        build = value["build-system"]
        project = value["project"]
        optional = project["optional-dependencies"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("Python SDK pyproject is malformed") from error
    if (
        build.get("requires") != EXPECTED_ROOTS["build"]
        or build.get("build-backend") != "hatchling.build"
        or project.get("dependencies") != EXPECTED_ROOTS["runtime"]
        or optional.get("dev") != EXPECTED_ROOTS["dev"]
        or optional.get("test") != EXPECTED_ROOTS["test"]
    ):
        raise ValueError("Python SDK dependency roots differ from the reviewed lock")


def validate_lock_documents(
    lock_payload: bytes,
    requirements_payload: bytes,
    manifest_payload: bytes,
    pyproject_payload: bytes,
) -> dict[str, object]:
    """Validate all committed lock documents and return their stable identity."""
    lock = _exact_keys(
        strict_json.loads(lock_payload),
        {
            "schema_version",
            "target",
            "pyproject_path",
            "pyproject_sha256",
            "requirements_path",
            "requirements_sha256",
            "wheelhouse_manifest_path",
            "wheelhouse_manifest_sha256",
            "packages",
        },
        "SDK Python lock",
    )
    manifest = _exact_keys(
        strict_json.loads(manifest_payload),
        {"schema_version", "target", "requirements_path", "wheels"},
        "SDK Python wheel manifest",
    )
    if (
        lock.get("schema_version") != 1
        or isinstance(lock.get("schema_version"), bool)
        or manifest.get("schema_version") != 1
        or isinstance(manifest.get("schema_version"), bool)
        or lock.get("target") != TARGET
        or manifest.get("target") != TARGET
        or lock.get("pyproject_path") != PYPROJECT_PATH
        or lock.get("requirements_path") != REQUIREMENTS_PATH
        or manifest.get("requirements_path") != REQUIREMENTS_PATH
        or lock.get("wheelhouse_manifest_path") != MANIFEST_PATH
        or not _lower_hex(lock.get("pyproject_sha256"))
        or not _lower_hex(lock.get("requirements_sha256"))
        or not _lower_hex(lock.get("wheelhouse_manifest_sha256"))
        or lock["pyproject_sha256"] != _sha256(pyproject_payload)
        or lock["requirements_sha256"] != _sha256(requirements_payload)
        or lock["wheelhouse_manifest_sha256"] != _sha256(manifest_payload)
    ):
        raise ValueError("SDK Python lock identity is incomplete or digest-skewed")

    raw_wheels = manifest.get("wheels")
    if (
        not isinstance(raw_wheels, list)
        or not 0 < len(raw_wheels) <= MAX_WHEELS
    ):
        raise ValueError("SDK Python wheel manifest has an invalid wheel count")
    wheels: list[dict[str, object]] = []
    seen_names: set[str] = set()
    seen_files: set[str] = set()
    total_bytes = 0
    for index, raw in enumerate(raw_wheels):
        wheel = _exact_keys(
            raw,
            {
                "distribution",
                "version",
                "filename",
                "url",
                "bytes",
                "sha256",
                "tags",
                "requires_python",
                "requires_dist",
            },
            f"SDK Python wheel {index}",
        )
        distribution = wheel.get("distribution")
        version = wheel.get("version")
        filename = wheel.get("filename")
        url = wheel.get("url")
        tags = wheel.get("tags")
        requires_python = wheel.get("requires_python")
        requires_dist = wheel.get("requires_dist")
        if (
            not isinstance(distribution, str)
            or NAME.fullmatch(distribution) is None
            or not isinstance(version, str)
            or not version
            or len(version) > 64
            or VERSION.fullmatch(version) is None
            or not isinstance(filename, str)
            or not filename.endswith(".whl")
            or len(filename) > 240
            or Path(filename).name != filename
            or "\\" in filename
            or not isinstance(url, str)
            or len(url) > 1024
            or not _exact_int(wheel.get("bytes"), minimum=1, maximum=MAX_WHEEL_BYTES)
            or not _lower_hex(wheel.get("sha256"))
            or not isinstance(tags, list)
            or not tags
            or len(tags) > 4
            or any(not isinstance(tag, str) or not 0 < len(tag) <= 128 for tag in tags)
            or len(set(tags)) != len(tags)
            or requires_python is not None
            and (not isinstance(requires_python, str) or not 0 < len(requires_python) <= 128)
            or not isinstance(requires_dist, list)
            or len(requires_dist) > 64
            or any(
                not isinstance(requirement, str)
                or not 0 < len(requirement) <= 512
                or "://" in requirement
                or " @ " in requirement
                for requirement in requires_dist
            )
        ):
            raise ValueError(f"SDK Python wheel descriptor {index} is malformed")
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "files.pythonhosted.org"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or Path(unquote(parsed.path)).name != filename
        ):
            raise ValueError(f"SDK Python wheel URL {index} is not an exact files.pythonhosted URL")
        if distribution in seen_names or filename in seen_files:
            raise ValueError("SDK Python wheel manifest contains a duplicate")
        seen_names.add(distribution)
        seen_files.add(filename)
        total_bytes += int(wheel["bytes"])
        wheels.append(wheel)
    if total_bytes > MAX_WHEELHOUSE_BYTES:
        raise ValueError("SDK Python wheelhouse exceeds its reviewed size limit")
    if [wheel["distribution"] for wheel in wheels] != sorted(seen_names):
        raise ValueError("SDK Python wheels are not in canonical distribution order")
    expected_packages = [
        f"{wheel['distribution']}=={wheel['version']}" for wheel in wheels
    ]
    if lock.get("packages") != expected_packages or expected_packages != EXPECTED_PACKAGES:
        raise ValueError("SDK Python package inventory differs from the wheel manifest")
    if requirements_payload != render_requirements(wheels):
        raise ValueError("SDK Python requirements are not the canonical hash lock")
    _validate_pyproject(pyproject_payload)
    return {
        "schema_version": 1,
        "target": TARGET,
        "lock_sha256": _sha256(lock_payload),
        "pyproject_sha256": _sha256(pyproject_payload),
        "requirements_sha256": _sha256(requirements_payload),
        "wheelhouse_manifest_sha256": _sha256(manifest_payload),
        "wheel_set_sha256": _canonical_sha256(wheels),
        "packages": expected_packages,
        "wheel_count": len(wheels),
        "wheel_bytes": total_bytes,
        "wheels": wheels,
    }


def worktree_lock_identity(root: Path = ROOT) -> dict[str, object]:
    root = root.resolve()
    return validate_lock_documents(
        (root / LOCK_PATH).read_bytes(),
        (root / REQUIREMENTS_PATH).read_bytes(),
        (root / MANIFEST_PATH).read_bytes(),
        (root / PYPROJECT_PATH).read_bytes(),
    )


def committed_lock_identity(
    root: Path,
    release_sha: str,
    read_blob: Callable[[Path, str, str], bytes],
) -> dict[str, object]:
    root = root.resolve()
    return validate_lock_documents(
        read_blob(root, release_sha, LOCK_PATH),
        read_blob(root, release_sha, REQUIREMENTS_PATH),
        read_blob(root, release_sha, MANIFEST_PATH),
        read_blob(root, release_sha, PYPROJECT_PATH),
    )


def require_runtime_target() -> None:
    machine = platform.machine().lower()
    if (
        sys.implementation.name != "cpython"
        or sys.version_info[:2] != (3, 12)
        or not sys.platform.startswith("linux")
        or machine not in {"x86_64", "amd64"}
    ):
        raise ValueError(
            "SDK Python evidence requires CPython 3.12 on glibc>=2.17 Linux x86_64"
        )
    libc_name, libc_version = platform.libc_ver()
    try:
        libc_tuple = tuple(int(part) for part in libc_version.split(".")[:2])
    except ValueError as error:
        raise ValueError("release host glibc version is not parseable") from error
    if (
        libc_name.lower() != "glibc"
        or libc_tuple < (2, 17)
    ):
        raise ValueError(
            "SDK Python evidence requires CPython 3.12 on glibc>=2.17 Linux x86_64"
        )


def _wheel_metadata(payload: bytes, descriptor: dict[str, object]) -> None:
    from io import BytesIO

    with zipfile.ZipFile(BytesIO(payload), mode="r") as archive:
        infos = archive.infolist()
        if not 0 < len(infos) <= MAX_ZIP_ENTRIES:
            raise ValueError("wheel ZIP has an invalid entry count")
        names: set[str] = set()
        expanded = 0
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            mode = (info.external_attr >> 16) & 0o170000
            if (
                not name
                or "\\" in name
                or path.is_absolute()
                or ".." in path.parts
                or name in names
                or info.flag_bits & 0x1
                or mode == stat.S_IFLNK
                or info.file_size < 0
            ):
                raise ValueError("wheel ZIP contains an unsafe entry")
            names.add(name)
            expanded += info.file_size
            if expanded > MAX_ZIP_EXPANDED_BYTES:
                raise ValueError("wheel ZIP exceeds its expanded-size limit")
        if archive.testzip() is not None:
            raise ValueError("wheel ZIP has a failed CRC")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
        record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
        if len(metadata_names) != 1 or len(wheel_names) != 1 or len(record_names) != 1:
            raise ValueError("wheel ZIP lacks one canonical dist-info record set")
        prefixes = {
            name.removesuffix(suffix)
            for name, suffix in (
                (metadata_names[0], "METADATA"),
                (wheel_names[0], "WHEEL"),
                (record_names[0], "RECORD"),
            )
        }
        if len(prefixes) != 1:
            raise ValueError("wheel ZIP dist-info records do not share one directory")
        metadata_payload = archive.read(metadata_names[0])
        wheel_payload = archive.read(wheel_names[0])
        if len(metadata_payload) > MAX_METADATA_BYTES or len(wheel_payload) > MAX_METADATA_BYTES:
            raise ValueError("wheel metadata exceeds its size limit")
    metadata = BytesParser(policy=email_policy.compat32).parsebytes(metadata_payload)
    wheel_metadata = BytesParser(policy=email_policy.compat32).parsebytes(wheel_payload)
    observed_tags = wheel_metadata.get_all("Tag", [])
    if (
        _normalized_name(str(metadata.get("Name", ""))) != descriptor["distribution"]
        or metadata.get("Version") != descriptor["version"]
        or metadata.get("Requires-Python") != descriptor["requires_python"]
        or metadata.get_all("Requires-Dist", []) != descriptor["requires_dist"]
        or observed_tags != descriptor["tags"]
    ):
        raise ValueError(f"wheel metadata differs from the manifest: {descriptor['filename']}")


def verify_wheel_payload(payload: bytes, descriptor: dict[str, object]) -> None:
    if len(payload) != descriptor["bytes"] or _sha256(payload) != descriptor["sha256"]:
        raise ValueError(f"wheel bytes differ from the manifest: {descriptor['filename']}")
    _wheel_metadata(payload, descriptor)


def _safe_wheelhouse(
    path: Path, *, require_empty: bool = False, create: bool = False
) -> Path:
    path = path.absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            if not create:
                raise ValueError("SDK Python wheelhouse does not exist")
            os.mkdir(current, 0o700)
            details = os.lstat(current)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise ValueError("SDK Python wheelhouse has unsafe ancestry")
    details = os.lstat(path)
    if details.st_uid != os.geteuid():
        raise ValueError("SDK Python wheelhouse is not owned by the runner")
    if stat.S_IMODE(os.lstat(path).st_mode) != 0o700:
        raise ValueError("SDK Python wheelhouse is not owner-only")
    if require_empty and any(path.iterdir()):
        raise ValueError("SDK Python wheelhouse materialization requires an empty directory")
    return path


def verify_wheelhouse(path: Path, identity: dict[str, object]) -> dict[str, object]:
    path = _safe_wheelhouse(path)
    expected = {str(wheel["filename"]): wheel for wheel in identity["wheels"]}
    observed = {entry.name for entry in path.iterdir()}
    if observed != set(expected):
        raise ValueError("SDK Python wheelhouse contains missing or extra files")
    for filename, descriptor in expected.items():
        candidate = path / filename
        details = os.lstat(candidate)
        if (
            stat.S_ISLNK(details.st_mode)
            or not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != 0o400
        ):
            raise ValueError(f"SDK Python wheel file is not immutable and owner-only: {filename}")
        file_descriptor = os.open(
            candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
        with os.fdopen(file_descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                != (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
            ):
                raise ValueError(f"SDK Python wheel changed while opening: {filename}")
            payload = handle.read(MAX_WHEEL_BYTES + 1)
        verify_wheel_payload(payload, descriptor)
    return {
        key: value for key, value in identity.items() if key != "wheels"
    }


def verify_sealed_wheelhouse(
    path: Path, identity: dict[str, object], descriptor_records: list[dict[str, object]]
) -> dict[str, object]:
    """Verify filename links backed by fully sealed inherited memfds."""
    path = _safe_wheelhouse(path)
    expected = {str(wheel["filename"]): wheel for wheel in identity["wheels"]}
    records = {
        str(record.get("filename")): record
        for record in descriptor_records
        if isinstance(record, dict)
    }
    if set(records) != set(expected) or {entry.name for entry in path.iterdir()} != set(expected):
        raise ValueError("sealed SDK Python wheel inventory differs from the lock")
    required_seals = 0x0001 | 0x0002 | 0x0004 | 0x0008
    for filename, descriptor in expected.items():
        record = records[filename]
        fd = record.get("fd")
        candidate = path / filename
        details = os.lstat(candidate)
        if (
            not isinstance(fd, int)
            or isinstance(fd, bool)
            or not stat.S_ISLNK(details.st_mode)
            or os.readlink(candidate) != f"/proc/self/fd/{fd}"
        ):
            raise ValueError(f"sealed SDK Python wheel link is unsafe: {filename}")
        opened = os.fstat(fd)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        if (
            not stat.S_ISREG(opened.st_mode)
            or seals & required_seals != required_seals
            or record.get("seals") != seals
            or record.get("bytes") != descriptor["bytes"]
            or record.get("sha256") != descriptor["sha256"]
        ):
            raise ValueError(f"sealed SDK Python wheel descriptor is unsafe: {filename}")
        os.lseek(fd, 0, os.SEEK_SET)
        payload = b""
        while len(payload) <= MAX_WHEEL_BYTES:
            block = os.read(fd, min(1024 * 1024, MAX_WHEEL_BYTES + 1 - len(payload)))
            if not block:
                break
            payload += block
        verify_wheel_payload(payload, descriptor)
    return {key: value for key, value in identity.items() if key != "wheels"}


def materialize_wheelhouse(path: Path, identity: dict[str, object]) -> dict[str, object]:
    require_runtime_target()
    path = _safe_wheelhouse(path, require_empty=True, create=True)
    opener = build_opener(ProxyHandler({}), _RejectRedirects(), HTTPSHandler())
    created: list[Path] = []
    try:
        for descriptor in identity["wheels"]:
            filename = str(descriptor["filename"])
            request = Request(
                str(descriptor["url"]),
                headers={
                    "Accept-Encoding": "identity",
                    "User-Agent": "TinyZKP-SDK-Evidence-Wheelhouse/1",
                },
                method="GET",
            )
            with opener.open(request, timeout=60) as response:
                if response.status != 200 or response.geturl() != descriptor["url"]:
                    raise ValueError(f"wheel download response is not exact: {filename}")
                raw_length = response.headers.get("Content-Length")
                if raw_length is not None and raw_length != str(descriptor["bytes"]):
                    raise ValueError(f"wheel download length header is wrong: {filename}")
                payload = response.read(int(descriptor["bytes"]) + 1)
            verify_wheel_payload(payload, descriptor)
            temporary = path / f".{filename}.{os.getpid()}.tmp"
            descriptor_fd = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                with os.fdopen(descriptor_fd, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                destination = path / filename
                os.replace(temporary, destination)
                os.chmod(destination, 0o400, follow_symlinks=False)
                created.append(destination)
            finally:
                temporary.unlink(missing_ok=True)
        directory_fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return verify_wheelhouse(path, identity)
    except Exception:
        for candidate in created:
            candidate.chmod(0o600, follow_symlinks=False)
            candidate.unlink(missing_ok=True)
        raise


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--wheelhouse", type=Path, required=True)
    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("--wheelhouse", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        identity = worktree_lock_identity()
        require_runtime_target()
        if args.command == "materialize":
            result = materialize_wheelhouse(args.wheelhouse, identity)
        else:
            result = verify_wheelhouse(args.wheelhouse, identity)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"SDK Python wheelhouse verification failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
