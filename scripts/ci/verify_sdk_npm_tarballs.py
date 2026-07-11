#!/usr/bin/env python3
"""Verify, prepare, and securely extract the closed TypeScript SDK tarball set."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile
import fcntl
import urllib.error
import urllib.parse
import urllib.request

import strict_json


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = "release/npm/sdk-typescript-tarballs-v1.json"
EXPECTED_NAMES = {
    "@noble/hashes",
    "@types/json-bigint",
    "@types/node",
    "bignumber.js",
    "json-bigint",
    "typescript",
    "undici-types",
}
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_EXPANDED_BYTES = 96 * 1024 * 1024
MAX_ENTRIES = 20_000


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


def _read_json(payload: bytes, label: str) -> dict[str, object]:
    value = strict_json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _integrity(payload: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")


def _safe_url(value: object, filename: str) -> str:
    if not isinstance(value, str):
        raise ValueError("npm tarball URL must be a string")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "registry.npmjs.org"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith(".tgz")
    ):
        raise ValueError("npm tarball URL is not the exact reviewed registry origin")
    if filename in {"", ".", ".."} or Path(filename).name != filename or not filename.endswith(".tgz"):
        raise ValueError("npm tarball filename is unsafe")
    return value


def validate_manifest(
    manifest: dict[str, object], *, package_json: bytes, package_lock: bytes
) -> dict[str, object]:
    if set(manifest) != {"schema_version", "package_json_path", "package_lock_path", "packages"}:
        raise ValueError("npm tarball manifest keys are malformed")
    if manifest.get("schema_version") != 1 or isinstance(manifest.get("schema_version"), bool):
        raise ValueError("unsupported npm tarball manifest")
    if manifest.get("package_json_path") != "clients/typescript/package.json" or manifest.get("package_lock_path") != "clients/typescript/package-lock.json":
        raise ValueError("npm tarball manifest binds unexpected package files")
    package = _read_json(package_json, "package.json")
    lock = _read_json(package_lock, "package-lock.json")
    packages = manifest.get("packages")
    if not isinstance(packages, list) or len(packages) != 7:
        raise ValueError("npm tarball manifest must contain exactly seven packages")
    records: list[dict[str, object]] = []
    seen_names: set[str] = set()
    seen_files: set[str] = set()
    for raw in packages:
        if not isinstance(raw, dict) or set(raw) != {"name", "version", "filename", "archive_root", "url", "bytes", "sha256", "integrity"}:
            raise ValueError("npm tarball record is malformed")
        name, version, filename = raw.get("name"), raw.get("version"), raw.get("filename")
        archive_root = raw.get("archive_root")
        size, integrity = raw.get("bytes"), raw.get("integrity")
        if name not in EXPECTED_NAMES or name in seen_names or not isinstance(version, str) or not version:
            raise ValueError("npm tarball package identity is malformed")
        if not isinstance(filename, str) or filename in seen_files:
            raise ValueError("npm tarball filename is duplicated")
        if (
            not isinstance(archive_root, str)
            or not archive_root
            or "/" in archive_root
            or "\\" in archive_root
            or archive_root in {".", ".."}
            or len(archive_root.encode("utf-8")) > 128
        ):
            raise ValueError("npm tarball archive root is unsafe")
        _safe_url(raw.get("url"), filename)
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_ARCHIVE_BYTES:
            raise ValueError("npm tarball size is invalid")
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            raise ValueError("npm tarball integrity is invalid")
        try:
            digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
        except ValueError as error:
            raise ValueError("npm tarball integrity is invalid") from error
        if len(digest) != 64:
            raise ValueError("npm tarball integrity is invalid")
        sha256 = raw.get("sha256")
        if not isinstance(sha256, str) or len(sha256) != 64 or any(character not in "0123456789abcdef" for character in sha256):
            raise ValueError("npm tarball SHA-256 is invalid")
        locked = lock.get("packages", {}).get(f"node_modules/{name}") if isinstance(lock.get("packages"), dict) else None
        if not isinstance(locked, dict) or locked.get("version") != version or locked.get("resolved") != raw.get("url") or locked.get("integrity") != integrity:
            raise ValueError(f"npm lockfile skew for {name}")
        seen_names.add(name)
        seen_files.add(filename)
        records.append(dict(raw))
    if seen_names != EXPECTED_NAMES:
        raise ValueError("npm tarball package closure is incomplete")
    root_lock = lock.get("packages", {}).get("") if isinstance(lock.get("packages"), dict) else None
    if not isinstance(root_lock, dict):
        raise ValueError("npm lock root is missing")
    declared: dict[str, object] = {}
    for section in ("dependencies", "devDependencies"):
        values = package.get(section, {})
        locked_values = root_lock.get(section, {})
        if not isinstance(values, dict) or values != locked_values:
            raise ValueError(f"package.json and lockfile {section} differ")
        declared.update(values)
    for name, version in declared.items():
        if not isinstance(version, str) or any(character in version for character in "^~*<>=| "):
            raise ValueError(f"TypeScript root dependency is not exact: {name}")
        locked = lock["packages"].get(f"node_modules/{name}")
        if not isinstance(locked, dict) or locked.get("version") != version:
            raise ValueError(f"TypeScript root dependency is not exactly resolved: {name}")
    identity = {
        "schema_version": 1,
        "package_json_sha256": hashlib.sha256(package_json).hexdigest(),
        "package_lock_sha256": hashlib.sha256(package_lock).hexdigest(),
        "tarball_count": len(records),
        "tarball_set_sha256": canonical_sha256(records),
    }
    return {**identity, "packages": records}


def worktree_lock_identity(root: Path = ROOT) -> dict[str, object]:
    return validate_manifest(
        _read_json((root / MANIFEST_PATH).read_bytes(), "npm tarball manifest"),
        package_json=(root / "clients/typescript/package.json").read_bytes(),
        package_lock=(root / "clients/typescript/package-lock.json").read_bytes(),
    )


def committed_lock_identity(root: Path, release_sha: str, blob_reader) -> dict[str, object]:
    return validate_manifest(
        _read_json(blob_reader(root, release_sha, MANIFEST_PATH), "npm tarball manifest"),
        package_json=blob_reader(root, release_sha, "clients/typescript/package.json"),
        package_lock=blob_reader(root, release_sha, "clients/typescript/package-lock.json"),
    )


def _safe_members(payload: bytes, record: dict[str, object]) -> list[tarfile.TarInfo]:
    if len(payload) != record["bytes"] or _integrity(payload) != record["integrity"] or hashlib.sha256(payload).hexdigest() != record["sha256"]:
        raise ValueError(f"npm tarball digest/size mismatch: {record['filename']}")
    members: list[tarfile.TarInfo]
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
    except (tarfile.TarError, EOFError) as error:
        raise ValueError(f"npm tarball is malformed: {record['filename']}") from error
    if not members or len(members) > MAX_ENTRIES:
        raise ValueError("npm tarball entry count is unsafe")
    expanded = 0
    seen: set[str] = set()
    has_package_json = False
    for member in members:
        if "\\" in member.name or member.name.startswith("/") or "\x00" in member.name:
            raise ValueError("npm tarball path is unsafe")
        parts = PurePosixPath(member.name).parts
        root_name = str(record["archive_root"])
        if (
            not parts
            or parts[0] != root_name
            or any(part in {"", ".", ".."} for part in parts)
            or (len(parts) == 1 and not member.isdir())
        ):
            raise ValueError("npm tarball must have its one exact reviewed root")
        normalized = "/".join(parts)
        if normalized in seen:
            raise ValueError("npm tarball contains duplicate normalized paths")
        seen.add(normalized)
        if member.islnk() or member.issym() or member.isdev() or member.isfifo() or not (member.isdir() or member.isfile()):
            raise ValueError("npm tarball contains a disallowed member type")
        if member.mode & 0o7000:
            raise ValueError("npm tarball contains privileged mode bits")
        if member.isfile():
            expanded += member.size
        if expanded > MAX_EXPANDED_BYTES:
            raise ValueError("npm tarball expands beyond the reviewed limit")
        has_package_json |= normalized == f"{root_name}/package.json" and member.isfile()
    if not has_package_json:
        raise ValueError("npm tarball lacks package/package.json")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        handle = archive.extractfile(f"{root_name}/package.json")
        metadata = _read_json(handle.read() if handle else b"", "npm package metadata")
    if metadata.get("name") != record["name"] or metadata.get("version") != record["version"]:
        raise ValueError("npm tarball package identity differs from the lock")
    return members


def verify_tarball_bytes(payload: bytes, record: dict[str, object]) -> None:
    _safe_members(payload, record)


def verify_tarball_directory(path: Path, identity: dict[str, object]) -> dict[str, object]:
    details = os.lstat(path)
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode) or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
        raise ValueError("npm tarball directory must be owner-only")
    expected = {str(item["filename"]): item for item in identity["packages"]}
    actual = {item.name: item for item in path.iterdir()}
    if set(actual) != set(expected):
        raise ValueError("npm tarball directory membership differs from the lock")
    for name, item in actual.items():
        details = os.lstat(item)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid() or details.st_nlink != 1 or stat.S_IMODE(details.st_mode) != 0o400:
            raise ValueError(f"npm tarball file is unsafe: {name}")
        payload = item.read_bytes()
        verify_tarball_bytes(payload, expected[name])
    return {key: value for key, value in identity.items() if key != "packages"}


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "redirects are forbidden", headers, fp)


def materialize_tarballs(destination: Path, identity: dict[str, object]) -> dict[str, object]:
    if destination.exists():
        raise ValueError("npm tarball destination must not already exist")
    destination.mkdir(mode=0o700, parents=True)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirect(), urllib.request.HTTPSHandler())
    try:
        for record in identity["packages"]:
            request = urllib.request.Request(str(record["url"]), method="GET", headers={"Accept-Encoding": "identity"})
            with opener.open(request, timeout=60) as response:
                if response.status != 200 or response.geturl() != record["url"]:
                    raise ValueError("npm registry response identity changed")
                payload = response.read(int(record["bytes"]) + 1)
            verify_tarball_bytes(payload, record)
            target = destination / str(record["filename"])
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o400)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(target, 0o400)
        os.chmod(destination, 0o700)
        return verify_tarball_directory(destination, identity)
    except Exception:
        for item in destination.glob("*"):
            item.chmod(0o600, follow_symlinks=False)
        shutil.rmtree(destination, ignore_errors=True)
        raise


def extract_sealed_tarballs(destination: Path, identity: dict[str, object], descriptors: dict[str, int]) -> None:
    if set(descriptors) != {str(record["filename"]) for record in identity["packages"]}:
        raise ValueError("sealed npm descriptor inventory differs from the lock")
    if destination.exists():
        raise ValueError("node_modules destination already exists")
    destination.mkdir(mode=0o700, parents=True)
    for record in identity["packages"]:
        name = str(record["filename"])
        fd = descriptors[name]
        os.lseek(fd, 0, os.SEEK_SET)
        payload = b""
        while len(payload) <= int(record["bytes"]):
            block = os.read(fd, min(1024 * 1024, int(record["bytes"]) + 1 - len(payload)))
            if not block:
                break
            payload += block
        _safe_members(payload, record)
        package_root = destination.joinpath(*str(record["name"]).split("/"))
        package_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for member in archive.getmembers():
                relative = PurePosixPath(member.name).relative_to(str(record["archive_root"]))
                if not relative.parts:
                    continue
                target = package_root.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("npm regular file could not be read")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, 0o700 if member.mode & 0o111 else 0o600)


def extract_sealed_manifest(destination: Path, identity: dict[str, object], raw: str) -> dict[str, object]:
    try:
        records = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("sealed npm descriptor manifest is malformed") from error
    if not isinstance(records, list):
        raise ValueError("sealed npm descriptor manifest is malformed")
    expected = {str(item["filename"]): item for item in identity["packages"]}
    mapped: dict[str, int] = {}
    required_seals = 0x0001 | 0x0002 | 0x0004 | 0x0008
    for record in records:
        if not isinstance(record, dict) or set(record) != {"filename", "fd", "bytes", "sha256", "seals"}:
            raise ValueError("sealed npm descriptor record is malformed")
        filename, fd = record["filename"], record["fd"]
        if filename not in expected or filename in mapped or not isinstance(fd, int) or isinstance(fd, bool):
            raise ValueError("sealed npm descriptor inventory is malformed")
        details = os.fstat(fd)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_size != expected[filename]["bytes"]
            or record["bytes"] != details.st_size
            or record["seals"] != seals
            or seals & required_seals != required_seals
        ):
            raise ValueError("sealed npm descriptor is not immutable")
        os.lseek(fd, 0, os.SEEK_SET)
        blocks: list[bytes] = []
        remaining = details.st_size + 1
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                break
            blocks.append(block)
            remaining -= len(block)
        payload = b"".join(blocks)
        if hashlib.sha256(payload).hexdigest() != record["sha256"]:
            raise ValueError("sealed npm descriptor digest differs from its record")
        verify_tarball_bytes(payload, expected[filename])
        mapped[filename] = fd
    extract_sealed_tarballs(destination, identity, mapped)
    return {key: value for key, value in identity.items() if key != "packages"}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--materialize", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--extract-sealed", type=Path)
    args = parser.parse_args(argv)
    choices = [args.materialize, args.verify, args.extract_sealed]
    if sum(value is not None for value in choices) != 1:
        parser.error("choose exactly one operation")
    try:
        identity = worktree_lock_identity()
        if args.materialize:
            result = materialize_tarballs(args.materialize, identity)
        elif args.verify:
            result = verify_tarball_directory(args.verify, identity)
        else:
            raw = os.environ.get("TINYZKP_SEALED_NPM_TARBALLS")
            if raw is None:
                raise ValueError("sealed npm descriptor manifest is missing")
            result = extract_sealed_manifest(args.extract_sealed, identity, raw)
    except (OSError, ValueError, urllib.error.URLError) as error:
        print(f"npm tarball preparation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.extract_sealed:
        print(
            "PASS TinyZKP locked TypeScript SDK environment "
            f"({result['tarball_count']} tarballs, {result['tarball_set_sha256']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
