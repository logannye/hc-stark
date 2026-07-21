#!/usr/bin/env python3
"""Bind the released TinyZKP engine CLI and OCI archive to one identity."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
from typing import BinaryIO


ROOT = Path(__file__).resolve().parents[2]
PROFILE = "tinyzkp-p3-goldilocks-v1"
PLONKY3_VERSION = "0.6.1"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 1024 * 1024
MAX_LAYER_BYTES = 512 * 1024 * 1024
MAX_ENGINE_BYTES = 256 * 1024 * 1024
EXPECTED_ENTRYPOINT = ["/usr/local/bin/tinyzkp-engine"]
EXPECTED_VOLUMES = {"/scratch", "/work"}
EXPECTED_SOURCE = "https://github.com/logannye/hc-stark"
EXPECTED_USER = "10001:10001"


def timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def safe_file(root: Path, path: Path) -> Path:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    candidate = candidate.absolute()
    if not candidate.is_relative_to(root):
        raise ValueError(f"artifact is outside the repository: {path}")
    current = root
    for part in candidate.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"artifact path contains a symlink: {path}")
    if not candidate.is_file():
        raise ValueError(f"artifact is missing: {path}")
    return candidate


def artifact_path(root: Path, path: Path) -> str:
    return safe_file(root, path).relative_to(root.resolve()).as_posix()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json_file(root: Path, path: Path) -> tuple[Path, dict[str, object]]:
    resolved = safe_file(root, path)
    if resolved.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON artifact exceeds 1 MiB: {path}")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"JSON artifact is malformed: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")
    return resolved, value


def read_tar_json(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
) -> dict[str, object]:
    member = members.get(name)
    if member is None or not member.isreg() or member.size > MAX_JSON_BYTES:
        raise ValueError(f"OCI JSON member is missing or unsafe: {name}")
    extracted: BinaryIO | None = archive.extractfile(member)
    if extracted is None:
        raise ValueError(f"OCI JSON member is unreadable: {name}")
    payload = extracted.read(MAX_JSON_BYTES + 1)
    if len(payload) != member.size:
        raise ValueError(f"OCI JSON member is truncated: {name}")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"OCI JSON member is malformed: {name}") from error
    if not isinstance(value, dict):
        raise ValueError(f"OCI JSON member must contain an object: {name}")
    return value


def descriptor_blob(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    descriptor: object,
) -> tuple[str, dict[str, object]]:
    if not isinstance(descriptor, dict):
        raise ValueError("OCI descriptor is malformed")
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or SHA256.fullmatch(digest.removeprefix("sha256:")) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > MAX_JSON_BYTES
    ):
        raise ValueError("OCI descriptor identity is malformed")
    name = f"blobs/sha256/{digest.removeprefix('sha256:')}"
    member = members.get(name)
    if member is None or not member.isreg() or member.size != size:
        raise ValueError(f"OCI descriptor blob is missing or size-skewed: {digest}")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ValueError(f"OCI descriptor blob is unreadable: {digest}")
    payload = extracted.read(MAX_JSON_BYTES + 1)
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest[7:]:
        raise ValueError(f"OCI descriptor blob digest is skewed: {digest}")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"OCI descriptor blob is malformed: {digest}") from error
    if not isinstance(value, dict):
        raise ValueError(f"OCI descriptor blob must contain an object: {digest}")
    return digest, value


def descriptor_bytes(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    descriptor: object,
    *,
    label: str,
) -> tuple[str, bytes]:
    if not isinstance(descriptor, dict):
        raise ValueError(f"OCI {label} descriptor is malformed")
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or SHA256.fullmatch(digest.removeprefix("sha256:")) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > MAX_LAYER_BYTES
    ):
        raise ValueError(f"OCI {label} descriptor identity is malformed")
    member = members.get(f"blobs/sha256/{digest[7:]}")
    if member is None or not member.isreg() or member.size != size:
        raise ValueError(f"OCI {label} blob is missing or size-skewed: {digest}")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ValueError(f"OCI {label} blob is unreadable: {digest}")
    payload = extracted.read(MAX_LAYER_BYTES + 1)
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest[7:]:
        raise ValueError(f"OCI {label} blob digest is skewed: {digest}")
    return digest, payload


def embedded_engine_sha256(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    layers: object,
) -> str:
    if not isinstance(layers, list) or not layers:
        raise ValueError("OCI image layers are missing")
    engine_payload: bytes | None = None
    target = PurePosixPath("usr/local/bin/tinyzkp-engine")
    whiteout = PurePosixPath("usr/local/bin/.wh.tinyzkp-engine")
    for index, descriptor in enumerate(layers):
        _digest, payload = descriptor_bytes(
            archive,
            members,
            descriptor,
            label=f"layer {index}",
        )
        try:
            layer = tarfile.open(fileobj=io.BytesIO(payload), mode="r:*")
        except tarfile.TarError as error:
            raise ValueError(f"OCI layer {index} is unreadable") from error
        with layer:
            seen: set[PurePosixPath] = set()
            for member in layer.getmembers():
                normalized = member.name.removeprefix("./").lstrip("/")
                pure = PurePosixPath(normalized)
                if (
                    not normalized
                    or PurePosixPath(member.name).is_absolute()
                    or ".." in pure.parts
                    or pure in seen
                ):
                    raise ValueError(f"OCI layer {index} contains an unsafe path")
                seen.add(pure)
                if pure == whiteout:
                    engine_payload = None
                    continue
                if pure != target:
                    continue
                if not member.isreg() or member.size <= 0 or member.size > MAX_ENGINE_BYTES:
                    raise ValueError("OCI engine entry is not a bounded regular file")
                extracted = layer.extractfile(member)
                if extracted is None:
                    raise ValueError("OCI engine entry is unreadable")
                candidate = extracted.read(MAX_ENGINE_BYTES + 1)
                if len(candidate) != member.size:
                    raise ValueError("OCI engine entry is truncated")
                engine_payload = candidate
    if engine_payload is None:
        raise ValueError("OCI image does not contain the TinyZKP engine binary")
    return hashlib.sha256(engine_payload).hexdigest()


def oci_identity(
    path: Path,
    *,
    release_sha: str,
    release_ref: str,
    expected_engine_sha256: str,
) -> dict[str, object]:
    try:
        archive = tarfile.open(path, mode="r:*")
    except (OSError, tarfile.TarError) as error:
        raise ValueError("OCI archive is unreadable") from error
    with archive:
        members: dict[str, tarfile.TarInfo] = {}
        for member in archive.getmembers():
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or member.name in members:
                raise ValueError("OCI archive contains an unsafe or duplicate path")
            if not (member.isdir() or member.isreg()):
                raise ValueError("OCI archive contains links or special files")
            members[member.name] = member
        layout = read_tar_json(archive, members, "oci-layout")
        index = read_tar_json(archive, members, "index.json")
        if layout != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("OCI layout version is unsupported")
        descriptors = index.get("manifests")
        if index.get("schemaVersion") != 2 or not isinstance(descriptors, list):
            raise ValueError("OCI index is malformed")

        candidates: list[
            tuple[str, str, dict[str, object], dict[str, object]]
        ] = []
        for descriptor in descriptors:
            manifest_digest, manifest = descriptor_blob(archive, members, descriptor)
            if manifest.get("schemaVersion") != 2:
                continue
            config_digest, config = descriptor_blob(
                archive, members, manifest.get("config")
            )
            if config.get("os") == "linux" and config.get("architecture") == "amd64":
                candidates.append((manifest_digest, config_digest, config, manifest))
        if len(candidates) != 1:
            raise ValueError("OCI archive must contain exactly one linux/amd64 image")

        manifest_digest, config_digest, image, manifest = candidates[0]
        config = image.get("config")
        if not isinstance(config, dict):
            raise ValueError("OCI image config is missing")
        labels = config.get("Labels")
        volumes = config.get("Volumes")
        if (
            not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.source") != EXPECTED_SOURCE
            or labels.get("org.opencontainers.image.revision") != release_sha
            or labels.get("org.opencontainers.image.version") != release_ref
            or labels.get("org.opencontainers.image.tinyzkp.profile") != PROFILE
            or config.get("User") != EXPECTED_USER
            or config.get("WorkingDir") != "/work"
            or config.get("Entrypoint") != EXPECTED_ENTRYPOINT
            or config.get("Cmd") != ["--help"]
            or not isinstance(volumes, dict)
            or set(volumes) != EXPECTED_VOLUMES
        ):
            raise ValueError("OCI runtime identity or confinement contract is skewed")
        embedded_sha256 = embedded_engine_sha256(
            archive, members, manifest.get("layers")
        )
        if embedded_sha256 != expected_engine_sha256:
            raise ValueError(
                "OCI embedded engine digest differs from the released CLI binary"
            )
        return {
            "manifest_digest": manifest_digest,
            "config_digest": config_digest,
            "platform": "linux/amd64",
            "entrypoint": EXPECTED_ENTRYPOINT,
            "embedded_engine_sha256": embedded_sha256,
        }


def build_report(
    *,
    root: Path,
    release_sha: str,
    release_ref: str,
    engine: Path,
    engine_release: Path,
    oci_archive: Path,
    compatibility_manifest: Path,
    checked_at: str | None = None,
) -> dict[str, object]:
    root = root.resolve()
    if SHA1.fullmatch(release_sha) is None:
        raise ValueError("release SHA must be one full lowercase Git SHA-1")
    if not release_ref.startswith("backend-v") or len(release_ref) > 128:
        raise ValueError("release ref must be one backend-v tag")

    engine = safe_file(root, engine)
    oci_archive = safe_file(root, oci_archive)
    release_path, release = read_json_file(root, engine_release)
    compatibility_path, compatibility = read_json_file(root, compatibility_manifest)
    expected_release_keys = {
        "service",
        "package_version",
        "release_sha",
        "release_ref",
        "backend",
        "plonky3_version",
        "compatibility_profile",
        "dependency_lock_sha256",
    }
    if (
        set(release) != expected_release_keys
        or release.get("service") != "cli"
        or release.get("release_sha") != release_sha
        or release.get("release_ref") != release_ref
        or release.get("backend") != "plonky3"
        or release.get("plonky3_version") != PLONKY3_VERSION
        or release.get("compatibility_profile") != PROFILE
        or not isinstance(release.get("package_version"), str)
        or not release.get("package_version")
        or SHA256.fullmatch(str(release.get("dependency_lock_sha256"))) is None
    ):
        raise ValueError("engine release metadata is incomplete or release-skewed")
    if (
        compatibility.get("schema_version") != 1
        or compatibility.get("profile_id") != PROFILE
        or compatibility.get("cargo_lock_sha256")
        != release.get("dependency_lock_sha256")
        or not isinstance(compatibility.get("release_status"), str)
        or not compatibility.get("release_status")
        or not isinstance(compatibility.get("upstream"), dict)
        or compatibility["upstream"].get("tag") != f"v{PLONKY3_VERSION}"
    ):
        raise ValueError("compatibility manifest is incomplete or profile-skewed")

    engine_sha256 = sha256_file(engine)
    oci = oci_identity(
        oci_archive,
        release_sha=release_sha,
        release_ref=release_ref,
        expected_engine_sha256=engine_sha256,
    )
    return {
        "schema_version": 1,
        "release_sha": release_sha,
        "release_ref": release_ref,
        "profile": PROFILE,
        "checked_at": checked_at or timestamp(),
        "surfaces": {
            "engine_cli": {
                "service": "engine_cli",
                "release_sha": release_sha,
                "artifact": artifact_path(root, engine),
                "artifact_sha256": engine_sha256,
                "identity_artifact": artifact_path(root, release_path),
                "identity_artifact_sha256": sha256_file(release_path),
                "package_version": release["package_version"],
            },
            "engine_oci": {
                "service": "engine_oci",
                "release_sha": release_sha,
                "artifact": artifact_path(root, oci_archive),
                "artifact_sha256": sha256_file(oci_archive),
                **oci,
            },
        },
        "compatibility": {
            "artifact": artifact_path(root, compatibility_path),
            "artifact_sha256": sha256_file(compatibility_path),
            "profile_id": PROFILE,
            "plonky3_version": PLONKY3_VERSION,
            "release_status": compatibility["release_status"],
        },
    }


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("identity report output is a symlink")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--release-ref", required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--engine-release", type=Path, required=True)
    parser.add_argument("--oci-archive", type=Path, required=True)
    parser.add_argument("--compatibility-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        if not output.absolute().is_relative_to(ROOT.resolve()):
            raise ValueError("identity report output is outside the repository")
        report = build_report(
            root=ROOT,
            release_sha=args.release_sha,
            release_ref=args.release_ref,
            engine=args.engine,
            engine_release=args.engine_release,
            oci_archive=args.oci_archive,
            compatibility_manifest=args.compatibility_manifest,
        )
        write_json_atomic(output, report)
    except (OSError, ValueError) as error:
        print(f"engine identity report failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
