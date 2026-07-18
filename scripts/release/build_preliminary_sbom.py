#!/usr/bin/env python3
"""Build a deterministic preliminary SPDX inventory from the locked Rust graph."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def spdx_id(name: str, version: str, source: str, ordinal: int) -> str:
    label = re.sub(r"[^A-Za-z0-9.-]", "-", f"{name}-{version}").strip("-.")
    identity = hashlib.sha256(f"{name}\0{version}\0{source}\0{ordinal}".encode()).hexdigest()[:12]
    return f"SPDXRef-Package-{label or 'unnamed'}-{identity}"


def package_entry(package: dict[str, object], ordinal: int) -> dict[str, object]:
    name = package.get("name")
    version = package.get("version")
    source = package.get("source", "")
    checksum = package.get("checksum")
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise ValueError("Cargo.lock package identity is malformed")
    if not isinstance(source, str):
        raise ValueError(f"Cargo.lock source is malformed for {name} {version}")
    if checksum is not None and (not isinstance(checksum, str) or not SHA256.fullmatch(checksum)):
        raise ValueError(f"Cargo.lock checksum is malformed for {name} {version}")
    result: dict[str, object] = {
        "SPDXID": spdx_id(name, version, source, ordinal),
        "name": name,
        "versionInfo": version,
        "downloadLocation": source or "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if checksum is not None:
        result["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
    if source.startswith("registry+"):
        result["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:cargo/{name}@{version}",
            }
        ]
    return result


def canonical_created(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("created must be an RFC 3339 timestamp with second precision") from error
    if parsed.tzinfo is None or parsed.microsecond != 0:
        raise ValueError("created must include a UTC offset and use second precision")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_sbom(lock_path: Path, *, release_sha: str, created: str) -> dict[str, object]:
    if not release_sha or len(release_sha) > 128 or any(character.isspace() for character in release_sha):
        raise ValueError("release SHA must be a non-empty, whitespace-free value of at most 128 characters")
    created = canonical_created(created)
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    raw_packages = lock.get("package")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise ValueError("Cargo.lock does not contain a package graph")
    packages = [package_entry(package, ordinal) for ordinal, package in enumerate(raw_packages)]
    packages.sort(key=lambda package: (str(package["name"]), str(package["versionInfo"]), str(package["SPDXID"])))
    lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"tinyzkp-engine-preliminary-{lock_digest[:12]}",
        "documentNamespace": f"https://tinyzkp.com/spdx/backend/{release_sha}/{lock_digest}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: TinyZKP build_preliminary_sbom.py"],
            "comment": "Preliminary dependency inventory derived deterministically from Cargo.lock; release artifacts receive a separate file-level SBOM.",
        },
        "documentDescribes": [package["SPDXID"] for package in packages],
        "packages": packages,
        "externalDocumentRefs": [],
        "annotations": [
            {
                "annotationDate": created,
                "annotationType": "OTHER",
                "annotator": "Tool: TinyZKP build_preliminary_sbom.py",
                "comment": f"Cargo.lock SHA-256: {lock_digest}; backend release: {release_sha}",
            }
        ],
    }


def write_atomic(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=ROOT / "Cargo.lock")
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    value = build_sbom(args.lock, release_sha=args.release_sha, created=args.created)
    write_atomic(args.output, value)
    print(json.dumps({"output": str(args.output), "sha256": sha256(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"preliminary SBOM generation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
