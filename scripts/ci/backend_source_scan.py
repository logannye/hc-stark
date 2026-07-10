#!/usr/bin/env python3
"""Scan the complete Git candidate set for secrets and generated artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
MAX_SCAN_BYTES = 32 * 1024 * 1024
GENERATED_COMPONENTS = {"target", "dist", "node_modules", "__pycache__"}
GENERATED_NAMES = {".DS_Store", ".env"}
GENERATED_SUFFIXES = {".pyc", ".pyo", ".profraw", ".tmp", ".o", ".rlib", ".rmeta", ".crate"}
SECRET_PATTERNS = {
    "stripe_secret": re.compile(rb"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"),
    "stripe_webhook": re.compile(rb"whsec_[A-Za-z0-9]{24,}"),
    "aws_access_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


def candidate_files(root: Path = ROOT) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    files = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(raw.decode("utf-8"))
        path = root / relative
        if path.is_file() and not path.is_symlink():
            files.append(path)
    return sorted(files)


def scan(root: Path = ROOT) -> tuple[list[str], dict[str, object]]:
    failures: list[str] = []
    hasher = hashlib.sha256()
    scanned = 0
    for path in candidate_files(root):
        relative = path.relative_to(root)
        if (
            GENERATED_COMPONENTS.intersection(relative.parts)
            or path.name in GENERATED_NAMES
            or path.suffix in GENERATED_SUFFIXES
        ):
            failures.append(f"generated artifact is in the candidate set: {relative}")
            continue
        size = path.stat().st_size
        if size > MAX_SCAN_BYTES:
            failures.append(f"candidate file exceeds the 32 MiB source-scan limit: {relative}")
            continue
        payload = path.read_bytes()
        hasher.update(relative.as_posix().encode())
        hasher.update(b"\0")
        hasher.update(hashlib.sha256(payload).digest())
        scanned += 1
        if b"\0" in payload:
            continue
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(payload):
                failures.append(f"{name} marker found in {relative}")
    metadata = {
        "schema_version": 1,
        "secret_scan_clean": not any("marker found" in failure for failure in failures),
        "generated_scan_clean": not any("generated artifact" in failure for failure in failures),
        "candidate_file_count": scanned,
        "candidate_set_sha256": hasher.hexdigest(),
    }
    return failures, metadata


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    failures, metadata = scan()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(f".{args.output.name}.tmp")
        temporary.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(args.output)
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1
    print(
        f"PASS  backend source scan ({metadata['candidate_file_count']} files, "
        f"{metadata['candidate_set_sha256']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
