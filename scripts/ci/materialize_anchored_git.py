#!/usr/bin/env python3
"""Materialize the exact reviewed Linux Git binary from a pinned Debian snapshot."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import stat
import tarfile
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
TRUST = ROOT / "release" / "release-trust-v1.json"


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def ar_members(payload: bytes) -> dict[str, bytes]:
    if not payload.startswith(b"!<arch>\n"):
        raise ValueError("anchored Git package is not a Debian ar archive")
    members: dict[str, bytes] = {}
    offset = 8
    while offset < len(payload):
        if offset + 60 > len(payload):
            raise ValueError("truncated Debian ar member")
        header = payload[offset : offset + 60]
        if header[58:60] != b"`\n":
            raise ValueError("malformed Debian ar member")
        name = header[:16].decode("ascii").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError as error:
            raise ValueError("malformed Debian ar size") from error
        start = offset + 60
        end = start + size
        if end > len(payload):
            raise ValueError("truncated Debian ar payload")
        members[name] = payload[start:end]
        offset = end + (size % 2)
    return members


def extract_git(package: bytes) -> bytes:
    members = ar_members(package)
    data_name = next((name for name in members if name.startswith("data.tar")), None)
    if data_name is None:
        raise ValueError("Debian package has no data archive")
    with tarfile.open(fileobj=io.BytesIO(members[data_name]), mode="r:*") as archive:
        candidates = [member for member in archive.getmembers() if member.name.lstrip("./") == "usr/bin/git"]
        if len(candidates) != 1 or not candidates[0].isfile():
            raise ValueError("Debian package has no single regular usr/bin/git")
        handle = archive.extractfile(candidates[0])
        if handle is None:
            raise ValueError("cannot extract anchored Git executable")
        return handle.read()


def materialize(output: Path, trust_path: Path = TRUST) -> Path:
    if not os.sys.platform.startswith("linux") or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise ValueError("anchored Linux Git materialization requires linux-x86_64")
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    anchor = trust["git"]["platforms"]["linux-x86_64"]
    request = urllib.request.Request(anchor["package_url"], headers={"User-Agent": "TinyZKP-release-gate/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        package = response.read(32 * 1024 * 1024 + 1)
    if len(package) > 32 * 1024 * 1024 or sha256(package) != anchor["package_sha256"]:
        raise ValueError("anchored Git package digest mismatch")
    executable = extract_git(package)
    if sha256(executable) != anchor["sha256"]:
        raise ValueError("anchored Git executable digest mismatch")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".git.", dir=output.parent)
    try:
        os.write(descriptor, executable)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o700)
    finally:
        os.close(descriptor)
    os.replace(temporary, output)
    if not stat.S_ISREG(output.stat().st_mode) or stat.S_IMODE(output.stat().st_mode) != 0o700:
        raise ValueError("anchored Git output permissions are unsafe")
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args()
    output = materialize(args.output.resolve())
    if args.github_env:
        with args.github_env.open("a", encoding="utf-8") as handle:
            handle.write(f"TINYZKP_ANCHORED_GIT={output}\n")
    print(output)


if __name__ == "__main__":
    main()

