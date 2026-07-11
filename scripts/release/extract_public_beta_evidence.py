#!/usr/bin/env python3
"""Safely materialize a private public-beta evidence archive in a checkout."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile


MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_MEMBERS = 4096
ROOT_NAME = "release-evidence"


def extract(archive: Path, checkout: Path) -> Path:
    archive = archive.resolve(strict=True)
    checkout = checkout.resolve(strict=True)
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("evidence archive exceeds the compressed size limit")
    destination = checkout / ROOT_NAME
    if destination.exists() or destination.is_symlink():
        raise ValueError("release-evidence destination already exists")
    seen: set[PurePosixPath] = set()
    expanded = 0
    os.mkdir(destination, 0o700)
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            members = bundle.getmembers()
            if not members or len(members) > MAX_MEMBERS:
                raise ValueError("evidence archive member count is invalid")
            for member in members:
                relative = PurePosixPath(member.name)
                if (
                    relative.is_absolute()
                    or not relative.parts
                    or relative.parts[0] != ROOT_NAME
                    or ".." in relative.parts
                    or relative in seen
                ):
                    raise ValueError("evidence archive contains an unsafe path")
                seen.add(relative)
                if member.issym() or member.islnk() or member.isdev():
                    raise ValueError("evidence archive contains a link or device")
                target = checkout.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    target.chmod(0o700)
                    continue
                if not member.isfile() or member.size <= 0:
                    raise ValueError("evidence archive contains an invalid file")
                expanded += member.size
                if expanded > MAX_EXPANDED_BYTES:
                    raise ValueError("evidence archive exceeds the expanded size limit")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError("evidence archive file cannot be read")
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                with source, os.fdopen(descriptor, "wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                if target.stat().st_size != member.size:
                    raise ValueError("evidence archive file length changed")
        manifest = destination / "public-beta-evidence.json"
        if not manifest.is_file() or manifest.is_symlink():
            raise ValueError("public-beta evidence manifest is missing")
        return manifest
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    args = parser.parse_args()
    print(extract(args.archive, args.checkout))


if __name__ == "__main__":
    main()
