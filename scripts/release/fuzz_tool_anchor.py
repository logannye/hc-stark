#!/usr/bin/env python3
"""Capture and verify the exact cargo-fuzz executable used for release evidence.

`capture` emits an owner-only, explicitly unreviewed candidate. It never edits
the committed release trust contract. An authorized reviewer must reproduce
and approve the candidate before deliberately adding its digest to
`release/release-trust-v1.json` in a separate reviewed source change.

`verify` recomputes the candidate from the current executable and release
source, then requires an exact digest already present in the committed trust
contract. Missing trust is a hard failure, not an instruction to trust the
freshly observed executable.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

import evidence_runtime
import run_fuzz_smoke


ROOT = Path(__file__).resolve().parents[2]
MAX_CANDIDATE_BYTES = 64 * 1024
TRUST_PATH = "release/release-trust-v1.json"
HOST_LINE = re.compile(r"^host: ([A-Za-z0-9_.-]+)$")
CANDIDATE_KEYS = {
    "cargo_fuzz_identity",
    "cargo_identity",
    "dependency_lock_sha256",
    "host",
    "proposed_trust_entry",
    "release_sha",
    "review_required",
    "rust_toolchain_sha256",
    "rustc_identity",
    "schema_version",
    "source_tree_sha256",
    "status",
    "toolchain",
    "trust_path",
}
IDENTITY_KEYS = {"path", "sha256", "version"}


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_git_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def cargo_host(version: str) -> str:
    matches = [
        match.group(1)
        for line in version.splitlines()
        if (match := HOST_LINE.fullmatch(line)) is not None
    ]
    if len(matches) != 1:
        raise ValueError("cargo -Vv must contain exactly one canonical host line")
    return matches[0]


def _validate_identity(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != IDENTITY_KEYS:
        raise ValueError(f"{label} identity has an invalid schema")
    if not isinstance(value.get("path"), str) or not value["path"]:
        raise ValueError(f"{label} identity path is invalid")
    if not _is_digest(value.get("sha256")):
        raise ValueError(f"{label} identity digest is invalid")
    if not isinstance(value.get("version"), str) or not value["version"]:
        raise ValueError(f"{label} identity version is invalid")
    return value


def validate_candidate(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != CANDIDATE_KEYS:
        raise ValueError("cargo-fuzz anchor candidate has an invalid schema")
    if value.get("schema_version") != 1 or isinstance(
        value.get("schema_version"), bool
    ):
        raise ValueError("cargo-fuzz anchor candidate version is invalid")
    if value.get("status") != "unreviewed" or value.get("review_required") is not True:
        raise ValueError("cargo-fuzz anchor candidate cannot represent trusted state")
    if value.get("toolchain") != run_fuzz_smoke.FUZZ_TOOLCHAIN:
        raise ValueError("cargo-fuzz anchor candidate toolchain is not frozen")
    if value.get("trust_path") != TRUST_PATH:
        raise ValueError("cargo-fuzz anchor candidate trust path is invalid")
    host = value.get("host")
    if not isinstance(host, str) or HOST_LINE.fullmatch(f"host: {host}") is None:
        raise ValueError("cargo-fuzz anchor candidate host is invalid")
    if not _is_git_sha(value.get("release_sha")):
        raise ValueError("cargo-fuzz anchor candidate release_sha is invalid")
    for name in (
        "source_tree_sha256",
        "dependency_lock_sha256",
        "rust_toolchain_sha256",
    ):
        if not _is_digest(value.get(name)):
            raise ValueError(f"cargo-fuzz anchor candidate {name} is invalid")
    _validate_identity(value.get("cargo_identity"), "cargo")
    _validate_identity(value.get("rustc_identity"), "rustc")
    cargo_fuzz = _validate_identity(value.get("cargo_fuzz_identity"), "cargo-fuzz")
    if cargo_fuzz["version"] != run_fuzz_smoke.CARGO_FUZZ_VERSION:
        raise ValueError("cargo-fuzz anchor candidate version is not frozen")
    proposed = value.get("proposed_trust_entry")
    if not isinstance(proposed, dict) or set(proposed) != {host}:
        raise ValueError("cargo-fuzz proposed trust entry is invalid")
    if proposed[host] != cargo_fuzz["sha256"]:
        raise ValueError("cargo-fuzz proposed trust digest does not match the executable")
    return value


def _tool_identities(
    root: Path, release_sha: str
) -> tuple[str, dict[str, object], dict[str, object], dict[str, object]]:
    environment = evidence_runtime.sanitized_environment(os.environ)
    cargo_path = evidence_runtime.rustup_tool_path(
        run_fuzz_smoke.FUZZ_TOOLCHAIN, "cargo", environment=environment, root=root
    )
    rustc_path = evidence_runtime.rustup_tool_path(
        run_fuzz_smoke.FUZZ_TOOLCHAIN, "rustc", environment=environment, root=root
    )
    cargo = evidence_runtime.executable_identity(
        str(cargo_path), ["-Vv"], environment=environment, root=root
    )
    rustc = evidence_runtime.executable_identity(
        str(rustc_path), ["-Vv"], environment=environment, root=root
    )
    host = cargo_host(str(cargo["version"]))
    anchor = evidence_runtime.toolchain_anchor(
        root, release_sha, execution_profile="fuzz", host=host
    )
    if (
        cargo["sha256"] != anchor["cargo_sha256"]
        or rustc["sha256"] != anchor["rustc_sha256"]
    ):
        raise ValueError("fuzz Cargo/rustc executables do not match committed anchors")
    cargo_fuzz = evidence_runtime.executable_identity(
        "cargo-fuzz", ["--version"], environment=environment, root=root
    )
    if cargo_fuzz["version"] != run_fuzz_smoke.CARGO_FUZZ_VERSION:
        raise ValueError(
            "cargo-fuzz version mismatch: expected "
            f"{run_fuzz_smoke.CARGO_FUZZ_VERSION}, found {cargo_fuzz['version']}"
        )
    return host, cargo, rustc, cargo_fuzz


def build_candidate(
    root: Path, release_sha: str | None, *, evidence_root: Path
) -> dict[str, object]:
    source = evidence_runtime.release_source_identity(
        root,
        release_sha,
        evidence_root=evidence_root,
        require_explicit_sha=True,
    )
    host, cargo, rustc, cargo_fuzz = _tool_identities(
        root, str(source["release_sha"])
    )
    candidate = {
        "schema_version": 1,
        **source,
        "status": "unreviewed",
        "review_required": True,
        "toolchain": run_fuzz_smoke.FUZZ_TOOLCHAIN,
        "host": host,
        "cargo_identity": cargo,
        "rustc_identity": rustc,
        "cargo_fuzz_identity": cargo_fuzz,
        "trust_path": TRUST_PATH,
        "proposed_trust_entry": {host: cargo_fuzz["sha256"]},
    }
    return validate_candidate(candidate)


def read_candidate(root: Path, path: Path) -> dict[str, object]:
    candidate = evidence_runtime.assert_no_symlink_ancestry(root, path)
    descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        details = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise ValueError("cargo-fuzz anchor candidate must be an owner-only file")
        payload = handle.read(MAX_CANDIDATE_BYTES + 1)
    if not payload or len(payload) > MAX_CANDIDATE_BYTES:
        raise ValueError("cargo-fuzz anchor candidate is empty or oversized")
    return validate_candidate(evidence_runtime.strict_json.loads(payload))


def require_trusted_digest(candidate: dict[str, object], trusted: str | None) -> None:
    observed = candidate["cargo_fuzz_identity"]["sha256"]  # type: ignore[index]
    if trusted is None:
        raise ValueError(
            f"cargo-fuzz is not anchored for {candidate['host']}; review the candidate "
            "and deliberately commit its digest before rerunning the nightly gate"
        )
    if trusted != observed:
        raise ValueError("installed cargo-fuzz does not match the committed trust anchor")


def capture(args: argparse.Namespace) -> int:
    output = evidence_runtime.assert_no_symlink_ancestry(ROOT, args.output)
    candidate = build_candidate(
        ROOT, args.release_sha, evidence_root=output.parent
    )
    evidence_runtime.write_json_atomic(ROOT, output, candidate)
    print(
        json.dumps(
            {
                "candidate": str(output.relative_to(ROOT)),
                "host": candidate["host"],
                "sha256": candidate["cargo_fuzz_identity"]["sha256"],  # type: ignore[index]
                "status": "unreviewed",
            },
            sort_keys=True,
        )
    )
    return 0


def verify(args: argparse.Namespace) -> int:
    path = evidence_runtime.assert_no_symlink_ancestry(ROOT, args.candidate)
    candidate = read_candidate(ROOT, path)
    current = build_candidate(
        ROOT, args.release_sha, evidence_root=path.parent
    )
    if candidate != current:
        raise ValueError("cargo-fuzz anchor candidate differs from the current release tool")
    try:
        trusted = evidence_runtime.cargo_fuzz_anchor(
            ROOT, str(candidate["release_sha"]), str(candidate["host"])
        )
    except ValueError as error:
        if "is not anchored" not in str(error):
            raise
        trusted = None
    require_trusted_digest(candidate, trusted)
    print(
        "PASS cargo-fuzz executable matches the separately reviewed committed anchor "
        f"for {candidate['host']}"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("capture", "verify"):
        command = subparsers.add_parser(name)
        command.add_argument(
            "--release-sha", default=os.environ.get("HC_RELEASE_SHA")
        )
        if name == "capture":
            command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        return capture(args) if args.command == "capture" else verify(args)
    except (OSError, ValueError) as error:
        print(f"BLOCKED cargo-fuzz trust gate: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
