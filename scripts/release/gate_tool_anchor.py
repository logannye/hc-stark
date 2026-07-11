#!/usr/bin/env python3
"""Capture and verify generic executables used by backend evidence gates.

Capture produces an owner-only, explicitly unreviewed candidate. It never
edits the committed trust contract. An independent reviewer must reproduce the
candidate before deliberately adding the exact platform mapping to
``release/release-trust-v1.json``.
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
import run_evidenced_command


ROOT = Path(__file__).resolve().parents[2]
TRUST_PATH = "release/release-trust-v1.json"
MAX_CANDIDATE_BYTES = 256 * 1024
PLATFORM = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,63}$")
TOOL_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
IDENTITY_KEYS = {"path", "sha256", "version"}
CANDIDATE_KEYS = {
    "dependency_lock_sha256",
    "platform",
    "proposed_trust_entry",
    "release_sha",
    "review_required",
    "rust_toolchain_sha256",
    "schema_version",
    "source_tree_sha256",
    "status",
    "tools",
    "trust_path",
}


def _is_digest(value: object, length: int = 64) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def expected_tool_names() -> frozenset[str]:
    """Derive the generic executables from the frozen evidence-gate commands."""

    names: set[str] = set()
    for spec in run_evidenced_command.GATES.values():
        command = list(spec["command"])
        primary = str(command[0])
        names.add(primary)
        if primary == "bash" and "sdk_contract_gate.sh" in str(command[1]):
            names.update({"python3", "node", "wasm-pack"})
    names.difference_update({"cargo", "rustc"})
    return frozenset(names)


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
        raise ValueError("gate-tool anchor candidate has an invalid schema")
    if value.get("schema_version") != 1 or isinstance(
        value.get("schema_version"), bool
    ):
        raise ValueError("gate-tool anchor candidate version is invalid")
    if value.get("status") != "unreviewed" or value.get("review_required") is not True:
        raise ValueError("gate-tool anchor candidate cannot represent trusted state")
    if value.get("trust_path") != TRUST_PATH:
        raise ValueError("gate-tool anchor candidate trust path is invalid")
    if not _is_digest(value.get("release_sha"), 40):
        raise ValueError("gate-tool anchor candidate release SHA is invalid")
    for field in (
        "source_tree_sha256",
        "dependency_lock_sha256",
        "rust_toolchain_sha256",
    ):
        if not _is_digest(value.get(field)):
            raise ValueError(f"gate-tool anchor candidate {field} is invalid")
    platform = value.get("platform")
    if not isinstance(platform, str) or PLATFORM.fullmatch(platform) is None:
        raise ValueError("gate-tool anchor candidate platform is invalid")
    tools = value.get("tools")
    expected_names = expected_tool_names()
    if not isinstance(tools, dict) or set(tools) != expected_names:
        raise ValueError(
            "gate-tool anchor candidate must contain exactly the evidence-gate tools"
        )
    for name, identity in tools.items():
        if TOOL_NAME.fullmatch(name) is None:
            raise ValueError("gate-tool anchor candidate tool name is invalid")
        _validate_identity(identity, name)
    proposed = value.get("proposed_trust_entry")
    expected_proposed = {
        name: identity["sha256"] for name, identity in sorted(tools.items())
    }
    if not isinstance(proposed, dict) or proposed != {platform: expected_proposed}:
        raise ValueError("gate-tool proposed trust entry differs from observed tools")
    return value


def observed_tools() -> dict[str, dict[str, object]]:
    environment = evidence_runtime.sanitized_environment(os.environ)
    observed: dict[str, dict[str, object]] = {}
    for spec in run_evidenced_command.GATES.values():
        for name, identity in run_evidenced_command._resolved_tools(
            spec, environment
        ).items():
            if name in {"cargo", "rustc"}:
                continue
            previous = observed.get(name)
            if previous is not None and previous != identity:
                raise ValueError(f"{name} resolves inconsistently across evidence gates")
            observed[name] = identity
    if set(observed) != expected_tool_names():
        raise ValueError("resolved generic gate-tool set is incomplete")
    return {name: observed[name] for name in sorted(observed)}


def build_candidate(
    root: Path, release_sha: str | None, *, evidence_root: Path
) -> dict[str, object]:
    source = evidence_runtime.release_source_identity(
        root,
        release_sha,
        evidence_root=evidence_root,
        require_explicit_sha=True,
    )
    platform = evidence_runtime.runtime_platform_key()
    tools = observed_tools()
    candidate = {
        "schema_version": 1,
        **source,
        "status": "unreviewed",
        "review_required": True,
        "platform": platform,
        "tools": tools,
        "trust_path": TRUST_PATH,
        "proposed_trust_entry": {
            platform: {
                name: identity["sha256"] for name, identity in tools.items()
            }
        },
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
            raise ValueError("gate-tool anchor candidate must be an owner-only file")
        payload = handle.read(MAX_CANDIDATE_BYTES + 1)
    if not payload or len(payload) > MAX_CANDIDATE_BYTES:
        raise ValueError("gate-tool anchor candidate is empty or oversized")
    return validate_candidate(evidence_runtime.strict_json.loads(payload))


def require_trusted_mapping(
    candidate: dict[str, object], trusted: dict[str, str] | None
) -> None:
    platform = str(candidate["platform"])
    proposed = candidate["proposed_trust_entry"]
    assert isinstance(proposed, dict)
    observed = proposed[platform]
    if trusted is None:
        raise ValueError(
            f"generic gate tools are not anchored for {platform}; independently "
            "review the candidate and commit the exact mapping before rerunning"
        )
    if trusted != observed:
        raise ValueError("installed generic gate tools differ from committed anchors")


def capture(args: argparse.Namespace) -> int:
    output = evidence_runtime.assert_no_symlink_ancestry(ROOT, args.output)
    candidate = build_candidate(ROOT, args.release_sha, evidence_root=output.parent)
    evidence_runtime.write_json_atomic(ROOT, output, candidate)
    print(
        json.dumps(
            {
                "candidate": str(output.relative_to(ROOT)),
                "platform": candidate["platform"],
                "status": "unreviewed",
                "tools": sorted(candidate["tools"]),  # type: ignore[arg-type]
            },
            sort_keys=True,
        )
    )
    return 0


def verify(args: argparse.Namespace) -> int:
    path = evidence_runtime.assert_no_symlink_ancestry(ROOT, args.candidate)
    candidate = read_candidate(ROOT, path)
    current = build_candidate(ROOT, args.release_sha, evidence_root=path.parent)
    if candidate != current:
        raise ValueError("gate-tool anchor candidate differs from current release tools")
    try:
        trusted = evidence_runtime.gate_tool_anchors(
            ROOT, str(candidate["release_sha"])
        )
    except ValueError as error:
        if "not anchored" not in str(error):
            raise
        trusted = None
    require_trusted_mapping(candidate, trusted)
    print(
        "PASS generic evidence-gate tools match the separately reviewed "
        f"committed anchors for {candidate['platform']}"
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
        print(f"BLOCKED generic gate-tool trust: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
