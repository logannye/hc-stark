#!/usr/bin/env python3
"""Reject mutable GitHub Action references in every workflow."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
import strict_json


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
USE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
REMOTE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
ACTION_ALLOWLIST = {
    "actions/attest": "f6bf1532d7d6793fce74eac584813a8eee607999",
    "actions/cache": "0057852bfaa89a56745cba8c7296529d2fc39830",
    "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "anchore/sbom-action": "e22c389904149dbc22b58101806040fa8d37a610",
    "cloudflare/wrangler-action": "9acf94ace14e7dc412b076f2c5c20b8ce93c79cd",
    "docker/setup-buildx-action": "bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
    "dtolnay/rust-toolchain": "4be7066ada62dd38de10e7b70166bc74ed198c30",
    "sigstore/cosign-installer": "f713795cb21599bc4e5c4b58cbad1da852d7eeb9",
    "softprops/action-gh-release": "3bb12739c298aeb8a4eeaf626c5b8d85266b0e65",
    "Swatinem/rust-cache": "42dc69e1aa15d09112580998cf2ef0119e2e91ae",
}


def failures(directory: Path) -> list[str]:
    problems: list[str] = []
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USE.match(line)
            if match is None:
                continue
            reference = match.group(1)
            # Local actions are immutable with the checked-out release source.
            if reference.startswith("./"):
                continue
            if REMOTE.fullmatch(reference) is None:
                problems.append(
                    f"{path.relative_to(directory.parent.parent)}:{number}: "
                    f"action is not pinned to a full commit: {reference}"
                )
                continue
            repository, revision = reference.rsplit("@", 1)
            if ACTION_ALLOWLIST.get(repository) != revision:
                problems.append(
                    f"{path.relative_to(directory.parent.parent)}:{number}: "
                    f"action commit is not in the reviewed allowlist: {reference}"
                )
    trust_path = directory.parent.parent / "release" / "release-trust-v1.json"
    try:
        trust = strict_json.loads(trust_path.read_bytes())
        installer = trust["cosign"]["installer_action_sha"]
        version = trust["cosign"]["version"]
    except (OSError, KeyError, TypeError, ValueError) as error:
        problems.append(f"release trust cannot anchor cosign workflows: {error}")
        return problems
    if installer != ACTION_ALLOWLIST["sigstore/cosign-installer"]:
        problems.append("cosign installer trust anchor differs from the action allowlist")
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines):
            if "uses: sigstore/cosign-installer@" not in line:
                continue
            window = "\n".join(lines[number + 1 : number + 5])
            if f"cosign-release: {version}" not in window:
                problems.append(
                    f"{path.relative_to(directory.parent.parent)}:{number + 1}: "
                    "cosign release does not match the committed trust anchor"
                )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflows", type=Path, default=WORKFLOWS)
    args = parser.parse_args(argv)
    problems = failures(args.workflows)
    for problem in problems:
        print(f"FAIL  {problem}", file=sys.stderr)
    if problems:
        return 1
    print("PASS  all GitHub Actions are pinned to full commit SHAs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
