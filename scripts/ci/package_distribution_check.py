#!/usr/bin/env python3
"""Validate package-registry distribution surfaces.

Registry READMEs and package metadata are acquisition surfaces. This check
guards the source-tagged links and transparent-receipt caveats that let TinyZKP
attribute PyPI, npm, crates.io, and MCP install traffic.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


@dataclass(frozen=True)
class Surface:
    name: str
    file: Path
    source: str
    medium: str
    platform: str
    signup_intent: str
    transparent_marker: str = "Default receipts are transparent"


SURFACES = [
    Surface("Python SDK README", Path("clients/python/README.md"), "pypi_tinyzkp", "package_registry", "pypi", "api_key"),
    Surface("TypeScript SDK README", Path("clients/typescript/README.md"), "npm_tinyzkp", "package_registry", "npm", "api_key"),
    Surface("CLI README", Path("clients/cli/README.md"), "npm_cli", "package_registry", "npm", "cli_install"),
    Surface("Rust SDK README", Path("clients/rust/README.md"), "crates_tinyzkp", "package_registry", "crates_io", "api_key"),
    Surface("WASM verifier README", Path("crates/hc-wasm/pkg/README.md"), "npm_wasm_verifier", "package_registry", "npm", "api_key"),
    Surface("MCP README", Path("crates/hc-mcp/README.md"), "github_mcp_readme", "github", "mcp_readme", "mcp_install"),
]

METADATA_MARKERS = {
    Path("clients/python/pyproject.toml"): [
        "source=pypi_tinyzkp",
        "intent=api_key",
        "intent=verify_receipt",
        "intent=limits",
    ],
    Path("clients/typescript/package.json"): [
        "source=npm_tinyzkp",
        "medium=package_registry",
        "platform=npm",
    ],
    Path("clients/cli/package.json"): [
        "source=npm_cli",
        "medium=package_registry",
        "platform=npm",
    ],
    Path("clients/rust/Cargo.toml"): [
        'readme = "README.md"',
        "source=crates_tinyzkp",
        "platform=crates_io",
    ],
    Path("crates/hc-wasm/pkg/package.json"): [
        '"README.md"',
        "source=npm_wasm_verifier",
        "platform=npm",
    ],
}


def _read(root: Path, file: Path) -> tuple[str | None, str | None]:
    path = root / file
    try:
        return path.read_text(encoding="utf-8"), None
    except OSError as exc:
        return None, str(exc)


def _url(source: str, medium: str, platform: str, path: str, intent: str) -> str:
    return f"https://tinyzkp.com{path}?source={source}&medium={medium}&platform={platform}&intent={intent}"


def validate_surface(root: Path, surface: Surface) -> list[Check]:
    text, error = _read(root, surface.file)
    if error:
        return [Check("FAIL", surface.name, f"{surface.file} is missing or unreadable: {error}")]

    assert text is not None
    required_urls = [
        ("signup", _url(surface.source, surface.medium, surface.platform, "/signup", surface.signup_intent)),
        ("verify", _url(surface.source, surface.medium, surface.platform, "/verify", "verify_receipt")),
        ("limits", _url(surface.source, surface.medium, surface.platform, "/limits", "limits")),
        (
            "agent offers",
            _url(surface.source, surface.medium, surface.platform, "/.well-known/tinyzkp-offers.json", "agent_offer"),
        ),
    ]

    failures = [
        Check("FAIL", surface.name, f"missing {label} URL: {url}")
        for label, url in required_urls
        if url not in text
    ]
    if surface.transparent_marker and surface.transparent_marker not in text:
        failures.append(Check("FAIL", surface.name, f"missing transparent receipt caveat: {surface.transparent_marker}"))

    if failures:
        return failures
    return [Check("PASS", surface.name, f"{surface.file} has source-tagged conversion links")]


def validate_metadata(root: Path) -> list[Check]:
    checks: list[Check] = []
    for file, markers in METADATA_MARKERS.items():
        text, error = _read(root, file)
        if error:
            checks.append(Check("FAIL", str(file), f"{file} is missing or unreadable: {error}"))
            continue

        assert text is not None
        missing = [marker for marker in markers if marker not in text]
        if missing:
            checks.append(Check("FAIL", str(file), f"missing metadata markers: {', '.join(missing)}"))
        else:
            checks.append(Check("PASS", str(file), "registry metadata preserves attribution markers"))
    return checks


def validate(root: Path = ROOT) -> list[Check]:
    checks: list[Check] = []
    for surface in SURFACES:
        checks.extend(validate_surface(root, surface))
    checks.extend(validate_metadata(root))
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]

    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")

    if failures:
        print(f"\n{len(failures)} package distribution check(s) failed.", file=sys.stderr)
        return 1

    print("\nAll package distribution checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
