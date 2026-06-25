#!/usr/bin/env python3
"""Validate the Cursor/Open Plugins package used for MCP distribution."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = ROOT / "plugins" / "tinyzkp-cursor"
MANIFESTS = [
    Path(".plugin/plugin.json"),
    Path(".cursor-plugin/plugin.json"),
]
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
FORBIDDEN_PATH_RE = re.compile(r"(^|/)\.\.(/|$)")
TRACKED_SOURCE = "source=cursor_directory"
HOSTED_MCP_URL = "https://mcp.tinyzkp.com/mcp"


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def _pass(name: str, detail: str) -> Check:
    return Check("PASS", name, detail)


def _fail(name: str, detail: str) -> Check:
    return Check("FAIL", name, detail)


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return None, str(exc)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"
    if not isinstance(data, dict):
        return None, "JSON root must be an object"
    return data, None


def validate_manifest(root: Path, rel_path: Path) -> list[Check]:
    path = root / "plugins" / "tinyzkp-cursor" / rel_path
    manifest, error = load_json(path)
    if error:
        return [_fail(str(rel_path), error)]
    assert manifest is not None

    failures: list[str] = []
    name = manifest.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        failures.append("name must follow Open Plugins lowercase name constraints")
    elif "--" in name or ".." in name:
        failures.append("name must not contain consecutive hyphens or periods")
    if not isinstance(manifest.get("version"), str) or not SEMVER_RE.match(str(manifest.get("version"))):
        failures.append("version must be semantic version x.y.z")
    for field in ("description", "homepage", "repository", "license"):
        value = manifest.get(field)
        if not isinstance(value, str) or not value:
            failures.append(f"{field} must be a non-empty string")
    if TRACKED_SOURCE not in str(manifest.get("homepage", "")):
        failures.append("homepage must preserve cursor_directory attribution")
    if manifest.get("mcpServers") != "./.mcp.json":
        failures.append('mcpServers must point at "./.mcp.json"')
    if manifest.get("rules") != "./rules/":
        failures.append('rules must point at "./rules/"')
    for field in ("mcpServers", "rules"):
        value = str(manifest.get(field) or "")
        if value and (not value.startswith("./") or FORBIDDEN_PATH_RE.search(value)):
            failures.append(f"{field} must be a safe plugin-root-relative path")
    keywords = manifest.get("keywords")
    required_keywords = {"tinyzkp", "mcp", "cursor", "proof-receipts", "stark"}
    if not isinstance(keywords, list) or not required_keywords.issubset({str(item) for item in keywords}):
        failures.append("keywords must include TinyZKP, MCP, Cursor, proof receipts, and STARK markers")

    if failures:
        return [_fail(str(rel_path), "; ".join(failures))]
    return [_pass(str(rel_path), "manifest is valid and source-tagged")]


def validate_manifest_pair(root: Path) -> list[Check]:
    neutral, neutral_error = load_json(root / "plugins" / "tinyzkp-cursor" / MANIFESTS[0])
    cursor, cursor_error = load_json(root / "plugins" / "tinyzkp-cursor" / MANIFESTS[1])
    if neutral_error or cursor_error:
        return []
    assert neutral is not None and cursor is not None
    if neutral != cursor:
        return [_fail("manifest parity", "vendor-neutral and Cursor manifests must stay identical")]
    return [_pass("manifest parity", "vendor-neutral and Cursor manifests match")]


def validate_mcp_config(root: Path) -> list[Check]:
    rel_path = Path("plugins/tinyzkp-cursor/.mcp.json")
    data, error = load_json(root / rel_path)
    if error:
        return [_fail(str(rel_path), error)]
    assert data is not None
    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or "tinyzkp" not in servers:
        return [_fail(str(rel_path), "mcpServers.tinyzkp is required")]
    server = servers.get("tinyzkp")
    if not isinstance(server, dict):
        return [_fail(str(rel_path), "mcpServers.tinyzkp must be an object")]

    failures: list[str] = []
    if server.get("command") != "npx":
        failures.append('command must be "npx" for Open Plugins command-based MCP compatibility')
    args = server.get("args")
    if not isinstance(args, list):
        failures.append("args must be a list")
    else:
        arg_values = [str(arg) for arg in args]
        for marker in ("-y", "mcp-remote", HOSTED_MCP_URL):
            if marker not in arg_values:
                failures.append(f"args must include {marker}")
    if failures:
        return [_fail(str(rel_path), "; ".join(failures))]
    return [_pass(str(rel_path), "MCP config routes Cursor to hosted TinyZKP")]


def validate_text_assets(root: Path) -> list[Check]:
    checks: list[Check] = []
    required = {
        Path("plugins/tinyzkp-cursor/README.md"): [
            TRACKED_SOURCE,
            HOSTED_MCP_URL,
            "Default receipts are transparent",
            "Do not put secrets",
            "prove_template",
            "verify_proof",
        ],
        Path("plugins/tinyzkp-cursor/rules/tinyzkp-proof-receipts.mdc"): [
            TRACKED_SOURCE,
            "prove_template",
            "verify_proof",
            "Never put secrets",
            "high-value",
        ],
        Path("plugins/tinyzkp-cursor/CHANGELOG.md"): [
            "0.1.0",
            "Cursor/Open Plugins",
        ],
    }
    for rel_path, markers in required.items():
        path = root / rel_path
        if not path.is_file():
            checks.append(_fail(str(rel_path), "missing file"))
            continue
        text = path.read_text(encoding="utf-8")
        missing = [marker for marker in markers if marker not in text]
        if missing:
            checks.append(_fail(str(rel_path), "missing markers: " + ", ".join(missing)))
        else:
            checks.append(_pass(str(rel_path), "asset is source-tagged and current"))
    return checks


def validate_distribution_target(root: Path) -> list[Check]:
    rel_path = Path("marketing/mcp_distribution_targets.json")
    data, error = load_json(root / rel_path)
    if error:
        return [_fail(str(rel_path), error)]
    assert data is not None
    targets = data.get("targets")
    if not isinstance(targets, list):
        return [_fail(str(rel_path), "targets must be a list")]
    target = next((item for item in targets if isinstance(item, dict) and item.get("id") == "cursor_directory"), None)
    if not isinstance(target, dict):
        return [_fail(str(rel_path), "cursor_directory target is required")]
    failures: list[str] = []
    expected = {
        "name": "Cursor Directory",
        "status": "submission_ready",
        "source": "cursor_directory",
        "platform": "cursor",
        "submission_url": "https://cursor.directory/plugins/new",
    }
    for field, value in expected.items():
        if target.get(field) != value:
            failures.append(f"{field} must be {value!r}")
    signup_url = str(target.get("signup_url") or "")
    for marker in (TRACKED_SOURCE, "medium=mcp_directory", "platform=cursor", "intent=mcp_install"):
        if marker not in signup_url:
            failures.append(f"signup_url missing {marker}")
    notes = str(target.get("notes") or "")
    for marker in ("plugins/tinyzkp-cursor", "Open Plugins", "cursor.directory"):
        if marker not in notes:
            failures.append(f"notes missing {marker}")
    if failures:
        return [_fail(str(rel_path), "; ".join(failures))]
    return [_pass(str(rel_path), "Cursor Directory target is submission-ready")]


def validate(root: Path = ROOT) -> list[Check]:
    checks: list[Check] = []
    if not PLUGIN_DIR.is_dir():
        return [_fail("plugins/tinyzkp-cursor", "missing plugin directory")]
    for manifest in MANIFESTS:
        checks.extend(validate_manifest(root, manifest))
    checks.extend(validate_manifest_pair(root))
    checks.extend(validate_mcp_config(root))
    checks.extend(validate_text_assets(root))
    checks.extend(validate_distribution_target(root))
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} Cursor plugin check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll Cursor plugin checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
