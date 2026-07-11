#!/usr/bin/env python3
"""Validate the public MCP server-card used by MCP directories."""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[2]
CARD = ROOT / "deploy" / "server-card.json"
CARGO_TOML = ROOT / "Cargo.toml"

EXPECTED_TOOLS = {"get_capabilities"}

FORBIDDEN_PUBLIC_TEMPLATE_MARKERS = {
    "range_proof",
    "zkml_matmul",
    "spartan_r1cs",
    "hash_preimage",
    "policy_compliance",
    "data_integrity",
}


def workspace_version() -> str:
    data = tomllib.loads(CARGO_TOML.read_text(encoding="utf-8"))
    return str(data["workspace"]["package"]["version"])


def load_card(path: pathlib.Path = CARD) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("server-card root must be a JSON object")
    return data


def tool_names(card: dict[str, object]) -> set[str]:
    tools = card.get("tools")
    if not isinstance(tools, list):
        return set()
    names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    return {name for name in names if isinstance(name, str)}


def validate_card(card: dict[str, object]) -> list[str]:
    failures: list[str] = []
    server_info = card.get("serverInfo") if isinstance(card.get("serverInfo"), dict) else {}
    metadata = card.get("metadata") if isinstance(card.get("metadata"), dict) else {}
    auth = card.get("authentication") if isinstance(card.get("authentication"), dict) else {}
    config_schema = card.get("configSchema") if isinstance(card.get("configSchema"), dict) else {}

    if server_info.get("name") != "tinyzkp":
        failures.append("serverInfo.name must be 'tinyzkp'")
    if server_info.get("version") != workspace_version():
        failures.append(
            f"serverInfo.version must match workspace version {workspace_version()!r}; "
            f"got {server_info.get('version')!r}"
        )

    actual_tools = tool_names(card)
    if actual_tools != EXPECTED_TOOLS:
        failures.append(
            "tools must match current public MCP tool set; "
            f"missing={sorted(EXPECTED_TOOLS - actual_tools)} extra={sorted(actual_tools - EXPECTED_TOOLS)}"
        )

    description = str(metadata.get("description", ""))
    if metadata.get("service_status") != "backend_recovery":
        failures.append("metadata.service_status must be backend_recovery")
    for unavailable_claim in (
        "Hosted proving",
        "hosted verification",
        "account creation",
        "public checkout",
    ):
        if unavailable_claim.lower() not in description.lower():
            failures.append(f"metadata.description must disclose unavailable {unavailable_claim}")
    if metadata.get("homepage") != "https://tinyzkp.com":
        failures.append("metadata.homepage must be https://tinyzkp.com")
    if metadata.get("documentation") != "https://tinyzkp.com/docs":
        failures.append("metadata.documentation must be https://tinyzkp.com/docs")
    if metadata.get("repository") != "https://github.com/logannye/hc-stark":
        failures.append("metadata.repository must point to hc-stark")

    if auth.get("required") is not False:
        failures.append("authentication.required must be false for the public MCP lane")
    if auth.get("schemes") != []:
        failures.append("authentication.schemes must be empty during recovery")

    properties = config_schema.get("properties") if isinstance(config_schema.get("properties"), dict) else {}
    if properties:
        failures.append("configSchema.properties must be empty during recovery")

    availability = card.get("availability") if isinstance(card.get("availability"), dict) else {}
    for field in ("proving", "verification", "accounts", "checkout"):
        if availability.get(field) is not False:
            failures.append(f"availability.{field} must be false")

    serialized = json.dumps(card).lower()
    leaked = sorted(marker for marker in FORBIDDEN_PUBLIC_TEMPLATE_MARKERS if marker in serialized)
    if leaked:
        failures.append(f"server-card must not advertise gated/non-live templates: {', '.join(leaked)}")

    return failures


def main() -> int:
    failures = validate_card(load_card())
    if failures:
        print("MCP server-card check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"PASS MCP server-card check ({len(EXPECTED_TOOLS)} tools)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
