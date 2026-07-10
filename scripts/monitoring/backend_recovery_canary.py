#!/usr/bin/env python3
"""Verify that every live TinyZKP surface remains safely in backend recovery."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin


HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "TinyZKP-Recovery-Canary/1.0 (+https://tinyzkp.com/status)",
}


@dataclass(frozen=True)
class Observation:
    name: str
    status: int
    body: bytes


def request(name: str, url: str, *, method: str = "GET", body: bytes | None = None, timeout: int = 20) -> Observation:
    req = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return Observation(name, response.status, response.read(1024 * 1024))
    except urllib.error.HTTPError as exc:
        return Observation(name, exc.code, exc.read(1024 * 1024))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{name} request failed: {exc.reason}") from exc


def json_object(observation: Observation) -> dict[str, object]:
    try:
        value = json.loads(observation.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{observation.name} did not return JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{observation.name} returned non-object JSON")
    return value


def validate(site_url: str, api_url: str, mcp_url: str, timeout: int) -> list[str]:
    failures: list[str] = []
    checks = [
        request("capabilities", urljoin(api_url.rstrip("/") + "/", "v1/capabilities"), timeout=timeout),
        request("prove", urljoin(api_url.rstrip("/") + "/", "prove"), method="POST", body=b"{}", timeout=timeout),
        request(
            "legacy verify",
            urljoin(api_url.rstrip("/") + "/", "verify"),
            method="POST",
            body=b'{"proof":{"version":7}}',
            timeout=timeout,
        ),
        request(
            "checkout",
            urljoin(site_url.rstrip("/") + "/", "api/create-checkout"),
            method="POST",
            body=b"{}",
            timeout=timeout,
        ),
        request("homepage", site_url.rstrip("/") + "/", timeout=timeout),
        request("status", urljoin(site_url.rstrip("/") + "/", "status"), timeout=timeout),
        request("mcp version", urljoin(mcp_url.rstrip("/") + "/", "version"), timeout=timeout),
    ]

    by_name = {check.name: check for check in checks}
    capabilities = json_object(by_name["capabilities"])
    if by_name["capabilities"].status != 200:
        failures.append(f"capabilities returned HTTP {by_name['capabilities'].status}")
    for field in ("proving_available", "verification_available", "checkout_enabled", "account_creation_enabled"):
        if capabilities.get(field) is not False:
            failures.append(f"capabilities {field} must be false")
    if capabilities.get("service_status") != "backend_recovery":
        failures.append("capabilities service_status must be backend_recovery")

    expected = {
        "prove": (503, "protocol_upgrade"),
        "legacy verify": (422, "legacy_statement_unbound"),
        "checkout": (503, "protocol_upgrade"),
    }
    for name, (status, code) in expected.items():
        observation = by_name[name]
        if observation.status != status:
            failures.append(f"{name} returned HTTP {observation.status}; expected {status}")
            continue
        if json_object(observation).get("code") != code:
            failures.append(f"{name} did not return {code}")

    forbidden_claims = ("v5", "private zero knowledge", "full-prover O(√N)", "100M-row", "self-serve pricing")
    for name in ("homepage", "status"):
        observation = by_name[name]
        text = observation.body.decode("utf-8", errors="replace").lower()
        if observation.status != 200:
            failures.append(f"{name} returned HTTP {observation.status}")
        if "backend recovery" not in text and "backend upgrade" not in text:
            failures.append(f"{name} does not disclose backend recovery")
        for claim in forbidden_claims:
            if claim.lower() in text:
                failures.append(f"{name} contains forbidden claim {claim!r}")

    mcp_version = json_object(by_name["mcp version"])
    if by_name["mcp version"].status != 200 or mcp_version.get("service") != "mcp":
        failures.append("MCP version endpoint is unavailable or malformed")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-url", default="https://tinyzkp.com")
    parser.add_argument("--api-url", default="https://api.tinyzkp.com")
    parser.add_argument("--mcp-url", default="https://mcp.tinyzkp.com")
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args(argv)
    try:
        failures = validate(args.site_url, args.api_url, args.mcp_url, args.timeout)
    except RuntimeError as exc:
        failures = [str(exc)]
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1
    print("PASS  live TinyZKP surfaces are consistently in backend recovery")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
