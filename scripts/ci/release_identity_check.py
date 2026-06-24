#!/usr/bin/env python3
"""Verify live TinyZKP surfaces expose the expected release identity."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin


@dataclass(frozen=True)
class ReleaseSurface:
    name: str
    url: str
    expected_service: str


def fetch_json(url: str, timeout: int) -> dict[str, object]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise RuntimeError(f"{url} returned HTTP {resp.status}")
            raw = resp.read(128 * 1024)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{url} returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{url} request failed: {exc.reason}") from exc

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{url} did not return JSON") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{url} returned non-object JSON")
    return data


def validate_payload(surface: ReleaseSurface, payload: dict[str, object], expected_sha: str) -> list[str]:
    failures: list[str] = []
    service = payload.get("service")
    release_sha = payload.get("release_sha")
    if service != surface.expected_service:
        failures.append(f"{surface.name} service must be {surface.expected_service!r}; got {service!r}")
    if release_sha != expected_sha:
        failures.append(f"{surface.name} release_sha must be {expected_sha!r}; got {release_sha!r}")
    if not isinstance(payload.get("package_version"), str) or not payload.get("package_version"):
        failures.append(f"{surface.name} package_version is missing")
    return failures


def check_surfaces(surfaces: list[ReleaseSurface], expected_sha: str, timeout: int) -> list[str]:
    failures: list[str] = []
    for surface in surfaces:
        try:
            payload = fetch_json(surface.url, timeout)
        except RuntimeError as exc:
            failures.append(str(exc))
            continue
        failures.extend(validate_payload(surface, payload, expected_sha))
    return failures


def release_surfaces(site_url: str, api_url: str, mcp_url: str) -> list[ReleaseSurface]:
    return [
        ReleaseSurface("site", urljoin(site_url.rstrip("/") + "/", "api/release"), "site"),
        ReleaseSurface("api", urljoin(api_url.rstrip("/") + "/", "version"), "api"),
        ReleaseSurface("mcp", urljoin(mcp_url.rstrip("/") + "/", "version"), "mcp"),
    ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True, help="Git commit SHA expected on all release surfaces")
    parser.add_argument("--site-url", default="https://tinyzkp.com", help="TinyZKP website origin")
    parser.add_argument("--api-url", default="https://api.tinyzkp.com", help="TinyZKP API origin")
    parser.add_argument("--mcp-url", default="https://mcp.tinyzkp.com", help="TinyZKP MCP HTTP origin")
    parser.add_argument("--timeout", type=int, default=20, help="Per-request timeout in seconds")
    args = parser.parse_args(argv)

    expected_sha = args.expected_sha.strip()
    if not expected_sha:
        print("FAIL  --expected-sha must not be blank", file=sys.stderr)
        return 1

    failures = check_surfaces(
        release_surfaces(args.site_url, args.api_url, args.mcp_url),
        expected_sha,
        args.timeout,
    )
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1

    print(f"PASS  live release identity matches {expected_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
