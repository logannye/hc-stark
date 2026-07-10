#!/usr/bin/env python3
"""Verify live TinyZKP surfaces expose the expected release identity."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin

import site_asset_manifest

MONITOR_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "TinyZKP-Release-Check/1.0 (+https://tinyzkp.com)",
}


@dataclass(frozen=True)
class ReleaseSurface:
    name: str
    url: str
    expected_service: str


def fetch_json(url: str, timeout: int) -> dict[str, object]:
    req = urllib.request.Request(url, headers=MONITOR_HEADERS)
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


def check_surfaces(
    surfaces: list[ReleaseSurface],
    expected_sha: str,
    timeout: int,
    expected_site_asset_sha256: str | None = None,
) -> list[str]:
    failures: list[str] = []
    versions: dict[str, str] = {}
    for surface in surfaces:
        try:
            payload = fetch_json(surface.url, timeout)
        except RuntimeError as exc:
            failures.append(str(exc))
            continue
        failures.extend(validate_payload(surface, payload, expected_sha))
        if surface.expected_service == "site" and expected_site_asset_sha256 is not None:
            if payload.get("asset_manifest_complete") is not True:
                failures.append("site asset manifest is incomplete")
            if payload.get("asset_manifest_sha256") != expected_site_asset_sha256:
                failures.append(
                    "site asset manifest digest must be "
                    f"{expected_site_asset_sha256!r}; got {payload.get('asset_manifest_sha256')!r}"
                )
        package_version = payload.get("package_version")
        if isinstance(package_version, str) and package_version:
            versions[surface.name] = package_version
    if len(set(versions.values())) > 1:
        failures.append(
            "release package versions disagree: "
            + ", ".join(f"{name}={version}" for name, version in sorted(versions.items()))
        )
    return failures


def release_surfaces(site_url: str, api_url: str, mcp_url: str) -> list[ReleaseSurface]:
    return [
        ReleaseSurface("site", urljoin(site_url.rstrip("/") + "/", "api/release"), "site"),
        ReleaseSurface("api", urljoin(api_url.rstrip("/") + "/", "version"), "api"),
        ReleaseSurface("mcp", urljoin(mcp_url.rstrip("/") + "/", "version"), "mcp"),
    ]


def validate_artifact(path: Path, expected_sha: str, expected_service: str) -> list[str]:
    try:
        if path.stat().st_size > 1024 * 1024:
            return [f"{path} exceeds the 1 MiB release artifact limit"]
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"{path} is not a readable JSON release artifact: {exc}"]
    if not isinstance(payload, dict):
        return [f"{path} must contain a JSON object"]
    if expected_service == "benchmark":
        failures = []
        if payload.get("release_sha") != expected_sha:
            failures.append(f"benchmark release_sha must be {expected_sha!r}; got {payload.get('release_sha')!r}")
        if payload.get("dependency_profile") != "tinyzkp-p3-goldilocks-v1":
            failures.append("benchmark dependency_profile mismatch")
        if payload.get("verification_succeeded") is not True:
            failures.append("benchmark did not record successful verification")
        return failures
    return validate_payload(
        ReleaseSurface(expected_service, str(path), expected_service), payload, expected_sha
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True, help="Git commit SHA expected on all release surfaces")
    parser.add_argument("--site-url", default="https://tinyzkp.com", help="TinyZKP website origin")
    parser.add_argument("--api-url", default="https://api.tinyzkp.com", help="TinyZKP API origin")
    parser.add_argument("--mcp-url", default="https://mcp.tinyzkp.com", help="TinyZKP MCP HTTP origin")
    parser.add_argument("--timeout", type=int, default=20, help="Per-request timeout in seconds")
    parser.add_argument("--cli-release-file", type=Path, help="Optional JSON emitted by `hc-cli release`")
    parser.add_argument("--benchmark-report", type=Path, help="Optional BenchmarkReportV1 to bind to the same release")
    args = parser.parse_args(argv)

    expected_sha = args.expected_sha.strip()
    if not expected_sha:
        print("FAIL  --expected-sha must not be blank", file=sys.stderr)
        return 1

    failures = check_surfaces(
        release_surfaces(args.site_url, args.api_url, args.mcp_url),
        expected_sha,
        args.timeout,
        str(site_asset_manifest.build(site_asset_manifest.ROOT / "site")["sha256"]),
    )
    if args.cli_release_file:
        failures.extend(validate_artifact(args.cli_release_file, expected_sha, "cli"))
    if args.benchmark_report:
        failures.extend(validate_artifact(args.benchmark_report, expected_sha, "benchmark"))
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1

    print(f"PASS  live release identity matches {expected_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
