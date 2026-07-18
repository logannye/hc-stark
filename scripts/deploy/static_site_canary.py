#!/usr/bin/env python3
"""Verify one exact TinyZKP Pages deployment using static surfaces only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse


ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
MAX_BODY = 4 * 1024 * 1024
CONTRACTS = ("release.json", "commerce.json", "pricing.json", "discovery.json")
PUBLIC_ROUTES = (
    "/",
    "/guard",
    "/compatibility",
    "/benchmarks",
    "/doctor",
    "/pricing",
    "/docs",
    "/troubleshooting",
    "/security",
    "/releases",
    "/support",
    "/plonky3-out-of-memory",
    "/resumable-plonky3-prover",
    "/ssd-backed-plonky3-proving",
)
RETIRED_ROUTES = (
    "/api/release",
    "/api/create-checkout",
    "/mcp",
    "/receipts",
    "/signup",
)
RETIRED_HOSTS = (
    "api.tinyzkp.com",
    "mcp.tinyzkp.com",
    "webhook.tinyzkp.com",
)


class CanaryError(ValueError):
    pass


def safe_base_url(value: str) -> str:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not (
            host == "tinyzkp.com"
            or host == "www.tinyzkp.com"
            or host == "tinyzkp.pages.dev"
            or host.endswith(".tinyzkp.pages.dev")
        )
    ):
        raise CanaryError("base URL is outside the TinyZKP Pages boundary")
    return value.rstrip("/") + "/"


def request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    opener=urllib.request.urlopen,
) -> tuple[int, dict[str, str], bytes]:
    url = urljoin(base_url, path.lstrip("/"))
    body = b"{}" if method == "POST" else None
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
            "Content-Type": "application/json",
            "User-Agent": "TinyZKP-Static-Pages-Canary/1",
        },
    )
    try:
        with opener(req, timeout=20) as response:
            raw = response.read(MAX_BODY + 1)
            status = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as error:
        raw = error.read(MAX_BODY + 1)
        status = error.code
        headers = {key.lower(): value for key, value in error.headers.items()}
    except (OSError, urllib.error.URLError) as error:
        raise CanaryError(f"request failed for {path}") from error
    if len(raw) > MAX_BODY:
        raise CanaryError(f"response is oversized for {path}")
    return status, headers, raw


def check_contracts(base_url: str, site: Path = SITE, *, opener=urllib.request.urlopen) -> None:
    parsed: dict[str, dict] = {}
    for name in CONTRACTS:
        status, headers, raw = request(base_url, "/" + name, opener=opener)
        if status != 200:
            raise CanaryError(f"/{name} returned HTTP {status}")
        expected = (site / name).read_bytes()
        if raw != expected:
            raise CanaryError(f"/{name} differs from the reviewed static source")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise CanaryError(f"/{name} is not JSON") from error
        if not isinstance(value, dict):
            raise CanaryError(f"/{name} must be a JSON object")
        parsed[name] = value
        if "application/json" not in headers.get("content-type", ""):
            raise CanaryError(f"/{name} has the wrong content type")

    release = parsed["release.json"]
    commerce = parsed["commerce.json"]
    pricing = parsed["pricing.json"]
    discovery = parsed["discovery.json"]
    states = {
        (
            item.get("launch_state"),
            item.get("sales_state"),
            item.get("commerce_state"),
            item.get("portal_state"),
        )
        for item in (release, commerce, pricing, discovery)
    }
    if len(states) != 1:
        raise CanaryError("generated public state contracts disagree")
    enabled = [
        release.get("checkout_enabled"),
        commerce.get("checkout_enabled"),
        pricing.get("checkout_enabled"),
        discovery.get("availability", {}).get("guard_checkout"),
    ]
    if len(set(enabled)) != 1:
        raise CanaryError("generated checkout states disagree")
    if enabled[0] is not True:
        for variant in commerce.get("variants", {}).values():
            if variant.get("checkout_url") is not None or variant.get("reviewed") is not False:
                raise CanaryError("closed commerce exposes a checkout URL")


def check_routes(base_url: str, *, opener=urllib.request.urlopen) -> None:
    preview = urlparse(base_url).hostname.endswith(".pages.dev")
    for path in PUBLIC_ROUTES:
        status, headers, _raw = request(base_url, path, opener=opener)
        if status != 200:
            raise CanaryError(f"{path} returned HTTP {status}")
        if headers.get("x-content-type-options") != "nosniff":
            raise CanaryError(f"{path} omits static security headers")
        if preview and headers.get("x-robots-tag") != "noindex, nofollow":
            raise CanaryError(f"{path} preview is indexable")
    for path in RETIRED_ROUTES:
        for method in ("GET", "POST"):
            status, headers, _raw = request(
                base_url, path, method=method, opener=opener
            )
            if status != 410:
                raise CanaryError(f"{method} {path} returned HTTP {status}, not 410")
            if headers.get("x-robots-tag") != "noindex, nofollow":
                raise CanaryError(f"{path} retirement response is indexable")


def check_retired_hosts(*, opener=urllib.request.urlopen) -> None:
    for hostname in RETIRED_HOSTS:
        for method in ("GET", "POST"):
            status, headers, _raw = request(
                f"https://{hostname}/",
                "/retirement-canary",
                method=method,
                opener=opener,
            )
            if status != 410:
                raise CanaryError(
                    f"{method} https://{hostname}/ returned HTTP {status}, not 410"
                )
            if headers.get("x-robots-tag") != "noindex, nofollow":
                raise CanaryError(f"{hostname} retirement response is indexable")
            if "location" in headers:
                raise CanaryError(f"{hostname} redirects instead of returning 410")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url")
    parser.add_argument(
        "--mode",
        choices=("contracts", "routes", "retired-hosts"),
        required=True,
    )
    args = parser.parse_args(argv)
    try:
        if args.mode == "retired-hosts":
            if args.base_url is not None:
                raise CanaryError("--base-url is not used for retired-hosts mode")
            check_retired_hosts()
        elif args.base_url is None:
            raise CanaryError("--base-url is required for contracts and routes modes")
        else:
            base = safe_base_url(args.base_url)
            if args.mode == "contracts":
                check_contracts(base)
            else:
                check_routes(base)
    except CanaryError as error:
        print(f"static Pages canary: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS static Pages {args.mode} canary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
