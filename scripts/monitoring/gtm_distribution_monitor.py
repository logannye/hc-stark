#!/usr/bin/env python3
"""Check TinyZKP GTM distribution surfaces.

Default mode performs live HTTP checks for canonical assets and active directory
listings. Use --offline in CI to validate only the checked-in target catalog and
source-tagged CTA shape.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGETS = ROOT / "marketing" / "mcp_distribution_targets.json"
SOURCE_RE = re.compile(r"^[a-z0-9_]+$")
ACTIVE_STATUSES = {"active"}


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str = ""


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("target catalog must be a JSON object")
    return data


def _fail(name: str, detail: str) -> Check:
    return Check("FAIL", name, detail)


def _pass(name: str, detail: str = "") -> Check:
    return Check("PASS", name, detail)


def _skip(name: str, detail: str) -> Check:
    return Check("SKIP", name, detail)


def _url_error(value: object, *, label: str, tinyzkp_only: bool = False) -> str | None:
    if not isinstance(value, str) or not value:
        return f"{label} must be a non-empty URL string"
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        return f"{label} must be an HTTPS URL"
    if tinyzkp_only and parsed.netloc != "tinyzkp.com":
        return f"{label} must use tinyzkp.com"
    return None


def _validate_signup_url(target: dict[str, Any]) -> list[str]:
    label = f"target {target.get('id', '<missing>')} signup_url"
    url = target.get("signup_url")
    error = _url_error(url, label=label, tinyzkp_only=True)
    if error:
        return [error]

    parsed = urlparse(str(url))
    failures: list[str] = []
    if parsed.path != "/signup":
        failures.append(f"{label} must point at /signup")
    query = parse_qs(parsed.query)
    expected = {
        "source": target.get("source"),
        "medium": "mcp_directory",
        "platform": target.get("platform"),
        "intent": "mcp_install",
    }
    for key, expected_value in expected.items():
        if not isinstance(expected_value, str) or not expected_value:
            failures.append(f"target {target.get('id', '<missing>')} must define {key}")
        elif query.get(key) != [expected_value]:
            failures.append(f"{label} must include {key}={expected_value}")
    return failures


def validate_config(config: dict[str, Any]) -> list[Check]:
    checks: list[Check] = []
    failures: list[str] = []

    positioning = config.get("positioning")
    if not isinstance(positioning, dict):
        failures.append("positioning must be an object")
    else:
        one_liner = str(positioning.get("one_liner", "")).lower()
        data_boundary = str(positioning.get("data_boundary", "")).lower()
        if "proof receipts" not in one_liner:
            failures.append("positioning.one_liner must mention proof receipts")
        for marker in ("secrets", "private customer data", "api keys"):
            if marker not in data_boundary:
                failures.append(f"positioning.data_boundary must mention {marker!r}")

    canonical_assets = config.get("canonical_assets")
    if not isinstance(canonical_assets, list) or not canonical_assets:
        failures.append("canonical_assets must be a non-empty list")
    else:
        seen_assets: set[str] = set()
        for asset in canonical_assets:
            if not isinstance(asset, dict):
                failures.append("canonical_assets entries must be objects")
                continue
            asset_id = asset.get("id")
            if not isinstance(asset_id, str) or not asset_id:
                failures.append("canonical asset must define id")
            elif asset_id in seen_assets:
                failures.append(f"duplicate canonical asset id: {asset_id}")
            else:
                seen_assets.add(asset_id)
            error = _url_error(asset.get("url"), label=f"canonical asset {asset_id} url")
            if error:
                failures.append(error)
            markers = asset.get("required_markers")
            if not isinstance(markers, list) or not all(isinstance(item, str) and item for item in markers):
                failures.append(f"canonical asset {asset_id} must define required_markers")

    targets = config.get("targets")
    if not isinstance(targets, list) or not targets:
        failures.append("targets must be a non-empty list")
    else:
        seen_ids: set[str] = set()
        seen_sources: set[str] = set()
        active_count = 0
        for target in targets:
            if not isinstance(target, dict):
                failures.append("targets entries must be objects")
                continue
            target_id = target.get("id")
            source = target.get("source")
            if not isinstance(target_id, str) or not target_id:
                failures.append("target must define id")
            elif target_id in seen_ids:
                failures.append(f"duplicate target id: {target_id}")
            else:
                seen_ids.add(target_id)
            if not isinstance(source, str) or not SOURCE_RE.match(source):
                failures.append(f"target {target_id} source must be lowercase snake_case")
            elif source in seen_sources:
                failures.append(f"duplicate target source: {source}")
            else:
                seen_sources.add(source)
            status = target.get("status")
            if not isinstance(status, str) or not status:
                failures.append(f"target {target_id} must define status")
            if status in ACTIVE_STATUSES:
                active_count += 1
                if not target.get("listing_url"):
                    failures.append(f"active target {target_id} must define listing_url")
            if "online_monitoring" in target and not isinstance(target.get("online_monitoring"), bool):
                failures.append(f"target {target_id} online_monitoring must be a boolean when present")
            listing_url = target.get("listing_url")
            if listing_url:
                error = _url_error(listing_url, label=f"target {target_id} listing_url")
                if error:
                    failures.append(error)
            for key in ("name", "kind", "platform", "submission_url", "install_command"):
                if not isinstance(target.get(key), str) or not target.get(key):
                    failures.append(f"target {target_id} must define {key}")
            markers = target.get("required_markers")
            if not isinstance(markers, list) or not all(isinstance(item, str) and item for item in markers):
                failures.append(f"target {target_id} must define required_markers")
            failures.extend(_validate_signup_url(target))
        if active_count < 1:
            failures.append("at least one active MCP distribution target is required")

    if failures:
        checks.extend(_fail("static target catalog", failure) for failure in failures)
    else:
        checks.append(_pass("static target catalog", "source-tagged directory targets are valid"))
    return checks


def fetch_url(url: str, *, timeout: float) -> tuple[int | None, str, str | None]:
    request = Request(url, headers={"User-Agent": "TinyZKP-GTM-Monitor/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            body = response.read(500_000).decode("utf-8", errors="replace")
            return status, body, None
    except HTTPError as exc:
        body = exc.read(4096).decode("utf-8", errors="replace")
        return exc.code, body, str(exc)
    except URLError as exc:
        return None, "", str(exc.reason)
    except OSError as exc:
        return None, "", str(exc)


def _check_url_contains(url: str, markers: list[str], *, name: str, timeout: float) -> Check:
    status, body, error = fetch_url(url, timeout=timeout)
    if status != 200:
        return _fail(name, f"{url} returned {status or 'network error'} ({error or 'no body'})")
    missing = [marker for marker in markers if marker not in body]
    if missing:
        return _fail(name, f"{url} missing markers: {', '.join(missing)}")
    return _pass(name, url)


def run_online_checks(config: dict[str, Any], *, timeout: float) -> list[Check]:
    checks: list[Check] = []
    for asset in config.get("canonical_assets", []):
        if not isinstance(asset, dict):
            continue
        checks.append(
            _check_url_contains(
                str(asset.get("url", "")),
                list(asset.get("required_markers", [])),
                name=f"canonical asset {asset.get('id', '<missing>')}",
                timeout=timeout,
            )
        )

    for target in config.get("targets", []):
        if not isinstance(target, dict):
            continue
        name = f"directory target {target.get('id', '<missing>')}"
        listing_url = str(target.get("listing_url", "") or "")
        if target.get("status") not in ACTIVE_STATUSES:
            checks.append(_skip(name, f"status={target.get('status')}; no live listing required"))
            continue
        if target.get("online_monitoring") is False:
            note = str(target.get("monitoring_note") or "online monitoring disabled")
            checks.append(_skip(name, f"status=active; {note}"))
            continue
        if not listing_url:
            checks.append(_fail(name, "active target has no listing_url"))
            continue
        checks.append(
            _check_url_contains(
                listing_url,
                list(target.get("required_markers", [])),
                name=name,
                timeout=timeout,
            )
        )
    return checks


def print_checks(checks: list[Check]) -> None:
    for check in checks:
        suffix = f" - {check.detail}" if check.detail else ""
        print(f"{check.status:<4} {check.name}{suffix}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS, help="Path to MCP distribution target catalog")
    parser.add_argument("--offline", action="store_true", help="Validate static catalog only; do not perform network checks")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout for online checks")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.targets)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL load target catalog - {exc}", file=sys.stderr)
        return 1

    checks = validate_config(config)
    if not args.offline and all(check.status == "PASS" for check in checks):
        checks.extend(run_online_checks(config, timeout=args.timeout))

    print_checks(checks)
    failures = [check for check in checks if check.status == "FAIL"]
    if failures:
        print(f"\nGTM distribution monitor: {len(failures)} failed, {len(checks) - len(failures)} passed/skipped")
        return 1
    print(f"\nGTM distribution monitor: {len(checks)} passed/skipped, 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
