#!/usr/bin/env python3
"""Fail-closed public audit for the TinyZKP backend-recovery posture."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class Check:
    name: str
    method: str
    url: str
    status: int
    marker: str | None = None
    json_code: str | None = None
    body: str | None = None
    json_field: str | None = None
    json_value: str | None = None


def request(check: Check) -> tuple[int, bytes, dict[str, str]]:
    data = (check.body or "{}").encode() if check.method == "POST" else None
    headers = {
        "User-Agent": "tinyzkp-containment-audit/1.0",
        "Accept": "application/json, text/event-stream",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(check.url, data=data, headers=headers, method=check.method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers)


def check_one(check: Check) -> tuple[bool, str]:
    try:
        status, body, _headers = request(check)
    except Exception as error:  # network/DNS/TLS failures are audit failures
        return False, f"connection error: {error}"
    if status != check.status:
        return False, f"status={status}, expected={check.status}"
    text = body.decode("utf-8", errors="replace")
    if check.marker and check.marker not in text:
        return False, f"missing marker={check.marker!r}"
    if check.json_code or check.json_field:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return False, "response was not JSON"
        if payload.get("code") != check.json_code:
            if check.json_code:
                return False, f"code={payload.get('code')!r}, expected={check.json_code!r}"
        if check.json_field and payload.get(check.json_field) != check.json_value:
            return False, f"{check.json_field}={payload.get(check.json_field)!r}, expected={check.json_value!r}"
    return True, f"status={status}"


def bases() -> tuple[str, str, str, str]:
    return (
        os.getenv("TINYZKP_AUDIT_API_BASE", "https://api.tinyzkp.com").rstrip("/"),
        os.getenv("TINYZKP_AUDIT_SITE_BASE", "https://tinyzkp.com").rstrip("/"),
        os.getenv("TINYZKP_AUDIT_WEBHOOK_BASE", "https://webhook.tinyzkp.com").rstrip("/"),
        os.getenv("TINYZKP_AUDIT_MCP_BASE", "https://mcp.tinyzkp.com").rstrip("/"),
    )


def checks() -> list[Check]:
    api, site, webhook, mcp = bases()
    disabled_api = ["/templates", "/estimate", "/prove", "/verify", "/v1/proofs"]
    result = [
        Check("api health", "GET", f"{api}/healthz", 200),
        Check("api readiness", "GET", f"{api}/readyz", 200),
        Check("published recovery status", "GET", f"{site}/discovery.json", 200, json_field="service_status", json_value="backend_recovery"),
    ]
    result.extend(Check(f"disabled API {path}", "POST" if path != "/templates" else "GET", f"{api}{path}", 503, json_code="protocol_upgrade") for path in disabled_api)
    result.extend([
        Check("disabled checkout", "POST", f"{site}/api/create-checkout", 503, json_code="protocol_upgrade"),
        Check("disabled signup", "POST", f"{site}/api/create-free-account", 503, json_code="protocol_upgrade"),
        Check("disabled demo proving", "POST", f"{site}/api/demo-prove", 503, json_code="protocol_upgrade"),
        Check("webhook health", "GET", f"{webhook}/health", 200),
        Check("retired webhook provisioning", "POST", f"{webhook}/provision-free", 404),
        Check("retired webhook session", "POST", f"{webhook}/session/resolve", 404),
        Check(
            "MCP transport",
            "POST",
            f"{mcp}/mcp",
            200,
            "protocolVersion",
            body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "tinyzkp-audit", "version": "1.0"}}}),
        ),
        Check("site home", "GET", f"{site}/", 200),
        Check("site status", "GET", f"{site}/status", 200, "Planned maintenance"),
        Check("site security", "GET", f"{site}/security", 200, "release gates"),
        Check("site docs", "GET", f"{site}/docs", 200, "protocol_upgrade"),
        Check("site pricing", "GET", f"{site}/pricing", 200, "independent review"),
        Check("retired research page", "GET", f"{site}/research", 410),
    ])
    return result


def main() -> int:
    log_dir = Path(os.getenv("TINYZKP_AUDIT_LOG_DIR", Path.home() / "Library/Logs/TinyZKP/audit"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"api_audit_{datetime.now():%Y-%m-%d}.log"
    lines = [f"TinyZKP audit mode: containment ({datetime.now():%Y-%m-%d %H:%M:%S})"]
    passed = 0
    for item in checks():
        ok, detail = check_one(item)
        passed += int(ok)
        lines.append(f"{'PASS' if ok else 'FAIL'} {item.name}: {detail}")
    failed = len(checks()) - passed
    lines.append(f"RESULTS: {passed}/{len(checks())} passed, {failed} failed")
    output = "\n".join(lines) + "\n"
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(output)
    sys.stdout.write(output)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
