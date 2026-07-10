#!/usr/bin/env python3
"""Exercise TinyZKP contact intake through Cloudflare and delete the probe."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin


def load_secret(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("internal-secret file must be a regular non-symlink file")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError("internal-secret file must be owner-only")
    raw = path.read_bytes()
    if not 16 <= len(raw) <= 4096:
        raise RuntimeError("internal-secret file length is invalid")
    value = raw.decode("utf-8").strip()
    if not value or "\n" in value or "\r" in value:
        raise RuntimeError("internal-secret file contains an invalid value")
    return value


def post_json(url: str, payload: dict[str, object], headers: dict[str, str]) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            raw = response.read(1024 * 1024)
    except urllib.error.HTTPError as error:
        status = error.code
        raw = error.read(1024 * 1024)
    try:
        body = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{url} returned malformed JSON with HTTP {status}") from error
    if not isinstance(body, dict):
        raise RuntimeError(f"{url} returned non-object JSON")
    return status, body


def run(site_url: str, webhook_url: str, secret: str) -> dict[str, object]:
    nonce = "probe_" + secrets.token_hex(16)
    message = f"TinyZKP automated contact readiness probe {nonce}"
    status, submitted = post_json(
        urljoin(site_url.rstrip("/") + "/", "api/contact"),
        {
            "name": "TinyZKP readiness probe",
            "email": "",
            "category": "General Inquiry",
            "message": message,
            "qualification": {
                "intent": "automated_readiness_probe",
                "contact_method": "github",
                "contact_handle": "https://tinyzkp.com/status",
                "consent": "twelve_month_retention",
            },
            "_honeypot": "",
        },
        {"Origin": site_url.rstrip("/")},
    )
    application_id = submitted.get("application_id")
    if status != 200 or not isinstance(application_id, str) or not application_id.startswith("eval_"):
        raise RuntimeError(f"public intake failed with HTTP {status}: {submitted.get('error', 'missing ID')}")
    cleanup_status, cleanup = post_json(
        urljoin(webhook_url.rstrip("/") + "/", "contact-readiness"),
        {"application_id": application_id, "nonce": nonce},
        {"X-Internal-Secret": secret},
    )
    if cleanup_status != 200 or cleanup.get("stored") is not True or cleanup.get("cleaned") is not True:
        raise RuntimeError(
            f"stored intake probe could not be reconciled/cleaned (HTTP {cleanup_status})"
        )
    return {"ok": True, "stored": True, "cleaned": True, "application_id": application_id}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-url", default="https://tinyzkp.com")
    parser.add_argument("--webhook-url", default="https://webhook.tinyzkp.com")
    parser.add_argument("--internal-secret-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run(args.site_url, args.webhook_url, load_secret(args.internal_secret_file))
    except RuntimeError as error:
        print(f"FAIL  {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
