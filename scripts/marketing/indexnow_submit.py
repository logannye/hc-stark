#!/usr/bin/env python3
"""Submit TinyZKP public URLs to IndexNow.

IndexNow is a public indexing notification protocol. This script defaults to a
dry run; pass --submit after deploying the key file to notify participating
search engines through api.indexnow.org.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SITEMAP = ROOT / "site" / "sitemap.xml"
DEFAULT_KEY_FILE = ROOT / "site" / "indexnow-key.txt"
DEFAULT_ENDPOINT = "https://api.indexnow.org/indexnow"
DEFAULT_SITE_URL = "https://tinyzkp.com"
KEY_RE = re.compile(r"^[A-Za-z0-9-]{8,128}$")
INDEXNOW_MAX_URLS = 10_000


@dataclass(frozen=True)
class Submission:
    host: str
    key: str
    key_location: str
    urls: list[str]

    def payload(self) -> dict[str, object]:
        return {
            "host": self.host,
            "key": self.key,
            "keyLocation": self.key_location,
            "urlList": self.urls,
        }


def read_key(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"IndexNow key file is missing: {path}")
    key = path.read_text(encoding="utf-8").strip()
    if not KEY_RE.fullmatch(key):
        raise ValueError("IndexNow key must be 8-128 alphanumeric/dash characters")
    return key


def sitemap_urls(path: Path, site_url: str) -> list[str]:
    if not path.is_file():
        raise ValueError(f"sitemap is missing: {path}")
    root = ET.parse(path).getroot()
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    host = urlparse(site_url).netloc
    urls: list[str] = []
    seen: set[str] = set()
    for loc in root.findall(".//sm:loc", namespace):
        url = (loc.text or "").strip()
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != host:
            continue
        if url not in seen:
            urls.append(url)
            seen.add(url)
    if not urls:
        raise ValueError("sitemap did not contain any same-host HTTPS URLs")
    return urls


def build_submission(site_url: str, sitemap: Path, key_file: Path, limit: int | None) -> Submission:
    parsed_site = urlparse(site_url)
    if parsed_site.scheme != "https" or not parsed_site.netloc:
        raise ValueError("--site-url must be an HTTPS origin")
    key = read_key(key_file)
    urls = sitemap_urls(sitemap, site_url)
    if limit is not None:
        urls = urls[:limit]
    if len(urls) > INDEXNOW_MAX_URLS:
        raise ValueError(f"IndexNow supports at most {INDEXNOW_MAX_URLS} URLs per request")
    return Submission(
        host=parsed_site.netloc,
        key=key,
        key_location=f"{site_url.rstrip('/')}/{key_file.name}",
        urls=urls,
    )


def submit(endpoint: str, payload: dict[str, object], timeout: float) -> tuple[int, str]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-url", default=DEFAULT_SITE_URL, help="Canonical HTTPS site origin")
    parser.add_argument("--sitemap", type=Path, default=DEFAULT_SITEMAP, help="Sitemap XML to submit")
    parser.add_argument("--key-file", type=Path, default=DEFAULT_KEY_FILE, help="Hosted IndexNow key file")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="IndexNow endpoint")
    parser.add_argument("--limit", type=int, default=None, help="Submit only the first N sitemap URLs")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds")
    parser.add_argument("--submit", action="store_true", help="Actually POST to IndexNow")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        submission = build_submission(
            site_url=args.site_url,
            sitemap=args.sitemap,
            key_file=args.key_file,
            limit=args.limit,
        )
    except ValueError as exc:
        print(f"FAIL IndexNow submission build - {exc}", file=sys.stderr)
        return 1

    payload = submission.payload()
    if not args.submit:
        result = {
            "ok": True,
            "submitted": False,
            "host": submission.host,
            "keyLocation": submission.key_location,
            "urlCount": len(submission.urls),
            "firstUrls": submission.urls[:5],
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(
                f"DRY-RUN IndexNow submission: {len(submission.urls)} URL(s) "
                f"for {submission.host}; keyLocation={submission.key_location}"
            )
        return 0

    status, body = submit(args.endpoint, payload, args.timeout)
    ok = status in (200, 202)
    result = {
        "ok": ok,
        "submitted": True,
        "endpoint": args.endpoint,
        "status": status,
        "urlCount": len(submission.urls),
        "body": body[:500],
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{'PASS' if ok else 'FAIL'} IndexNow submit - status={status}, urls={len(submission.urls)}")
        if body:
            print(body[:500])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
