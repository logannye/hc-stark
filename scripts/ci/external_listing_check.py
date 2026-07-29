#!/usr/bin/env python3
"""Fail CI when a published surface points at a URL this site does not serve.

Retiring the hosted stack (`b4570c5`) turned `api.tinyzkp.com` and
`mcp.tinyzkp.com` into permanent 410s and deleted `crates/hc-mcp`. Three
external directory manifests were left behind advertising exactly those
things, plus a `/signup` page and a `/requests` page that had also become
410s. Nothing noticed, because nothing checked published URLs against the
routes the worker actually serves.

This resolves every URL that appears in a published manifest or in
`site/llms.txt` against the route table declared in `site/_worker.js`, and
fails on any that maps to a retired host, a gone prefix, or a path the site
does not serve. It needs no network access -- the retired hosts, permanent
redirects, gone prefixes, and public routes are all declared in the worker,
which is the same source of truth the deployed site uses.

Verified against the manifests as they were actually published, it catches
the four URL claims:

    server.json    mcp.tinyzkp.com/mcp   -> retired host
    server.json    /requests             -> gone prefix
    smithery.yaml  mcp.tinyzkp.com       -> retired host
    smithery.yaml  /signup               -> gone prefix

It does NOT catch the other three false claims in those files -- the
`repository.subfolder: crates/hc-mcp` pointing at a deleted crate, the "100
evaluation receipts/month" product that never existed, and the ten
advertised MCP tools. Those are not URLs and are a different class of
problem; this gate is not a substitute for reading a manifest before
publishing it. See docs/runbooks/external_listing_retraction.md.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
WORKER = SITE / "_worker.js"

# Files whose URLs are published to third parties. A manifest listed here
# that does not exist is fine -- it means we delisted, which is a valid
# outcome, not a failure.
PUBLISHED_SURFACES = (
    "server.json",
    "smithery.yaml",
    "glama.json",
    "site/llms.txt",
)

# The trailing `(?<![.,;:)])` matters: these URLs appear mid-prose in
# llms.txt, and swallowing the sentence's full stop turns every one of them
# into a phantom failure.
URL_RE = re.compile(r"https://([a-z0-9.-]*tinyzkp\.com)(/[^\s\"'`)>,]*(?<![.,;:)]))?")

_SET_RE = r"const {name} = new Set\(\[(.*?)\]\)"
_STRING_RE = re.compile(r"[\"']([^\"']+)[\"']")


def _worker_set(text: str, name: str) -> set[str]:
    match = re.search(_SET_RE.format(name=name), text, re.DOTALL)
    if match is None:
        raise ValueError(f"{name} not found in site/_worker.js")
    return set(_STRING_RE.findall(match.group(1)))


def _worker_list(text: str, name: str) -> list[str]:
    match = re.search(rf"const {name} = \[(.*?)\];", text, re.DOTALL)
    if match is None:
        raise ValueError(f"{name} not found in site/_worker.js")
    return _STRING_RE.findall(match.group(1))


def _worker_map_keys(text: str, name: str) -> set[str]:
    match = re.search(rf"const {name} = new Map\(\[(.*?)\]\);", text, re.DOTALL)
    if match is None:
        raise ValueError(f"{name} not found in site/_worker.js")
    return set(_STRING_RE.findall(match.group(1))[::2])


def worker_routes(text: str) -> dict[str, set[str] | list[str]]:
    return {
        "retired_hosts": _worker_set(text, "RETIRED_HOSTS"),
        "public_routes": _worker_set(text, "PUBLIC_ROUTES"),
        "redirects": _worker_map_keys(text, "PERMANENT_REDIRECTS"),
        "gone_prefixes": _worker_list(text, "GONE_PREFIXES"),
    }


def served_assets() -> set[str]:
    """Static files the site publishes, as absolute paths."""
    assets: set[str] = set()
    for path in SITE.rglob("*"):
        if path.is_file():
            assets.add("/" + path.relative_to(SITE).as_posix())
    return assets


def classify(
    url: str,
    host: str,
    path: str,
    routes: dict[str, set[str] | list[str]],
    assets: set[str],
) -> str | None:
    """Return a failure reason, or None when the URL is served."""
    if host in routes["retired_hosts"]:
        return f"{url} targets retired host {host} (permanent 410)"
    if host != "tinyzkp.com":
        return None  # some other subdomain; not this gate's business
    path = path or "/"
    path = path.split("#", 1)[0].split("?", 1)[0]
    if path in routes["public_routes"] or path in routes["redirects"]:
        return None
    if path in assets or path.rstrip("/") + ".html" in assets:
        return None
    for prefix in routes["gone_prefixes"]:
        if path.startswith(prefix):
            return f"{url} matches gone prefix {prefix!r} (permanent 410)"
    # `/v1/...` is handled by the worker before the static path, and is not
    # in PUBLIC_ROUTES because it is an API, not a page.
    if path.startswith("/v1/"):
        return None
    return f"{url} is not a served route, redirect, or asset"


def check(
    surfaces: dict[str, str],
    routes: dict[str, set[str] | list[str]],
    assets: set[str],
) -> list[str]:
    failures: list[str] = []
    for name, text in sorted(surfaces.items()):
        for match in URL_RE.finditer(text):
            reason = classify(
                match.group(0), match.group(1), match.group(2) or "", routes, assets
            )
            if reason is not None:
                failures.append(f"{name}: {reason}")
    return failures


def main(argv: list[str]) -> int:
    try:
        worker_text = WORKER.read_text(encoding="utf-8")
        routes = worker_routes(worker_text)
        assets = served_assets()
        surfaces = {
            name: (ROOT / name).read_text(encoding="utf-8")
            for name in PUBLISHED_SURFACES
            if (ROOT / name).is_file()
        }
        failures = check(surfaces, routes, assets)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"external listing check failed to run: {error}", file=sys.stderr)
        return 2

    if failures:
        print("external listing check failed:", file=sys.stderr)
        for failure in sorted(set(failures)):
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(
        f"PASS external listing check "
        f"({len(surfaces)} published surface(s), every tinyzkp.com URL is served)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
