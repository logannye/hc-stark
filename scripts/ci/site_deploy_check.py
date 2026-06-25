#!/usr/bin/env python3
"""Validate Cloudflare Pages deploy configuration for TinyZKP.com.

The static route checker proves internal links resolve. This preflight focuses
on deploy/runtime coherence: Pages config, advanced-mode worker routing, API
function handler exports, and the environment bindings required for production.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
WRANGLER = SITE / "wrangler.toml"
WORKER = SITE / "_worker.js"
FUNCTIONS = SITE / "functions" / "api"

IMPORT_RE = re.compile(r'import\s+\*\s+as\s+(\w+)\s+from\s+"\.\/functions\/api\/([^"]+)\.js";')
ROUTE_RE = re.compile(r'"(/api/[^"]+)":\s*(\w+)')
HANDLER_RE = re.compile(r"export\s+async\s+function\s+(onRequest(?:Get|Post|Put|Delete|Patch|Head|Options)?)\b")
ENV_RE = re.compile(
    r"(?:context\.)?env\.([A-Z][A-Z0-9_]*)"
    r"|envString\(\s*env\s*,\s*\"([A-Z][A-Z0-9_]*)\"\s*\)"
)

PROJECT_NAME = "tinyzkp"
EXPECTED_COMPATIBILITY_DATE = "2025-12-01"
EXPECTED_OUTPUT_DIR = "."

REQUIRED_FILES = [
    "index.html",
    "docs.html",
    "research.html",
    "security.html",
    "signup.html",
    "contact.html",
    "status.html",
    "sitemap.xml",
    "robots.txt",
    "shared.css",
    "analytics.js",
    "favicon.svg",
    "og-image.png",
    "og-image.svg",
    "_worker.js",
]

REQUIRED_BINDINGS = {
    "INTERNAL_SECRET",
    "STRIPE_SECRET_KEY",
    "STRIPE_PRICE_ID_TRACE_STEP_METERED",
    "STRIPE_PRICE_ID_DEVELOPER",
    "STRIPE_PRICE_ID_PRO",
    "STRIPE_PRICE_ID_SCALE",
    "TINYZKP_DEMO_API_KEY",
}

ONE_OF_BINDINGS = [
    ("STRIPE_PRICE_ID_METERED", "STRIPE_PRICE_ID"),
]

OPTIONAL_BINDINGS = {
    "CF_PAGES_BRANCH",
    "CF_PAGES_COMMIT_SHA",
    "CF_PAGES_URL",
    "STRIPE_PRICE_ID",
    "STRIPE_PRICE_ID_METERED",
    "STRIPE_PRICE_ID_PILOT",
    "STRIPE_PRICE_ID_TEAM",
    "STRIPE_PORTAL_CONFIG_ID",
    "TINYZKP_RELEASE_BUILD_URL",
    "TINYZKP_RELEASE_REF",
    "TINYZKP_RELEASE_SHA",
    "WEBHOOK_BASE_URL",
}


def display(path: pathlib.Path) -> str:
    return path.relative_to(ROOT).as_posix()


def parse_env_file(path: pathlib.Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        raise FileNotFoundError(path)
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key:
            env[key] = value
    return env


def placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        lowered == ""
        or "changeme" in lowered
        or "change_me" in lowered
        or "xxx" in lowered
        or lowered.startswith("price_xxx")
        or lowered.startswith("sk_live_xxx")
        or lowered.startswith("sk_test_xxx")
    )


def load_bindings(path: pathlib.Path | None) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key.startswith("STRIPE_")
        or key.startswith("TINYZKP_")
        or key in {"INTERNAL_SECRET", "WEBHOOK_BASE_URL"}
    }
    if path is not None:
        env.update(parse_env_file(path))
    return env


def extract_env_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for match in ENV_RE.finditer(text):
        refs.add(next(group for group in match.groups() if group))
    return refs


def validate_wrangler(failures: list[str]) -> None:
    if not WRANGLER.is_file():
        failures.append("site/wrangler.toml is missing")
        return
    data = tomllib.loads(WRANGLER.read_text(encoding="utf-8"))
    if data.get("name") != PROJECT_NAME:
        failures.append(f"site/wrangler.toml name must be {PROJECT_NAME!r}")
    if data.get("pages_build_output_dir") != EXPECTED_OUTPUT_DIR:
        failures.append("site/wrangler.toml pages_build_output_dir must be '.'")
    if data.get("compatibility_date") != EXPECTED_COMPATIBILITY_DATE:
        failures.append(
            "site/wrangler.toml compatibility_date must stay pinned to "
            f"{EXPECTED_COMPATIBILITY_DATE!r} for reproducible Pages runtime behavior"
        )


def validate_required_files(failures: list[str]) -> None:
    for rel in REQUIRED_FILES:
        if not (SITE / rel).is_file():
            failures.append(f"required site file missing: site/{rel}")


def worker_routes() -> tuple[dict[str, pathlib.Path], list[str], set[str]]:
    failures: list[str] = []
    if not WORKER.is_file():
        return {}, ["site/_worker.js is missing"], set()
    text = WORKER.read_text(encoding="utf-8")
    imports_by_var = {
        var_name: FUNCTIONS / f"{module_name}.js"
        for var_name, module_name in IMPORT_RE.findall(text)
    }
    routes: dict[str, pathlib.Path] = {}
    for route_path, var_name in ROUTE_RE.findall(text):
        module = imports_by_var.get(var_name)
        if module is None:
            failures.append(f"site/_worker.js maps {route_path} to unimported module {var_name}")
        else:
            routes[route_path] = module
    referenced_env = extract_env_refs(text)
    return routes, failures, referenced_env


def validate_functions(failures: list[str]) -> set[str]:
    routes, route_failures, env_refs = worker_routes()
    failures.extend(route_failures)

    public_functions = sorted(path for path in FUNCTIONS.glob("*.js") if not path.name.startswith("_"))
    route_modules = {path.resolve() for path in routes.values()}
    for path in public_functions:
        expected_route = f"/api/{path.stem}"
        if path.resolve() not in route_modules:
            failures.append(f"{display(path)} is not routed by site/_worker.js")
        if expected_route not in routes:
            failures.append(f"{display(path)} expected route {expected_route} missing from site/_worker.js")

    for route, path in sorted(routes.items()):
        if not path.is_file():
            failures.append(f"site/_worker.js route {route} points to missing {display(path)}")
            continue
        text = path.read_text(encoding="utf-8")
        handlers = set(HANDLER_RE.findall(text))
        if not handlers:
            failures.append(f"{display(path)} exports no onRequest handler")
        env_refs.update(extract_env_refs(text))

    allowed = REQUIRED_BINDINGS | OPTIONAL_BINDINGS | {item for group in ONE_OF_BINDINGS for item in group}
    unknown = sorted(env_refs - allowed - {"ASSETS"})
    if unknown:
        failures.append(f"unclassified Cloudflare env bindings referenced: {', '.join(unknown)}")

    return env_refs


def validate_production_bindings(bindings: dict[str, str], failures: list[str]) -> None:
    for key in sorted(REQUIRED_BINDINGS):
        if placeholder(bindings.get(key, "")):
            failures.append(f"production Pages binding {key} is missing or placeholder")
    for alternatives in ONE_OF_BINDINGS:
        if all(placeholder(bindings.get(key, "")) for key in alternatives):
            failures.append(
                "production Pages binding requires one of: " + ", ".join(alternatives)
            )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--production",
        action="store_true",
        help="Validate required production bindings from env and/or --bindings-file",
    )
    parser.add_argument(
        "--bindings-file",
        type=pathlib.Path,
        help="Optional KEY=value file representing Cloudflare Pages bindings/secrets",
    )
    args = parser.parse_args(argv)

    failures: list[str] = []
    validate_wrangler(failures)
    validate_required_files(failures)
    env_refs = validate_functions(failures)

    expected_refs = REQUIRED_BINDINGS | OPTIONAL_BINDINGS | {item for group in ONE_OF_BINDINGS for item in group}
    missing_static_refs = sorted(REQUIRED_BINDINGS - env_refs)
    if missing_static_refs:
        failures.append(
            "required production bindings are not referenced by site functions: "
            + ", ".join(missing_static_refs)
        )
    if not any(key in env_refs for group in ONE_OF_BINDINGS for key in group):
        failures.append("no Stripe per-proof price binding is referenced by checkout code")
    unused_classified = sorted(expected_refs - env_refs)
    # STRIPE_PORTAL_CONFIG_ID and WEBHOOK_BASE_URL can stay optional, but the rest
    # should be visible in code or the required binding list is drifting.
    unexpected_unused = [key for key in unused_classified if key not in {"STRIPE_PORTAL_CONFIG_ID", "WEBHOOK_BASE_URL"}]
    if unexpected_unused:
        failures.append("classified Pages bindings are not referenced: " + ", ".join(unexpected_unused))

    if args.production:
        try:
            bindings = load_bindings(args.bindings_file)
        except FileNotFoundError as exc:
            failures.append(f"bindings file not found: {exc.filename}")
        else:
            validate_production_bindings(bindings, failures)

    if failures:
        print("Cloudflare Pages deploy check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    mode = "production" if args.production else "static"
    print(f"PASS Cloudflare Pages deploy check ({mode}, {len(env_refs)} env bindings classified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
