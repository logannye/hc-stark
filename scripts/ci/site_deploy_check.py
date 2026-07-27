#!/usr/bin/env python3
"""Validate the static-only Cloudflare Pages configuration for TinyZKP.com."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
import tomllib

from deploy_readiness_check import ProductionEnvError, load_private_env_file


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
    "guard.html",
    "compatibility.html",
    "benchmarks.html",
    "doctor.html",
    "troubleshooting.html",
    "plonky3-out-of-memory.html",
    "resumable-plonky3-prover.html",
    "ssd-backed-plonky3-proving.html",
    "docs.html",
    "security.html",
    "pricing.html",
    "releases.html",
    "support.html",
    "privacy.html",
    "terms.html",
    "refunds.html",
    "eula.html",
    "pricing.json",
    "discovery.json",
    "commerce.json",
    "compatibility.json",
    "release.json",
    "offers.jsonld",
    "sitemap.xml",
    "robots.txt",
    "shared.css",
    "shared.js",
    "roi.js",
    "favicon.svg",
    "guard-social.png",
    "_worker.js",
]

REQUIRED_BINDINGS: set[str] = set()

ONE_OF_BINDINGS: list[tuple[str, ...]] = []

# `DB` is the D1 binding shared by the anonymous rate limiter
# (`rate_limit_windows`) and the shape-only demand log (`demand_log`); see
# site/wrangler.toml's `[[d1_databases]]` block and migrations/*.sql. It is
# classified as optional (not required), unlike REQUIRED_BINDINGS, because
# its real identity lives in wrangler.toml's committed `database_id` -- it
# is a structural resource binding, not a secret injected out-of-band via
# `wrangler pages secret` (which `cloudflare_pages_secret_check.py` validates
# using REQUIRED_BINDINGS). Both `site/_worker.js` code paths that use it
# fail open/silent if it is ever absent or misconfigured.
OPTIONAL_BINDINGS: set[str] = {"DB"}


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


def load_bindings(
    path: pathlib.Path | None, *, production: bool = False
) -> dict[str, str]:
    if production:
        if path is None:
            raise ProductionEnvError(
                "production Pages bindings require an explicit owner-only file"
            )
        return load_private_env_file(path, exact_mode_0600=True)

    env = {
        key: value
        for key, value in os.environ.items()
        if key.startswith("TINYZKP_")
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
    unused_classified = sorted(expected_refs - env_refs)
    if unused_classified:
        failures.append(
            "classified Pages bindings are not referenced: "
            + ", ".join(unused_classified)
        )

    if args.production:
        try:
            bindings = load_bindings(args.bindings_file, production=True)
        except (FileNotFoundError, ProductionEnvError) as exc:
            failures.append(f"production Pages bindings are unsafe: {exc}")
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
