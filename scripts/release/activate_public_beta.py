#!/usr/bin/env python3
"""Transactionally promote the exact public-beta site and origin route."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any
import urllib.request


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, check=True, timeout=1800)


def cloudflare(token: str, method: str, url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=b"{}" if method == "POST" else None,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.loads(response.read())
    if value.get("success") is not True:
        raise RuntimeError(f"Cloudflare request failed: {value.get('errors')}")
    return value


def production_deployment(token: str, account: str, project: str) -> dict[str, Any]:
    value = cloudflare(
        token,
        "GET",
        f"https://api.cloudflare.com/client/v4/accounts/{account}/pages/projects/{project}/deployments?env=production&per_page=25",
    )
    for deployment in value.get("result", []):
        if deployment.get("environment") == "production" and deployment.get("latest_stage", {}).get("status") == "success":
            return deployment
    raise RuntimeError("no successful production Pages deployment exists")


def rollback_pages(token: str, account: str, project: str, deployment_id: str) -> None:
    cloudflare(
        token,
        "POST",
        f"https://api.cloudflare.com/client/v4/accounts/{account}/pages/projects/{project}/deployments/{deployment_id}/rollback",
    )


def fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "tinyzkp-activation"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read())


def write_private(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists() or path.is_symlink():
        raise ValueError("activation evidence already exists")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def require_executable(path: Path) -> Path:
    path = path.resolve(strict=True)
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o022 or not os.access(path, os.X_OK):
        raise ValueError("smoke command must be an operator-owned non-writable executable")
    return path


def activate(args: argparse.Namespace) -> None:
    root = Path(__file__).resolve().parents[2]
    if len(args.release_sha) != 40 or any(byte not in "0123456789abcdef" for byte in args.release_sha):
        raise SystemExit("release SHA must be a full lowercase Git commit")
    abandoned = json.loads((root / "release" / "abandoned-public-beta-candidates.json").read_text(encoding="utf-8"))
    if any(candidate.get("release_sha") == args.release_sha for candidate in abandoned.get("candidates", [])):
        raise SystemExit("this public-beta candidate is permanently abandoned and cannot be activated")
    if args.confirmation != "ACTIVATE_PUBLIC_BETA":
        raise SystemExit("explicit ACTIVATE_PUBLIC_BETA confirmation is required")
    token = os.environ.get(args.cloudflare_token_env, "")
    if not token:
        raise SystemExit(f"{args.cloudflare_token_env} is required")
    staged = args.staged_site.resolve(strict=True)
    discovery = json.loads((staged / "discovery.json").read_text(encoding="utf-8"))
    if discovery.get("service_status") != "public_beta" or discovery.get("release_sha") != args.release_sha:
        raise SystemExit("staged site identity does not match the release")
    smoke = require_executable(args.smoke_command)
    previous = production_deployment(token, args.account_id, args.project)
    current: dict[str, Any] | None = None
    started = now()
    ssh = ["ssh", "-o", "BatchMode=yes", args.api_ssh]
    try:
        run(
            [args.wrangler, "pages", "deploy", str(staged), "--project-name", args.project, "--branch", "main", "--commit-hash", args.release_sha, "--commit-dirty=false"],
            cwd=root,
        )
        current = production_deployment(token, args.account_id, args.project)
        if current.get("id") == previous.get("id"):
            raise RuntimeError("Pages production deployment did not change")
        run(ssh + ["sudo", "/opt/tinyzkp/deploy/hetzner/beta/set-beta-writes.sh", "0", args.release_sha, "public_beta"])
        run(ssh + ["sudo", "/opt/tinyzkp/deploy/hetzner/beta/switch-beta-route.sh", "public", args.release_sha, "public_beta"])
        api = fetch_json("https://api.tinyzkp.com/v1/discovery")
        site = fetch_json("https://tinyzkp.com/discovery.json")
        if any(value.get("service_status") != "public_beta" or value.get("release_sha") != args.release_sha for value in (api, site)):
            raise RuntimeError("external discovery identity mismatch")
        run(ssh + ["sudo", "/opt/tinyzkp/deploy/hetzner/beta/set-beta-writes.sh", "1", args.release_sha, "public_beta"])
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "TINYZKP_RELEASE_SHA": args.release_sha}
        run([str(smoke)], env=environment)
        run([args.wrangler, "deploy", "--config", "deploy/uptime-probe/wrangler.toml", "--var", "AUDIT_MODE:public_beta"], cwd=root)
    except BaseException as activation_error:
        rollback_errors: list[str] = []

        def attempt(label: str, action: Any) -> None:
            try:
                action()
            except BaseException as error:  # keep restoring independent surfaces
                rollback_errors.append(f"{label}: {error}")

        attempt(
            "disable writes",
            lambda: run(ssh + ["sudo", "/opt/tinyzkp/deploy/hetzner/beta/set-beta-writes.sh", "0", args.release_sha, "public_beta"]),
        )
        attempt(
            "restore Caddy rollback route",
            lambda: run(ssh + ["sudo", "/opt/tinyzkp/deploy/hetzner/beta/switch-beta-route.sh", "rollback", args.release_sha, "public_beta"]),
        )
        attempt(
            "restore Pages deployment",
            lambda: rollback_pages(token, args.account_id, args.project, str(previous["id"])),
        )
        attempt(
            "restore containment probe",
            lambda: run(
                [args.wrangler, "deploy", "--config", "deploy/uptime-probe/wrangler.toml", "--var", "AUDIT_MODE:containment"],
                cwd=root,
            ),
        )

        def verify_containment() -> None:
            discovery = fetch_json("https://tinyzkp.com/discovery.json")
            if discovery.get("service_status") != "backend_recovery":
                raise RuntimeError("public discovery did not return to containment")

        attempt("verify containment", verify_containment)
        if rollback_errors:
            raise RuntimeError(
                "activation failed and rollback was incomplete: " + "; ".join(rollback_errors)
            ) from activation_error
        raise
    write_private(
        args.evidence,
        {
            "schema_version": "public-beta-activation-v1",
            "status": "passed",
            "release_sha": args.release_sha,
            "started_at": started,
            "completed_at": now(),
            "previous_pages_deployment_id": previous["id"],
            "public_pages_deployment_id": current["id"] if current else None,
            "caddy_transaction": "passed",
            "writes_enabled_after_read_checks": True,
            "public_smoke": "passed",
            "probe_mode": "public_beta",
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--staged-site", type=Path, required=True)
    parser.add_argument("--api-ssh", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--project", default="tinyzkp")
    parser.add_argument("--cloudflare-token-env", default="CLOUDFLARE_API_TOKEN")
    parser.add_argument("--wrangler", default="wrangler")
    parser.add_argument("--smoke-command", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--confirmation", required=True)
    activate(parser.parse_args())


if __name__ == "__main__":
    main()
