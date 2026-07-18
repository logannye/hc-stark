#!/usr/bin/env python3
"""Aggregate the fast gates required for a TinyZKP reconciliation launch.

The individual checks stay as the source of truth. This script gives operators
one deterministic command for local/CI preflight, plus opt-in live canaries for
the post-deploy announcement gate.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
from email.parser import BytesParser
import hashlib
import hmac
import io
import json
import os
import pathlib
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field

from deploy_readiness_check import (
    ProductionEnvError,
    backup_env_exec,
    load_private_env_file,
    parse_private_env_bytes,
    read_private_file,
    reject_conflicting_inherited_environment,
)
from cloudflare_toolchain_check import validate_runtime as cloudflare_toolchain_identity
import fixed_host_backup_evidence
import installer_drill_evidence
import legacy_billing_containment_status
import runtime_lock


ROOT = pathlib.Path(__file__).resolve().parents[2]
TRUSTED_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
FIXED_PYCACHE_PREFIX = "/var/lib/tinyzkp-preflight-pycache"
EXPECTED_REMOTE_URL = "https://github.com/logannye/hc-stark.git"
FIXED_EVIDENCE_PATH = pathlib.Path(
    "/var/lib/tinyzkp-private/deploy/production-preflight.json"
)
FIXED_PAGES_BINDINGS_PATH = pathlib.Path(
    "/var/lib/tinyzkp-private/deploy/pages-bindings.env"
)
FIXED_MACHINE_ID_PATH = pathlib.Path("/etc/machine-id")
FIXED_CONSUMPTION_DIR = FIXED_EVIDENCE_PATH.parent / "consumed"
DEFAULT_DEPLOYMENT_ID = "tinyzkp-production-primary"
EVIDENCE_SCHEMA = "tinyzkp-production-preflight-evidence-v8"
EVIDENCE_MAX_BYTES = 256 * 1024
EVIDENCE_MAX_AGE = timedelta(minutes=30)
RELEASE_SHA = re.compile(r"^[0-9a-f]{40}$")
NONCE = re.compile(r"^[0-9a-f]{64}$")
DEPLOYMENT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
EVIDENCE_KEYS = {
    "schema_version",
    "status",
    "created_at",
    "release_sha",
    "remote_url",
    "remote_main_sha",
    "branch",
    "working_tree_clean",
    "published_origin_main",
    "production",
    "live",
    "nonce",
    "host_identity_sha256",
    "deployment_id",
    "host_env_sha256",
    "pages_bindings_sha256",
    "backup_loader_token_sha256",
    "backup_transport_kind",
    "backup_transport_secret_path",
    "backup_transport_secret_sha256",
    "production_runtime_identity_sha256",
    "production_runtime_file_count",
    "production_runtime_byte_count",
    "fixed_host_backup_evidence_identity_sha256",
    "fixed_host_backup_subject_sha256",
    "fixed_host_backup_run_id",
    "installer_drill_evidence_identity_sha256",
    "installer_drill_subject_sha256",
    "installer_drill_run_id",
    "installer_drill_review_status",
    "legacy_billing_containment_required",
    "legacy_billing_status_identity_sha256",
    "legacy_billing_status_subject_sha256",
    "legacy_billing_current_inventory_sha256",
    "legacy_billing_status_observed_at",
    "private_gate_input_snapshot_sha256",
    "host_python_realpath",
    "host_python_sha256",
    "venv_root",
    "venv_identity_sha256",
    "venv_file_count",
    "venv_package_count",
    "node_realpath",
    "node_sha256",
    "node_version",
    "cloudflare_toolchain_profile_id",
    "cloudflare_toolchain_profile_sha256",
    "cloudflare_package_lock_sha256",
    "cloudflare_materialization_sha256",
    "wrangler_version",
    "wrangler_install_root",
    "wrangler_entrypoint_realpath",
    "wrangler_entrypoint_sha256",
    "wrangler_tree_sha256",
    "wrangler_file_count",
    "wrangler_total_bytes",
    "git_realpath",
    "git_sha256",
    "container_images_sha256",
    "container_image_ids",
    "gate_results",
}


def production_image_names(release_sha: str) -> tuple[str, str]:
    if RELEASE_SHA.fullmatch(release_sha) is None:
        raise EvidenceError("production image release tag is not canonical")
    return (
        f"tinyzkp/hc-server:{release_sha}",
        f"tinyzkp/hc-mcp:{release_sha}",
    )


@dataclass(frozen=True)
class Step:
    name: str
    command: tuple[str, ...]
    env: dict[str, str] = field(default_factory=dict)
    timeout_secs: int = 120


@dataclass(frozen=True)
class StepResult:
    name: str
    status: str
    command: tuple[str, ...]
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    duration_secs: float = 0.0
    error: str | None = None


def build_steps(
    args: argparse.Namespace, *, python: str = "python3", node: str = "node"
) -> list[Step]:
    if args.live and not args.production:
        raise ValueError("live launch checks require the complete production preflight")
    if args.production and not args.host_python:
        raise ValueError(
            "production preflight requires the explicit production host Python interpreter"
        )
    if args.production and not args.node_executable:
        raise ValueError(
            "production preflight requires the explicit pinned Node executable"
        )
    if args.production and not args.wrangler_entrypoint:
        raise ValueError(
            "production preflight requires the explicit pinned Wrangler entrypoint"
        )
    deploy_readiness_cmd = [
        python,
        "scripts/ci/deploy_readiness_check.py",
        "--env-file",
        args.env_file,
    ]
    if args.production:
        deploy_readiness_cmd.append("--production")
    if args.check_host_python or args.production:
        deploy_readiness_cmd.append("--check-host-python")
    if args.host_python:
        deploy_readiness_cmd.extend(["--host-python", args.host_python])

    cloudflare_toolchain_cmd = (python, "scripts/ci/cloudflare_toolchain_check.py")
    if args.production:
        cloudflare_toolchain_cmd = (
            python,
            "scripts/ci/cloudflare_toolchain_check.py",
            "--runtime",
            "--node-executable",
            args.node_executable,
            "--wrangler-entrypoint",
            args.wrangler_entrypoint,
        )

    backup_test_command = (
        python,
        "-m",
        "pytest",
        "billing/tests/test_backup_script.py",
    )
    if args.production:
        backup_test_command = (
            "/usr/sbin/runuser",
            "--user",
            "tinyzkp-billing",
            "--",
            python,
            "-m",
            "pytest",
            "billing/tests/test_backup_script.py",
        )

    steps = [
        Step(
            "recovery reconciliation invariants",
            (python, "scripts/ci/recovery_reconciliation_invariants.py"),
        ),
        Step("backend recovery gate", (python, "scripts/ci/backend_recovery_gate.py")),
        Step("MCP recovery server-card", (python, "scripts/ci/server_card_check.py")),
        Step(
            "frozen Plonky3 compatibility profile",
            (python, "scripts/ci/plonky3_compatibility_gate.py"),
        ),
        Step(
            "Guard launch state derivation",
            (python, "scripts/ci/guard_launch_gate.py", "--check"),
        ),
        Step(
            "billing runtime dependency metadata",
            (python, "billing/runtime_lock.py", "verify-metadata"),
        ),
        Step(
            "backup/restore drift check", (python, "scripts/ci/backup_restore_check.py")
        ),
        Step(
            "backup execution and retention tests",
            backup_test_command,
        ),
        Step(
            "fixed-host backup evidence policy tests",
            (
                python,
                "-m",
                "pytest",
                "scripts/ci/test_fixed_host_backup_evidence.py",
                "scripts/ci/test_fixed_host_evidence_workspace.py",
            ),
        ),
        Step(
            "installer and legacy containment evidence policy tests",
            (
                python,
                "-m",
                "pytest",
                "scripts/ci/test_installer_drill_evidence.py",
                "scripts/ci/test_legacy_billing_containment_status.py",
            ),
        ),
        Step("static site route check", (python, "scripts/ci/site_route_check.py")),
        Step(
            "static site route policy tests",
            (python, "-m", "pytest", "scripts/ci/test_site_route_check.py"),
        ),
        Step(
            "release identity policy tests",
            (
                python,
                "-m",
                "pytest",
                "scripts/ci/test_release_identity_check.py",
                "scripts/ci/test_site_asset_manifest.py",
            ),
        ),
        Step(
            "legacy billing containment tests",
            (
                python,
                "-m",
                "pytest",
                "billing/tests/test_legacy_billing_containment.py",
                "billing/tests/test_legacy_write_quarantine.py",
            ),
        ),
        Step(
            "evaluation intake tests",
            (
                python,
                "-m",
                "pytest",
                "billing/tests/test_contact_intake.py",
                "billing/tests/test_evaluation_store.py",
                "scripts/monitoring/test_contact_intake_readiness.py",
            ),
        ),
        Step(
            "public claims lint",
            (python, "-m", "pytest", "billing/tests/test_site_pricing_parity.py"),
        ),
        Step(
            "commercial offer parity",
            (python, "scripts/commercial/render_offers.py", "--check"),
        ),
        Step(
            "contract billing policy tests",
            (
                python,
                "-m",
                "pytest",
                "billing/tests/test_contract_billing.py",
                "billing/tests/test_configure_contract_portal.py",
                "billing/tests/test_evaluation_start_ready.py",
                "billing/tests/test_stripe_production_identity_check.py",
            ),
        ),
        Step(
            "commercial scorecard policy tests",
            (
                python,
                "-m",
                "pytest",
                "scripts/commercial/test_validate_scorecard.py",
                "scripts/commercial/test_evaluation_qualification.py",
                "scripts/commercial/test_partner_preflight.py",
            ),
        ),
        Step(
            "Cloudflare Pages static deploy check",
            (python, "scripts/ci/site_deploy_check.py"),
        ),
        Step(
            "private production configuration policy tests",
            (
                python,
                "-m",
                "pytest",
                "scripts/ci/test_site_deploy_check.py",
                "scripts/ci/test_production_secret_parity_check.py",
            ),
        ),
        Step(
            "Cloudflare Pages secret policy tests",
            (
                python,
                "-m",
                "pytest",
                "scripts/ci/test_cloudflare_pages_secret_check.py",
                "scripts/ci/test_cloudflare_toolchain_check.py",
            ),
        ),
        Step(
            "Cloudflare Pages release transaction adversarial tests",
            (
                python,
                "-m",
                "pytest",
                "scripts/deploy/test_cloudflare_pages_release.py",
            ),
        ),
        Step(
            "pinned Cloudflare production toolchain",
            cloudflare_toolchain_cmd,
        ),
        Step(
            "Cloudflare Pages worker dispatch check",
            (node, "scripts/ci/site_worker_dispatch_test.mjs"),
        ),
        Step(
            "public beta Pages preview policy check",
            (node, "scripts/release/test_public_beta_site_worker.mjs"),
        ),
        Step(
            "Docker Compose render check",
            (python, "scripts/ci/compose_config_check.py"),
        ),
        Step(
            "billing service hardening tests",
            (python, "-m", "pytest", "scripts/ci/test_billing_service_hardening.py"),
        ),
        Step(
            "transactional deployment tests",
            (python, "-m", "pytest", "deploy/hetzner/test_deployment_transaction.py"),
        ),
        Step("deploy readiness check", tuple(deploy_readiness_cmd)),
    ]

    if args.production:
        steps.extend(
            [
                Step(
                    "complete production host runtime identity",
                    (
                        "/usr/bin/python3",
                        "billing/runtime_lock.py",
                        "verify-production-runtime",
                        "--venv-root",
                        str(pathlib.Path(args.host_python).parent.parent),
                        "--node-binary",
                        args.node_executable,
                    ),
                ),
                Step(
                    "sealed billing runtime wheelhouse",
                    (
                        "/usr/bin/python3",
                        "billing/runtime_lock.py",
                        "verify-wheelhouse",
                        "--wheelhouse",
                        "/var/lib/tinyzkp-runtime/wheelhouse",
                        "--production-permissions",
                    ),
                ),
                Step(
                    "installed billing runtime closure",
                    (
                        args.host_python,
                        "billing/runtime_lock.py",
                        "verify-installed",
                    ),
                ),
                Step(
                    "reviewed fixed-host backup and restore evidence",
                    (
                        "/usr/bin/python3",
                        "scripts/ci/fixed_host_backup_evidence.py",
                        "--expected-release-sha",
                        args.expected_release_sha or "0" * 40,
                        "--expected-deployment-id",
                        args.deployment_id,
                        "--machine-id-file",
                        str(FIXED_MACHINE_ID_PATH),
                    ),
                ),
                Step(
                    "billing runtime installer crash and rollback evidence",
                    (
                        "/usr/bin/python3",
                        "scripts/ci/installer_drill_evidence.py",
                        "verify",
                        "--expected-release-sha",
                        args.expected_release_sha or "0" * 40,
                        "--expected-deployment-id",
                        args.deployment_id,
                        "--machine-id-file",
                        str(FIXED_MACHINE_ID_PATH),
                    ),
                ),
                Step(
                    "host and Pages secret parity",
                    (
                        python,
                        "scripts/ci/production_secret_parity_check.py",
                        "--host-env-file",
                        args.env_file,
                        "--pages-bindings-file",
                        args.pages_bindings_file,
                    ),
                ),
                Step(
                    "read-only Stripe production identity check",
                    (
                        args.host_python,
                        "billing/stripe_production_identity_check.py",
                        "--env-file",
                        args.env_file,
                    ),
                    timeout_secs=60,
                ),
                Step(
                    "Cloudflare Pages production binding check",
                    (
                        python,
                        "scripts/ci/site_deploy_check.py",
                        "--production",
                        "--bindings-file",
                        args.pages_bindings_file,
                    ),
                ),
            ]
        )
        if args.require_legacy:
            steps.append(
                Step(
                    "fresh read-only legacy billing containment status",
                    (
                        "/usr/bin/python3",
                        "scripts/ci/legacy_billing_containment_status.py",
                        "verify",
                        "--env-file",
                        args.env_file,
                        "--expected-release-sha",
                        args.expected_release_sha or "0" * 40,
                        "--expected-deployment-id",
                        args.deployment_id,
                    ),
                )
            )
        if args.evidence_output or args.verify_evidence:
            steps.append(
                Step(
                    "identity-bound maintenance container build",
                    (
                        "/usr/bin/docker",
                        "compose",
                        "-f",
                        "docker-compose.yml",
                        "-f",
                        "deploy/hetzner/docker-compose.prod.yml",
                        "build",
                    ),
                    env={"HC_IMAGE_TAG": args.expected_release_sha or "0" * 40},
                    timeout_secs=1800,
                )
            )

    if args.live:
        cloudflare_environment = {
            key: os.environ[key]
            for key in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID")
            if os.environ.get(key)
        }
        steps.extend(
            [
                Step(
                    "Cloudflare Pages live secret inventory check",
                    (
                        python,
                        "scripts/ci/cloudflare_pages_secret_check.py",
                        "--node-executable",
                        args.node_executable,
                        "--wrangler-entrypoint",
                        args.wrangler_entrypoint,
                    ),
                    env=cloudflare_environment,
                    timeout_secs=60,
                ),
                Step(
                    "live backend recovery canary",
                    (
                        python,
                        "scripts/monitoring/backend_recovery_canary.py",
                        "--site-url",
                        args.site_url,
                        "--api-url",
                        args.api_url,
                        "--mcp-url",
                        args.mcp_url,
                    ),
                    timeout_secs=180,
                ),
                Step(
                    "live durable contact intake canary",
                    (
                        python,
                        "scripts/monitoring/contact_intake_readiness.py",
                        "--site-url",
                        args.site_url,
                        "--webhook-url",
                        args.webhook_url,
                        "--internal-secret-file",
                        args.contact_readiness_secret_file,
                    ),
                    timeout_secs=120,
                ),
            ]
        )
        expected_release_sha = (
            args.expected_release_sha
            or os.environ.get("TINYZKP_EXPECT_RELEASE_SHA", "")
        ).strip()
        if expected_release_sha:
            steps.append(
                Step(
                    "live release identity check",
                    (
                        python,
                        "scripts/ci/release_identity_check.py",
                        "--expected-sha",
                        expected_release_sha,
                        "--site-url",
                        args.site_url,
                        "--api-url",
                        args.api_url,
                        "--mcp-url",
                        args.mcp_url,
                    ),
                    timeout_secs=120,
                )
            )

    if args.authenticated_smoke:
        raise ValueError(
            "authenticated proving smoke is unavailable while backend v1 is blocked"
        )

    return steps


def _tail(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def production_subprocess_environment(
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    environment = {
        "PATH": TRUSTED_SYSTEM_PATH,
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": FIXED_PYCACHE_PREFIX,
        "PYTEST_ADDOPTS": "-p no:cacheprovider",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "RCLONE_CONFIG": "/var/lib/tinyzkp-private/backup/rclone.conf",
    }
    if extra:
        forbidden = {
            key
            for key in extra
            if key in {"PATH", "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS"}
            or key.startswith("LD_")
            or key.startswith("DYLD_")
            or key.startswith("GIT_")
        }
        if forbidden:
            raise EvidenceError(
                "production step requested forbidden environment keys: "
                + ", ".join(sorted(forbidden))
            )
        environment.update(extra)
    return environment


def run_step(
    step: Step, *, root: pathlib.Path = ROOT, production: bool = False
) -> StepResult:
    env = (
        production_subprocess_environment(step.env)
        if production
        else {**os.environ, **step.env}
    )
    started = time.monotonic()
    try:
        completed = subprocess.run(
            step.command,
            cwd=root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=step.timeout_secs,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return StepResult(
            name=step.name,
            status="FAIL",
            command=step.command,
            stdout=_tail(exc.stdout or ""),
            stderr=_tail(exc.stderr or ""),
            duration_secs=time.monotonic() - started,
            error=f"timed out after {step.timeout_secs}s",
        )
    except OSError as exc:
        return StepResult(
            name=step.name,
            status="FAIL",
            command=step.command,
            duration_secs=time.monotonic() - started,
            error=str(exc),
        )

    return StepResult(
        name=step.name,
        status="PASS" if completed.returncode == 0 else "FAIL",
        command=step.command,
        stdout=_tail(completed.stdout),
        stderr=_tail(completed.stderr),
        returncode=completed.returncode,
        duration_secs=time.monotonic() - started,
    )


def run_steps(
    steps: list[Step], *, root: pathlib.Path = ROOT, production: bool = False
) -> list[StepResult]:
    return [run_step(step, root=root, production=production) for step in steps]


def result_to_json(result: StepResult) -> dict[str, object]:
    return {
        "name": result.name,
        "status": result.status,
        "command": list(result.command),
        "returncode": result.returncode,
        "duration_secs": round(result.duration_secs, 3),
        "error": result.error,
        "stdout_tail": result.stdout,
        "stderr_tail": result.stderr,
    }


class EvidenceError(ValueError):
    """A production preflight artifact is unsafe, stale, or incomplete."""


def _strict_json_object(raw: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"production preflight evidence duplicates {key!r}")
            result[key] = value
        return result

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                EvidenceError(f"invalid JSON number {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(
            "production preflight evidence must be strict UTF-8 JSON"
        ) from error
    if not isinstance(payload, dict):
        raise EvidenceError(
            "production preflight evidence must contain one JSON object"
        )
    return payload


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _backup_private_input_identity(env_file: pathlib.Path) -> dict[str, str]:
    """Bind private backup capabilities that live outside the deployment env.

    The env digest binds the selected transport and its public destination. The
    loader capability plus rclone credential bytes are separate files read
    by the eventual cron process, so a deploy claim must also become invalid if
    any of those bytes change after preflight.
    """

    try:
        configured = load_private_env_file(env_file)
        return _backup_private_input_identity_from_config(configured)
    except ProductionEnvError as error:
        raise EvidenceError(
            "private backup capability is unavailable or unsafe"
        ) from error


def _backup_private_input_identity_from_config(
    configured: dict[str, str],
) -> dict[str, str]:
    try:
        loader_raw = read_private_file(
            backup_env_exec.FIXED_LOADER_TOKEN,
            label="backup loader token",
            max_bytes=128,
            exact_mode_0600=True,
        )
        remote = configured.get("HC_BACKUP_REMOTE", "").strip()
        http_url = configured.get("HC_BACKUP_HTTP_URL", "").strip()
        http_token_file = configured.get("HC_BACKUP_HTTP_TOKEN_FILE", "").strip()
        if remote and not http_url and not http_token_file:
            kind = "rclone"
            secret_path = backup_env_exec.FIXED_RCLONE_CONFIG
            max_bytes = 256 * 1024
        else:
            raise EvidenceError(
                "production backup evidence requires exactly one encrypted rclone credential"
            )
        secret_raw = read_private_file(
            secret_path,
            label=f"{kind} backup credential",
            max_bytes=max_bytes,
            exact_mode_0600=True,
        )
    except ProductionEnvError as error:
        raise EvidenceError(
            "private backup capability is unavailable or unsafe"
        ) from error
    return {
        "backup_loader_token_sha256": _sha256(loader_raw),
        "backup_transport_kind": kind,
        "backup_transport_secret_path": str(secret_path),
        "backup_transport_secret_sha256": _sha256(secret_raw),
    }


def _private_gate_input_snapshot(args: argparse.Namespace) -> dict[str, str]:
    host_raw = read_private_file(
        pathlib.Path(args.env_file),
        label="production env",
        max_bytes=64 * 1024,
    )
    pages_raw = read_private_file(
        pathlib.Path(args.pages_bindings_file),
        label="production Pages bindings",
        max_bytes=64 * 1024,
        exact_mode_0600=True,
    )
    configured = parse_private_env_bytes(host_raw)
    return {
        "host_env_sha256": _sha256(host_raw),
        "pages_bindings_sha256": _sha256(pages_raw),
        **_backup_private_input_identity_from_config(configured),
    }


def _identity_snapshot_sha256(snapshot: dict[str, object]) -> str:
    return _sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _regular_file_digest(
    path: pathlib.Path,
    *,
    label: str = "executable",
    reject_symlink: bool = False,
) -> tuple[str, str]:
    try:
        lexical_metadata = path.lstat()
    except OSError as error:
        raise EvidenceError(f"{label} is unavailable") from error
    if reject_symlink and path.is_symlink():
        raise EvidenceError(f"{label} must not be a symlink")
    if not path.is_symlink() and not stat.S_ISREG(lexical_metadata.st_mode):
        raise EvidenceError(f"{label} must be a regular file")
    try:
        real_path = path.resolve(strict=True)
    except OSError as error:
        raise EvidenceError(f"{label} is unavailable") from error
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(real_path, flags)
    except OSError as error:
        raise EvidenceError(f"{label} is unavailable or unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & stat.S_IXUSR:
            raise EvidenceError(f"{label} must resolve to an executable regular file")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > 256 * 1024 * 1024:
                raise EvidenceError(f"{label} exceeds the 256 MiB identity limit")
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return str(real_path), digest.hexdigest()


def _cloudflare_evidence_identity(args: argparse.Namespace) -> dict[str, object]:
    identity = cloudflare_toolchain_identity(
        pathlib.Path(args.node_executable), pathlib.Path(args.wrangler_entrypoint)
    )
    expected_keys = {
        "profile_id",
        "profile_sha256",
        "package_lock_sha256",
        "materialization_sha256",
        "node_version",
        "wrangler_version",
        "node_realpath",
        "node_sha256",
        "wrangler_install_root",
        "wrangler_entrypoint_realpath",
        "wrangler_entrypoint_sha256",
        "wrangler_tree_sha256",
        "wrangler_file_count",
        "wrangler_total_bytes",
    }
    if set(identity) != expected_keys:
        raise EvidenceError("Cloudflare toolchain identity is incomplete")
    return {
        "cloudflare_toolchain_profile_id": identity["profile_id"],
        "cloudflare_toolchain_profile_sha256": identity["profile_sha256"],
        "cloudflare_package_lock_sha256": identity["package_lock_sha256"],
        "cloudflare_materialization_sha256": identity["materialization_sha256"],
        "node_version": identity["node_version"],
        "node_realpath": identity["node_realpath"],
        "node_sha256": identity["node_sha256"],
        "wrangler_version": identity["wrangler_version"],
        "wrangler_install_root": identity["wrangler_install_root"],
        "wrangler_entrypoint_realpath": identity["wrangler_entrypoint_realpath"],
        "wrangler_entrypoint_sha256": identity["wrangler_entrypoint_sha256"],
        "wrangler_tree_sha256": identity["wrangler_tree_sha256"],
        "wrangler_file_count": identity["wrangler_file_count"],
        "wrangler_total_bytes": identity["wrangler_total_bytes"],
    }


def _production_runtime_evidence_identity(
    args: argparse.Namespace,
) -> dict[str, object]:
    try:
        identity = runtime_lock.verify_production_runtime_identity(
            runtime_lock.DEFAULT_HOST_PROVENANCE,
            runtime_lock.DEFAULT_PROFILE,
            venv_root=pathlib.Path(args.host_python).parent.parent,
            node_binary=pathlib.Path(args.node_executable),
        )
    except (OSError, subprocess.TimeoutExpired, runtime_lock.RuntimeLockError) as error:
        raise EvidenceError(
            "complete production host runtime identity is invalid"
        ) from error
    return {
        "production_runtime_identity_sha256": identity.identity_sha256,
        "production_runtime_file_count": identity.file_count,
        "production_runtime_byte_count": identity.byte_count,
    }


def _fixed_host_backup_evidence_identity(
    args: argparse.Namespace,
    *,
    machine_id_path: pathlib.Path = FIXED_MACHINE_ID_PATH,
) -> dict[str, object]:
    expected_release_sha = str(args.expected_release_sha or "")
    try:
        report = fixed_host_backup_evidence.validate_evidence(
            expected_release_sha=expected_release_sha,
            expected_host_identity_sha256=stable_host_identity(machine_id_path),
            expected_deployment_id=args.deployment_id,
            machine_id_file=machine_id_path,
        )
    except (OSError, fixed_host_backup_evidence.EvidenceError) as error:
        raise EvidenceError("fixed-host backup evidence is invalid") from error
    return {
        "fixed_host_backup_evidence_identity_sha256": report[
            "evidence_identity_sha256"
        ],
        "fixed_host_backup_subject_sha256": report["subject_artifact_set_sha256"],
        "fixed_host_backup_run_id": report["run_id"],
    }


def _installer_drill_evidence_identity(
    args: argparse.Namespace,
    *,
    machine_id_path: pathlib.Path = FIXED_MACHINE_ID_PATH,
) -> dict[str, object]:
    expected_release_sha = str(args.expected_release_sha or "")
    try:
        report = installer_drill_evidence.validate_evidence(
            installer_drill_evidence.FIXED_EVIDENCE,
            expected_release_sha=expected_release_sha,
            expected_host_identity_sha256=stable_host_identity(machine_id_path),
            expected_deployment_id=args.deployment_id,
            machine_id_file=machine_id_path,
        )
    except (OSError, installer_drill_evidence.EvidenceError) as error:
        raise EvidenceError(
            "billing runtime installer drill evidence is invalid"
        ) from error
    return {
        "installer_drill_evidence_identity_sha256": report["evidence_identity_sha256"],
        "installer_drill_subject_sha256": report["subject_sha256"],
        "installer_drill_run_id": report["run_id"],
        "installer_drill_review_status": report["review_status"],
    }


def _legacy_billing_containment_evidence_identity(
    args: argparse.Namespace,
) -> dict[str, object]:
    empty: dict[str, object] = {
        "legacy_billing_containment_required": False,
        "legacy_billing_status_identity_sha256": "",
        "legacy_billing_status_subject_sha256": "",
        "legacy_billing_current_inventory_sha256": "",
        "legacy_billing_status_observed_at": "",
    }
    if not args.require_legacy:
        return empty
    try:
        configured = load_private_env_file(pathlib.Path(args.env_file))
        account_id = configured.get("STRIPE_EXPECTED_ACCOUNT_ID", "").strip()
        display_name = configured.get("STRIPE_EXPECTED_DISPLAY_NAME", "").strip()
        report = legacy_billing_containment_status.validate_evidence(
            legacy_billing_containment_status.FIXED_EVIDENCE,
            expected_release_sha=str(args.expected_release_sha or ""),
            expected_deployment_id=args.deployment_id,
            expected_account_id=account_id,
            expected_display_name=display_name,
        )
    except (
        OSError,
        ProductionEnvError,
        legacy_billing_containment_status.EvidenceError,
    ) as error:
        raise EvidenceError(
            "fresh legacy billing containment status is invalid"
        ) from error
    return {
        "legacy_billing_containment_required": True,
        "legacy_billing_status_identity_sha256": report["evidence_identity_sha256"],
        "legacy_billing_status_subject_sha256": report["subject_sha256"],
        "legacy_billing_current_inventory_sha256": report["current_inventory_sha256"],
        "legacy_billing_status_observed_at": report["observed_at"],
    }


def container_image_identity(release_sha: str) -> tuple[dict[str, str], str]:
    image_names = production_image_names(release_sha)
    try:
        completed = subprocess.run(
            ("/usr/bin/docker", "image", "inspect", *image_names),
            env=production_subprocess_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceError("cannot inspect production container images") from error
    if completed.returncode != 0:
        raise EvidenceError("production container images are unavailable")
    try:
        inspected = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(
            "production container image identity is malformed"
        ) from error
    if not isinstance(inspected, list) or len(inspected) != len(image_names):
        raise EvidenceError("production container image identity is incomplete")
    identities: dict[str, str] = {}
    for name, record in zip(image_names, inspected):
        if not isinstance(record, dict) or not isinstance(record.get("Id"), str):
            raise EvidenceError("production container image ID is malformed")
        image_id = record["Id"]
        if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
            raise EvidenceError("production container image ID is not canonical")
        identities[name] = image_id
    canonical = json.dumps(inspected, sort_keys=True, separators=(",", ":")).encode()
    return identities, _sha256(canonical)


def _normalized_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def venv_identity(host_python: pathlib.Path) -> dict[str, object]:
    """Hash every immutable venv byte and validate installed distribution records."""

    if host_python.name != "python" or host_python.parent.name != "bin":
        raise EvidenceError("host Python must be the venv bin/python path")
    venv_root = host_python.parent.parent
    try:
        root_metadata = venv_root.lstat()
        python_metadata = host_python.lstat()
    except OSError as error:
        raise EvidenceError("production venv is unavailable") from error
    if (
        venv_root.is_symlink()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) & 0o022
    ):
        raise EvidenceError(
            "production venv root must be current-owner and symlink-free"
        )
    if (
        host_python.is_symlink()
        or not stat.S_ISREG(python_metadata.st_mode)
        or python_metadata.st_nlink != 1
        or python_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(python_metadata.st_mode) & 0o222
        or not python_metadata.st_mode & stat.S_IXUSR
    ):
        raise EvidenceError("production venv Python must be an immutable private copy")

    pyvenv_cfg = venv_root / "pyvenv.cfg"
    if not pyvenv_cfg.is_file() or pyvenv_cfg.is_symlink():
        raise EvidenceError("production venv pyvenv.cfg is missing or unsafe")
    site_packages = sorted((venv_root / "lib").glob("python*/site-packages"))
    if len(site_packages) != 1 or not site_packages[0].is_dir():
        raise EvidenceError(
            "production venv must contain exactly one site-packages directory"
        )
    site_packages_root = site_packages[0]

    files: list[dict[str, object]] = []
    file_paths: set[pathlib.Path] = set()
    total_bytes = 0
    for current, directory_names, file_names in os.walk(venv_root, followlinks=False):
        current_path = pathlib.Path(current)
        current_metadata = current_path.lstat()
        if (
            current_path.is_symlink()
            or not stat.S_ISDIR(current_metadata.st_mode)
            or current_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(current_metadata.st_mode) & 0o022
        ):
            raise EvidenceError(
                "production venv contains a mutable or unsafe directory"
            )
        for name in sorted(directory_names):
            candidate = current_path / name
            if candidate.is_symlink():
                raise EvidenceError("production venv contains a symlink")
        for name in sorted(file_names):
            candidate = current_path / name
            metadata = candidate.lstat()
            if (
                candidate.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o222
            ):
                raise EvidenceError("production venv contains a mutable or unsafe file")
            raw = candidate.read_bytes()
            total_bytes += len(raw)
            if total_bytes > 512 * 1024 * 1024 or len(files) >= 20_000:
                raise EvidenceError("production venv exceeds its identity limits")
            relative = candidate.relative_to(venv_root).as_posix()
            files.append({"path": relative, "size": len(raw), "sha256": _sha256(raw)})
            file_paths.add(candidate.resolve(strict=True))

    packages: list[dict[str, str]] = []
    package_names: set[str] = set()
    for dist_info in sorted(site_packages_root.glob("*.dist-info")):
        if dist_info.is_symlink() or not dist_info.is_dir():
            raise EvidenceError("production venv distribution metadata is unsafe")
        metadata_path = dist_info / "METADATA"
        record_path = dist_info / "RECORD"
        if (
            metadata_path.resolve(strict=True) not in file_paths
            or record_path.resolve(strict=True) not in file_paths
        ):
            raise EvidenceError("production venv distribution lacks METADATA or RECORD")
        metadata_raw = metadata_path.read_bytes()
        record_raw = record_path.read_bytes()
        message = BytesParser().parsebytes(metadata_raw)
        name = str(message.get("Name", "")).strip()
        version = str(message.get("Version", "")).strip()
        normalized = _normalized_package_name(name)
        if not normalized or not version or normalized in package_names:
            raise EvidenceError(
                "production venv contains duplicate or invalid packages"
            )
        package_names.add(normalized)
        try:
            record_rows = list(csv.reader(io.StringIO(record_raw.decode("utf-8"))))
        except (UnicodeDecodeError, csv.Error) as error:
            raise EvidenceError("production venv RECORD is malformed") from error
        seen_records: set[pathlib.Path] = set()
        for row in record_rows:
            if len(row) != 3 or not row[0]:
                raise EvidenceError("production venv RECORD row is malformed")
            lexical = site_packages_root / pathlib.PurePosixPath(row[0])
            try:
                target = lexical.resolve(strict=True)
                target.relative_to(venv_root.resolve(strict=True))
            except (OSError, ValueError) as error:
                raise EvidenceError(
                    "production venv RECORD points outside the venv"
                ) from error
            if target in seen_records or target not in file_paths:
                raise EvidenceError(
                    "production venv RECORD target is duplicate or missing"
                )
            seen_records.add(target)
        packages.append(
            {
                "name": normalized,
                "version": version,
                "metadata_sha256": _sha256(metadata_raw),
                "record_sha256": _sha256(record_raw),
            }
        )
    if not packages:
        raise EvidenceError(
            "production venv contains no installed distribution metadata"
        )

    canonical = json.dumps(
        {
            "files": sorted(files, key=lambda item: str(item["path"])),
            "packages": packages,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        "venv_root": str(venv_root.resolve(strict=True)),
        "venv_identity_sha256": _sha256(canonical),
        "venv_file_count": len(files),
        "venv_package_count": len(packages),
    }


def _git_bytes(
    root: pathlib.Path, git_executable: pathlib.Path, *arguments: str
) -> bytes:
    completed = subprocess.run(
        (
            str(git_executable),
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            *arguments,
        ),
        cwd=root,
        env=production_subprocess_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise EvidenceError("cannot establish the deployment source identity")
    return completed.stdout


def _git_remote_bytes(git_executable: pathlib.Path, *arguments: str) -> bytes:
    """Run a remote-only Git query without repository or user configuration."""

    environment = production_subprocess_environment()
    environment.update(
        {
            "GIT_DIR": "/dev/null",
            "GIT_WORK_TREE": "/nonexistent",
            "GIT_CEILING_DIRECTORIES": "/",
        }
    )
    completed = subprocess.run(
        (str(git_executable), "--no-pager", *arguments),
        cwd=pathlib.Path("/"),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise EvidenceError("cannot establish the reviewed remote identity")
    return completed.stdout


def _git_output(
    root: pathlib.Path, git_executable: pathlib.Path, *arguments: str
) -> str:
    try:
        return _git_bytes(root, git_executable, *arguments).decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise EvidenceError("Git returned a non-UTF-8 source identity") from error


def _git_remote_output(git_executable: pathlib.Path, *arguments: str) -> str:
    try:
        return _git_remote_bytes(git_executable, *arguments).decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise EvidenceError("Git returned a non-UTF-8 remote identity") from error


def validate_git_metadata(root: pathlib.Path) -> None:
    """Require a private, current-owner Git directory with no external objects."""

    git_dir = root / ".git"
    try:
        root_metadata = git_dir.lstat()
    except OSError as error:
        raise EvidenceError("deployment Git metadata is unavailable") from error
    if (
        git_dir.is_symlink()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) & 0o022
    ):
        raise EvidenceError(
            "deployment Git metadata must be current-owner and not group/world-writable"
        )

    forbidden = {
        pathlib.Path("objects/info/alternates"),
        pathlib.Path("objects/info/http-alternates"),
        pathlib.Path("info/grafts"),
    }
    for directory, names, files in os.walk(git_dir, topdown=True, followlinks=False):
        current = pathlib.Path(directory)
        for name in (*names, *files):
            candidate = current / name
            try:
                metadata = candidate.lstat()
                relative = candidate.relative_to(git_dir)
            except (OSError, ValueError) as error:
                raise EvidenceError(
                    "deployment Git metadata changed during validation"
                ) from error
            expected_directory = name in names
            if (
                candidate.is_symlink()
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or (expected_directory and not stat.S_ISDIR(metadata.st_mode))
                or (not expected_directory and not stat.S_ISREG(metadata.st_mode))
            ):
                raise EvidenceError("deployment Git metadata contains an unsafe entry")
            if relative in forbidden:
                raise EvidenceError(
                    "deployment Git metadata may not use external object stores"
                )


def source_identity(
    root: pathlib.Path,
    git_executable: pathlib.Path,
    expected_remote_url: str = EXPECTED_REMOTE_URL,
) -> tuple[str, str, bool, bool, str, str]:
    validate_git_metadata(root)
    release_sha = _git_output(root, git_executable, "rev-parse", "HEAD")
    branch = _git_output(root, git_executable, "rev-parse", "--abbrev-ref", "HEAD")
    clean = not _git_output(
        root, git_executable, "status", "--porcelain", "--untracked-files=all"
    )
    configured_remote_url = _git_output(
        root,
        git_executable,
        "config",
        "--local",
        "--no-includes",
        "--get",
        "remote.origin.url",
    )
    if configured_remote_url != expected_remote_url:
        raise EvidenceError("origin URL does not match the reviewed TinyZKP remote")
    remote_observation = _git_remote_output(
        git_executable,
        "ls-remote",
        "--exit-code",
        expected_remote_url,
        "refs/heads/main",
    )
    remote_lines = remote_observation.splitlines()
    if len(remote_lines) != 1:
        raise EvidenceError("remote main identity is missing or ambiguous")
    remote_parts = remote_lines[0].split()
    if len(remote_parts) != 2 or remote_parts[1] != "refs/heads/main":
        raise EvidenceError("remote main identity is malformed")
    remote_main_sha = remote_parts[0]
    if RELEASE_SHA.fullmatch(release_sha) is None:
        raise EvidenceError("deployment release SHA is not canonical")
    if RELEASE_SHA.fullmatch(remote_main_sha) is None:
        raise EvidenceError("remote main SHA is not canonical")
    return (
        release_sha,
        branch,
        clean,
        remote_main_sha == release_sha,
        configured_remote_url,
        remote_main_sha,
    )


def validate_immutable_source_materialization(
    root: pathlib.Path, git_executable: pathlib.Path
) -> None:
    validate_git_metadata(root)
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise EvidenceError("deployment source root is unavailable") from error
    if (
        root.is_symlink()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) & 0o022
    ):
        raise EvidenceError(
            "deployment source root must be current-owner and symlink-free"
        )
    raw_paths = _git_bytes(root, git_executable, "ls-files", "-z")
    try:
        relative_paths = [
            pathlib.Path(item.decode("utf-8"))
            for item in raw_paths.split(b"\0")
            if item
        ]
    except UnicodeDecodeError as error:
        raise EvidenceError("tracked source path is not UTF-8") from error
    if not relative_paths:
        raise EvidenceError("deployment source contains no tracked files")
    object_format = _git_output(
        root, git_executable, "rev-parse", "--show-object-format"
    )
    if object_format not in {"sha1", "sha256"}:
        raise EvidenceError("deployment repository object format is unsupported")
    expected_entries: dict[pathlib.Path, tuple[str, str]] = {}
    for record in _git_bytes(root, git_executable, "ls-tree", "-r", "-z", "HEAD").split(
        b"\0"
    ):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ")
            relative = pathlib.Path(raw_path.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as error:
            raise EvidenceError("HEAD tree contains a malformed entry") from error
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise EvidenceError("HEAD tree contains a non-regular deployment entry")
        expected_entries[relative] = (mode, object_id)
    if set(expected_entries) != set(relative_paths):
        raise EvidenceError("tracked worktree paths do not match the HEAD tree")
    resolved_root = root.resolve(strict=True)
    for relative in relative_paths:
        if relative.is_absolute() or ".." in relative.parts:
            raise EvidenceError("tracked source path is unsafe")
        candidate = root / relative
        try:
            metadata = candidate.lstat()
            candidate.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as error:
            raise EvidenceError(
                "tracked source file is unavailable or escapes the root"
            ) from error
        if (
            candidate.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o222
        ):
            raise EvidenceError(
                "tracked deployment source must be immutable regular files"
            )
        expected_mode, expected_object_id = expected_entries[relative]
        actual_mode = "100755" if metadata.st_mode & stat.S_IXUSR else "100644"
        if actual_mode != expected_mode:
            raise EvidenceError("tracked deployment source mode differs from HEAD")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(candidate, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise EvidenceError("tracked deployment source identity changed")
            if opened.st_size > 256 * 1024 * 1024:
                raise EvidenceError("tracked deployment source file is too large")
            digest = hashlib.new(object_format)
            digest.update(f"blob {opened.st_size}\0".encode("ascii"))
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
            if total != opened.st_size:
                raise EvidenceError("tracked deployment source size changed")
        finally:
            os.close(descriptor)
        if not hmac.compare_digest(digest.hexdigest(), expected_object_id):
            raise EvidenceError("tracked deployment source bytes differ from HEAD")


def _timestamp(now: datetime) -> str:
    return (
        now.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def stable_host_identity(path: pathlib.Path = FIXED_MACHINE_ID_PATH) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError("stable host identity is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise EvidenceError("stable host identity file is unsafe")
        raw = os.read(descriptor, 256)
        if os.read(descriptor, 1):
            raise EvidenceError("stable host identity file is oversized")
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("ascii").strip().lower()
    except UnicodeDecodeError as error:
        raise EvidenceError("stable host identity is malformed") from error
    if re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise EvidenceError("stable host identity is malformed")
    return _sha256(value.encode("ascii"))


def _gate_results(results: list[StepResult]) -> list[dict[str, object]]:
    return [
        {
            "name": result.name,
            "status": result.status,
            "returncode": result.returncode,
        }
        for result in results
    ]


def placeholder_evidence(status: str, expected_release_sha: str) -> dict[str, object]:
    return {
        "schema_version": EVIDENCE_SCHEMA,
        "status": status,
        "created_at": _timestamp(datetime.now(timezone.utc)),
        "release_sha": expected_release_sha,
        "remote_url": "",
        "remote_main_sha": "",
        "branch": "",
        "working_tree_clean": False,
        "published_origin_main": False,
        "production": True,
        "live": False,
        "nonce": secrets.token_hex(32),
        "host_identity_sha256": "",
        "deployment_id": "",
        "host_env_sha256": "",
        "pages_bindings_sha256": "",
        "backup_loader_token_sha256": "",
        "backup_transport_kind": "",
        "backup_transport_secret_path": "",
        "backup_transport_secret_sha256": "",
        "production_runtime_identity_sha256": "",
        "production_runtime_file_count": 0,
        "production_runtime_byte_count": 0,
        "fixed_host_backup_evidence_identity_sha256": "",
        "fixed_host_backup_subject_sha256": "",
        "fixed_host_backup_run_id": "",
        "installer_drill_evidence_identity_sha256": "",
        "installer_drill_subject_sha256": "",
        "installer_drill_run_id": "",
        "installer_drill_review_status": "",
        "legacy_billing_containment_required": False,
        "legacy_billing_status_identity_sha256": "",
        "legacy_billing_status_subject_sha256": "",
        "legacy_billing_current_inventory_sha256": "",
        "legacy_billing_status_observed_at": "",
        "private_gate_input_snapshot_sha256": "",
        "host_python_realpath": "",
        "host_python_sha256": "",
        "venv_root": "",
        "venv_identity_sha256": "",
        "venv_file_count": 0,
        "venv_package_count": 0,
        "node_realpath": "",
        "node_sha256": "",
        "node_version": "",
        "cloudflare_toolchain_profile_id": "",
        "cloudflare_toolchain_profile_sha256": "",
        "cloudflare_package_lock_sha256": "",
        "cloudflare_materialization_sha256": "",
        "wrangler_version": "",
        "wrangler_install_root": "",
        "wrangler_entrypoint_realpath": "",
        "wrangler_entrypoint_sha256": "",
        "wrangler_tree_sha256": "",
        "wrangler_file_count": 0,
        "wrangler_total_bytes": 0,
        "git_realpath": "",
        "git_sha256": "",
        "container_images_sha256": "",
        "container_image_ids": {},
        "gate_results": [],
    }


def build_pass_evidence(
    args: argparse.Namespace,
    results: list[StepResult],
    *,
    now: datetime | None = None,
    root: pathlib.Path = ROOT,
    machine_id_path: pathlib.Path = FIXED_MACHINE_ID_PATH,
    issuance_input_snapshot: dict[str, str] | None = None,
) -> dict[str, object]:
    if any(result.status != "PASS" or result.returncode != 0 for result in results):
        raise EvidenceError("production preflight did not pass every aggregate gate")
    git_path = pathlib.Path(args.git_executable)
    host_python_path = pathlib.Path(args.host_python)
    validate_immutable_source_materialization(root, git_path)
    (
        release_sha,
        branch,
        clean,
        published_origin_main,
        remote_url,
        remote_main_sha,
    ) = source_identity(root, git_path)
    if release_sha != args.expected_release_sha:
        raise EvidenceError(
            "production preflight release SHA does not match the expected SHA"
        )
    if branch != "main":
        raise EvidenceError(
            "production preflight evidence may be issued only from main"
        )
    if not clean:
        raise EvidenceError(
            "production preflight evidence requires a clean source tree"
        )
    if not published_origin_main:
        raise EvidenceError(
            "production preflight evidence requires HEAD to equal origin/main"
        )
    final_private_snapshot = _private_gate_input_snapshot(args)
    if (
        issuance_input_snapshot is not None
        and final_private_snapshot != issuance_input_snapshot
    ):
        raise EvidenceError(
            "private production inputs changed while aggregate gates were running"
        )
    production_runtime = _production_runtime_evidence_identity(args)
    fixed_host_backup = _fixed_host_backup_evidence_identity(
        args, machine_id_path=machine_id_path
    )
    installer_drill = _installer_drill_evidence_identity(
        args, machine_id_path=machine_id_path
    )
    legacy_billing = _legacy_billing_containment_evidence_identity(args)
    host_python_realpath, host_python_sha256 = _regular_file_digest(
        host_python_path,
        label="host Python",
        reject_symlink=True,
    )
    runtime = venv_identity(host_python_path)
    cloudflare_runtime = _cloudflare_evidence_identity(args)
    git_realpath, git_sha256 = _regular_file_digest(
        git_path, label="Git executable", reject_symlink=True
    )
    container_image_ids, container_images_sha256 = container_image_identity(release_sha)
    return {
        "schema_version": EVIDENCE_SCHEMA,
        "status": "pass",
        "created_at": _timestamp(now or datetime.now(timezone.utc)),
        "release_sha": release_sha,
        "remote_url": remote_url,
        "remote_main_sha": remote_main_sha,
        "branch": branch,
        "working_tree_clean": True,
        "published_origin_main": True,
        "production": True,
        "live": False,
        "nonce": secrets.token_hex(32),
        "host_identity_sha256": stable_host_identity(machine_id_path),
        "deployment_id": args.deployment_id,
        **final_private_snapshot,
        "private_gate_input_snapshot_sha256": _identity_snapshot_sha256(
            final_private_snapshot
        ),
        **production_runtime,
        **fixed_host_backup,
        **installer_drill,
        **legacy_billing,
        "host_python_realpath": host_python_realpath,
        "host_python_sha256": host_python_sha256,
        **runtime,
        **cloudflare_runtime,
        "git_realpath": git_realpath,
        "git_sha256": git_sha256,
        "container_images_sha256": container_images_sha256,
        "container_image_ids": container_image_ids,
        "gate_results": _gate_results(results),
    }


def validate_evidence_issuance_inputs(
    args: argparse.Namespace,
    *,
    root: pathlib.Path = ROOT,
    machine_id_path: pathlib.Path = FIXED_MACHINE_ID_PATH,
) -> dict[str, str]:
    git_path = pathlib.Path(args.git_executable)
    host_python_path = pathlib.Path(args.host_python)
    _regular_file_digest(git_path, label="Git executable", reject_symlink=True)
    _cloudflare_evidence_identity(args)
    _production_runtime_evidence_identity(args)
    _fixed_host_backup_evidence_identity(args, machine_id_path=machine_id_path)
    _installer_drill_evidence_identity(args, machine_id_path=machine_id_path)
    _legacy_billing_containment_evidence_identity(args)
    _regular_file_digest(host_python_path, label="host Python", reject_symlink=True)
    venv_identity(host_python_path)
    validate_immutable_source_materialization(root, git_path)
    release_sha, branch, clean, published, _remote, _remote_sha = source_identity(
        root, git_path
    )
    if (
        release_sha != args.expected_release_sha
        or branch != "main"
        or not clean
        or not published
    ):
        raise EvidenceError(
            "evidence issuance requires the current clean published main"
        )
    private_snapshot = _private_gate_input_snapshot(args)
    stable_host_identity(machine_id_path)
    return private_snapshot


def atomic_write_evidence(path: pathlib.Path, payload: dict[str, object]) -> None:
    parent = path.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise EvidenceError(
            "production preflight evidence parent is unavailable"
        ) from error
    if parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
        raise EvidenceError(
            "production preflight evidence parent must be a real directory"
        )
    if (
        parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise EvidenceError(
            "production preflight evidence parent must be current-owner-only"
        )
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as error:
        raise EvidenceError("production preflight evidence target is unsafe") from error
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != os.geteuid()
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise EvidenceError(
            "existing production preflight evidence must be current-owner mode 0600"
        )

    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if len(encoded) > EVIDENCE_MAX_BYTES:
        raise EvidenceError("production preflight evidence exceeds its size limit")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        directory = os.open(parent, directory_flags)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def create_evidence_exclusive(path: pathlib.Path, payload: dict[str, object]) -> None:
    parent = path.parent
    metadata = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise EvidenceError("production preflight evidence parent must be mode 0700")
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise EvidenceError(
            "production preflight evidence already exists or is unsafe; archive it before issuing new evidence"
        ) from error
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def consume_evidence(
    path: pathlib.Path,
    args: argparse.Namespace,
    *,
    now: datetime | None = None,
    root: pathlib.Path = ROOT,
    machine_id_path: pathlib.Path = FIXED_MACHINE_ID_PATH,
    consumption_dir: pathlib.Path = FIXED_CONSUMPTION_DIR,
) -> dict[str, object]:
    raw = read_private_file(
        path,
        label="production preflight evidence",
        max_bytes=EVIDENCE_MAX_BYTES,
        exact_mode_0600=True,
    )
    preliminary = _strict_json_object(raw)
    nonce = preliminary.get("nonce")
    if not isinstance(nonce, str) or NONCE.fullmatch(nonce) is None:
        raise EvidenceError("production preflight evidence nonce is invalid")
    directory_metadata = consumption_dir.lstat()
    if (
        consumption_dir.is_symlink()
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
    ):
        raise EvidenceError(
            "production evidence consumption directory must be mode 0700"
        )
    claim = consumption_dir / f"{nonce}.claim"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        claim_descriptor = os.open(claim, flags, 0o600)
    except OSError as error:
        raise EvidenceError(
            "production preflight evidence was already consumed"
        ) from error
    os.close(claim_descriptor)
    destination = consumption_dir / f"{nonce}.evidence.json"
    failed_destination = consumption_dir / f"{nonce}.failed.json"
    try:
        report = verify_evidence(
            path,
            args,
            now=now,
            root=root,
            machine_id_path=machine_id_path,
        )
    except Exception:
        if path.exists() and not failed_destination.exists():
            os.rename(path, failed_destination)
        raise
    if destination.exists():
        raise EvidenceError("production preflight evidence destination already exists")
    os.rename(path, destination)
    return {**report, "consumed": True, "nonce": nonce}


def _parse_created_at(raw: object) -> datetime:
    if (
        not isinstance(raw, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            raw,
        )
        is None
    ):
        raise EvidenceError(
            "production preflight evidence created_at is not canonical UTC"
        )
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError(
            "production preflight evidence created_at is invalid"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise EvidenceError("production preflight evidence created_at must be UTC")
    return parsed


def verify_evidence(
    path: pathlib.Path,
    args: argparse.Namespace,
    *,
    now: datetime | None = None,
    root: pathlib.Path = ROOT,
    machine_id_path: pathlib.Path = FIXED_MACHINE_ID_PATH,
) -> dict[str, object]:
    if not args.production or args.live:
        raise EvidenceError(
            "production preflight evidence is valid only before a production deploy"
        )
    try:
        raw = read_private_file(
            path,
            label="production preflight evidence",
            max_bytes=EVIDENCE_MAX_BYTES,
            exact_mode_0600=True,
        )
    except ProductionEnvError as error:
        raise EvidenceError(str(error)) from error
    payload = _strict_json_object(raw)
    if set(payload) != EVIDENCE_KEYS:
        raise EvidenceError(
            "production preflight evidence fields are incomplete or unknown"
        )
    if (
        payload.get("schema_version") != EVIDENCE_SCHEMA
        or payload.get("status") != "pass"
    ):
        raise EvidenceError(
            "production preflight evidence is not a completed passing artifact"
        )
    checked_at = now or datetime.now(timezone.utc)
    created_at = _parse_created_at(payload.get("created_at"))
    age = checked_at - created_at
    if age < timedelta(minutes=-1) or age > EVIDENCE_MAX_AGE:
        raise EvidenceError("production preflight evidence is stale or future-dated")
    if (
        payload.get("production") is not True
        or payload.get("live") is not False
        or payload.get("branch") != "main"
        or payload.get("working_tree_clean") is not True
        or payload.get("published_origin_main") is not True
        or payload.get("remote_url") != EXPECTED_REMOTE_URL
        or payload.get("deployment_id") != args.deployment_id
        or payload.get("host_identity_sha256") != stable_host_identity(machine_id_path)
        or not isinstance(payload.get("nonce"), str)
        or NONCE.fullmatch(str(payload.get("nonce"))) is None
    ):
        raise EvidenceError(
            "production preflight evidence has an invalid deployment mode"
        )
    expected_release_sha = str(args.expected_release_sha or "")
    if RELEASE_SHA.fullmatch(expected_release_sha) is None:
        raise EvidenceError("expected deployment release SHA is not canonical")
    git_path = pathlib.Path(args.git_executable)
    host_python_path = pathlib.Path(args.host_python)
    validate_immutable_source_materialization(root, git_path)
    (
        release_sha,
        branch,
        clean,
        published_origin_main,
        remote_url,
        remote_main_sha,
    ) = source_identity(root, git_path)
    if (
        payload.get("release_sha") != expected_release_sha
        or release_sha != expected_release_sha
        or branch != "main"
        or not clean
        or not published_origin_main
        or payload.get("remote_url") != remote_url
        or payload.get("remote_main_sha") != remote_main_sha
    ):
        raise EvidenceError(
            "production preflight evidence does not bind the current clean main release"
        )

    configured = load_private_env_file(pathlib.Path(args.env_file))
    reject_conflicting_inherited_environment(configured, dict(os.environ))
    private_snapshot = _private_gate_input_snapshot(args)
    production_runtime = _production_runtime_evidence_identity(args)
    fixed_host_backup = _fixed_host_backup_evidence_identity(
        args, machine_id_path=machine_id_path
    )
    installer_drill = _installer_drill_evidence_identity(
        args, machine_id_path=machine_id_path
    )
    legacy_billing = _legacy_billing_containment_evidence_identity(args)
    host_python_realpath, host_python_sha256 = _regular_file_digest(
        host_python_path,
        label="host Python",
        reject_symlink=True,
    )
    runtime = venv_identity(host_python_path)
    cloudflare_runtime = _cloudflare_evidence_identity(args)
    git_realpath, git_sha256 = _regular_file_digest(
        git_path, label="Git executable", reject_symlink=True
    )
    container_image_ids, container_images_sha256 = container_image_identity(
        expected_release_sha
    )
    if (
        any(payload.get(key) != value for key, value in private_snapshot.items())
        or payload.get("private_gate_input_snapshot_sha256")
        != _identity_snapshot_sha256(private_snapshot)
        or type(payload.get("production_runtime_file_count")) is not int
        or type(payload.get("production_runtime_byte_count")) is not int
        or any(payload.get(key) != value for key, value in production_runtime.items())
        or any(payload.get(key) != value for key, value in fixed_host_backup.items())
        or any(payload.get(key) != value for key, value in installer_drill.items())
        or any(payload.get(key) != value for key, value in legacy_billing.items())
        or payload.get("host_python_realpath") != host_python_realpath
        or payload.get("host_python_sha256") != host_python_sha256
        or payload.get("venv_root") != runtime["venv_root"]
        or payload.get("venv_identity_sha256") != runtime["venv_identity_sha256"]
        or type(payload.get("venv_file_count")) is not int
        or payload.get("venv_file_count") != runtime["venv_file_count"]
        or type(payload.get("venv_package_count")) is not int
        or payload.get("venv_package_count") != runtime["venv_package_count"]
        or type(payload.get("wrangler_file_count")) is not int
        or type(payload.get("wrangler_total_bytes")) is not int
        or any(payload.get(key) != value for key, value in cloudflare_runtime.items())
        or payload.get("git_realpath") != git_realpath
        or payload.get("git_sha256") != git_sha256
        or payload.get("container_images_sha256") != container_images_sha256
        or payload.get("container_image_ids") != container_image_ids
    ):
        raise EvidenceError(
            "production preflight evidence inputs changed after the gate ran"
        )

    gate_results = payload.get("gate_results")
    if not isinstance(gate_results, list):
        raise EvidenceError("production preflight evidence gate results are malformed")
    expected_names = [
        step.name
        for step in build_steps(
            args,
            python=str(pathlib.Path(args.host_python)),
            node=str(pathlib.Path(args.node_executable)),
        )
    ]
    actual_names: list[str] = []
    for result in gate_results:
        if not isinstance(result, dict) or set(result) != {
            "name",
            "status",
            "returncode",
        }:
            raise EvidenceError(
                "production preflight evidence gate result is malformed"
            )
        if (
            type(result.get("status")) is not str
            or result.get("status") != "PASS"
            or type(result.get("returncode")) is not int
            or result.get("returncode") != 0
        ):
            raise EvidenceError(
                "production preflight evidence contains a non-passing gate"
            )
        name = result.get("name")
        if not isinstance(name, str):
            raise EvidenceError("production preflight evidence gate name is malformed")
        actual_names.append(name)
    if actual_names != expected_names or len(set(actual_names)) != len(actual_names):
        raise EvidenceError(
            "production preflight evidence does not contain the complete gate set"
        )
    return {
        "schema_version": 1,
        "status": "pass",
        "release_sha": expected_release_sha,
        "fresh": True,
        "inputs_unchanged": True,
        "complete_gate_set": True,
        "container_images_sha256": container_images_sha256,
        "container_image_ids": container_image_ids,
    }


def print_text(results: list[StepResult]) -> None:
    for result in results:
        print(f"{result.status:<4} {result.name} ({result.duration_secs:.1f}s)")
        if result.status == "FAIL":
            print(f"     command: {shlex.join(result.command)}")
            if result.error:
                print(f"     error: {result.error}")
            if result.stdout.strip():
                print("     stdout:")
                for line in result.stdout.strip().splitlines()[-20:]:
                    print(f"       {line}")
            if result.stderr.strip():
                print("     stderr:")
                for line in result.stderr.strip().splitlines()[-20:]:
                    print(f"       {line}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-legacy",
        action="store_true",
        help="Require a fresh exact-account read-only legacy billing containment artifact",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Production env file for deploy readiness checks",
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="Enable production env and Pages binding checks",
    )
    parser.add_argument(
        "--pages-bindings-file",
        help="Cloudflare Pages production bindings/secrets file",
    )
    parser.add_argument(
        "--check-host-python",
        action="store_true",
        help="Verify host Python packages for enabled services",
    )
    parser.add_argument(
        "--host-python", help="Host Python interpreter used by billing services"
    )
    parser.add_argument(
        "--node-executable",
        help="Absolute reviewed Node executable used by production JavaScript gates",
    )
    parser.add_argument(
        "--wrangler-entrypoint",
        help="Absolute reviewed local Wrangler entrypoint used by Cloudflare production gates",
    )
    parser.add_argument(
        "--git-executable",
        help="Absolute reviewed Git executable used for source and remote identity",
    )
    parser.add_argument(
        "--deployment-id",
        default=DEFAULT_DEPLOYMENT_ID,
        help="Stable deployment target identifier bound into one-time evidence",
    )
    parser.add_argument(
        "--live", action="store_true", help="Run public live canaries; use after deploy"
    )
    parser.add_argument(
        "--site-url",
        default="https://tinyzkp.com",
        help="TinyZKP website origin for live checks",
    )
    parser.add_argument(
        "--api-url",
        default="https://api.tinyzkp.com",
        help="TinyZKP API origin for live checks",
    )
    parser.add_argument(
        "--mcp-url",
        default="https://mcp.tinyzkp.com",
        help="TinyZKP MCP origin for live checks",
    )
    parser.add_argument(
        "--webhook-url",
        default="https://webhook.tinyzkp.com",
        help="TinyZKP billing/contact webhook origin for the durable intake canary",
    )
    parser.add_argument(
        "--contact-readiness-secret-file",
        help="Owner-only file containing INTERNAL_SECRET for the live durable intake canary",
    )
    parser.add_argument(
        "--expected-release-sha",
        help="Expected Git SHA for live site/API release identity checks; defaults to TINYZKP_EXPECT_RELEASE_SHA",
    )
    parser.add_argument(
        "--authenticated-smoke",
        action="store_true",
        help="Run authenticated prove/verify smoke using TINYZKP_SMOKE_API_KEY or TINYZKP_AUDIT_API_KEY",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON"
    )
    parser.add_argument(
        "--evidence-output",
        type=pathlib.Path,
        help="Write an owner-only, short-lived production preflight artifact for deploy.sh",
    )
    parser.add_argument(
        "--verify-evidence",
        type=pathlib.Path,
        help="Verify a complete production preflight artifact without rerunning or mutating anything",
    )
    parser.add_argument(
        "--consume-evidence",
        action="store_true",
        help="Atomically consume verified evidence for one deployment attempt",
    )
    args = parser.parse_args(argv)

    if args.production and not args.pages_bindings_file:
        parser.error("--production requires --pages-bindings-file")
    if args.require_legacy and not args.production:
        parser.error("--require-legacy requires --production")
    if args.live and not args.production:
        parser.error("--live requires --production")
    if args.production and not args.host_python:
        parser.error("--production requires --host-python")
    if args.production:
        host_python = pathlib.Path(args.host_python)
        if (
            not host_python.is_absolute()
            or not host_python.is_file()
            or not os.access(host_python, os.X_OK)
        ):
            parser.error("--host-python must be an existing executable absolute path")
        args.check_host_python = True
        for option, value in (
            ("--node-executable", args.node_executable),
            ("--git-executable", args.git_executable),
        ):
            if not value:
                parser.error(f"--production requires {option}")
            executable = pathlib.Path(value)
            if (
                not executable.is_absolute()
                or not executable.is_file()
                or not os.access(executable, os.X_OK)
            ):
                parser.error(f"{option} must be an existing executable absolute path")
        if not args.wrangler_entrypoint:
            parser.error("--production requires --wrangler-entrypoint")
        wrangler_entrypoint = pathlib.Path(args.wrangler_entrypoint)
        if not wrangler_entrypoint.is_absolute() or not wrangler_entrypoint.is_file():
            parser.error(
                "--wrangler-entrypoint must be an existing regular absolute path"
            )
        if DEPLOYMENT_ID.fullmatch(args.deployment_id or "") is None:
            parser.error("--deployment-id is invalid")
    if args.evidence_output and (
        not args.production
        or args.live
        or args.verify_evidence is not None
        or args.consume_evidence
    ):
        parser.error(
            "--evidence-output requires a non-live production preflight and cannot be combined with --verify-evidence"
        )
    if args.verify_evidence and (
        not args.production or args.live or args.evidence_output is not None
    ):
        parser.error(
            "--verify-evidence requires non-live --production and cannot be combined with --evidence-output"
        )
    if args.consume_evidence and args.verify_evidence is None:
        parser.error("--consume-evidence requires --verify-evidence")
    if (args.evidence_output or args.verify_evidence) and RELEASE_SHA.fullmatch(
        (args.expected_release_sha or "").strip()
    ) is None:
        parser.error(
            "preflight evidence requires a canonical 40-character --expected-release-sha"
        )
    if args.evidence_output or args.verify_evidence:
        args.expected_release_sha = args.expected_release_sha.strip()
        evidence_path = args.evidence_output or args.verify_evidence
        if evidence_path != FIXED_EVIDENCE_PATH:
            parser.error(
                f"production evidence path must be exactly {FIXED_EVIDENCE_PATH}"
            )
        if pathlib.Path(args.pages_bindings_file) != FIXED_PAGES_BINDINGS_PATH:
            parser.error(
                "production evidence requires the fixed private Pages bindings path"
            )
    if (args.evidence_output or args.consume_evidence) and pathlib.Path(
        sys.executable
    ).resolve() != pathlib.Path(args.host_python).resolve():
        parser.error(
            "issue production evidence by invoking the exact --host-python interpreter"
        )
    if args.live and not (
        (args.expected_release_sha or "").strip()
        or os.environ.get("TINYZKP_EXPECT_RELEASE_SHA", "").strip()
    ):
        parser.error(
            "--live requires --expected-release-sha (or TINYZKP_EXPECT_RELEASE_SHA)"
        )
    if args.live and not args.contact_readiness_secret_file:
        parser.error("--live requires --contact-readiness-secret-file")

    if args.verify_evidence:
        try:
            report = (
                consume_evidence(args.verify_evidence, args)
                if args.consume_evidence
                else verify_evidence(args.verify_evidence, args)
            )
        except (EvidenceError, ProductionEnvError, OSError) as error:
            print(f"FAIL production preflight evidence: {error}", file=sys.stderr)
            return 1
        print(json.dumps(report, sort_keys=True))
        return 0

    issuance_input_snapshot: dict[str, str] | None = None
    if args.evidence_output:
        try:
            issuance_input_snapshot = validate_evidence_issuance_inputs(args)
            create_evidence_exclusive(
                args.evidence_output,
                placeholder_evidence("in_progress", args.expected_release_sha),
            )
        except (EvidenceError, OSError) as error:
            print(f"FAIL production preflight evidence: {error}", file=sys.stderr)
            return 1

    python_executable = args.host_python if args.production else sys.executable
    node_executable = args.node_executable if args.production else "node"
    steps = build_steps(args, python=python_executable, node=node_executable)
    results = run_steps(steps, production=args.production)
    failures = [result for result in results if result.status != "PASS"]
    evidence_failure: str | None = None
    if args.evidence_output:
        try:
            if failures:
                atomic_write_evidence(
                    args.evidence_output,
                    placeholder_evidence("fail", args.expected_release_sha),
                )
            else:
                atomic_write_evidence(
                    args.evidence_output,
                    build_pass_evidence(
                        args,
                        results,
                        issuance_input_snapshot=issuance_input_snapshot,
                    ),
                )
        except (EvidenceError, ProductionEnvError, OSError) as error:
            evidence_failure = str(error)
            try:
                atomic_write_evidence(
                    args.evidence_output,
                    placeholder_evidence("fail", args.expected_release_sha),
                )
            except Exception:
                pass
            print(f"FAIL production preflight evidence: {error}", file=sys.stderr)

    if args.json:
        print(
            json.dumps(
                {"results": [result_to_json(result) for result in results]}, indent=2
            )
        )
    else:
        print_text(results)
        print()
        print(
            f"Production launch preflight: {len(results) - len(failures)} passed, {len(failures)} failed"
        )
        if args.live and not failures:
            print("Live canaries passed; public launch/announcement gate is clear.")
        elif not args.live:
            print(
                "Live canaries were not run; use --live after deploy before public announcement."
            )

    return 1 if failures or evidence_failure else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
