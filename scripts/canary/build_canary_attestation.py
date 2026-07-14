#!/usr/bin/env python3
"""Build an unsigned canary attestation from semantically validated source evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
from typing import Callable


MODULE_PATH = Path(__file__).with_name("hc_beta_e2e.py")
SPEC = importlib.util.spec_from_file_location("hc_beta_e2e", MODULE_PATH)
assert SPEC and SPEC.loader
E2E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E2E)
VALIDATOR_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def require(value: dict[str, object], expected: dict[str, object], label: str) -> None:
    for field, wanted in expected.items():
        if value.get(field) != wanted:
            raise ValueError(f"{label} requires {field}={wanted!r}")


def validate_stripe(value: dict[str, object], kind: str) -> None:
    require(
        value,
        {
            "status": "passed",
            "kind": kind,
            "livemode": True,
            "synthetic": True,
            "payment_status": "paid",
            "catalog_namespace": "tinyzkp_public_beta_v1",
            "automatic_tax": True,
            "billing_address_collected": True,
            "amount_minor": 2500 if kind == "topup" else 4900,
        },
        "Stripe live-object evidence",
    )


def validate_ledger(value: dict[str, object], kind: str) -> None:
    expected = 25_000 if kind == "topup" else 49_000
    require(
        value,
        {
            "status": "passed",
            "kind": kind,
            "grant_count": 1,
            "reversal_count": 1,
            "granted_millicredits": expected,
            "reversed_millicredits": expected,
            "net_millicredits": 0,
            "semantic_duplicate_outcomes": 0,
            "synthetic": True,
            "excluded_from_revenue": True,
        },
        "credit-ledger evidence",
    )


def validate_refund(value: dict[str, object], _kind: str) -> None:
    require(
        value,
        {
            "status": "passed",
            "refund_succeeded": True,
            "full_refund": True,
            "reversal_applied_once": True,
        },
        "refund-reversal evidence",
    )


def validate_reconciliation(value: dict[str, object], _kind: str | None) -> None:
    require(
        value,
        {
            "status": "clean",
            "unexplained_differences": 0,
            "ledger_reconstruction_differences": 0,
            "pending_events": 0,
        },
        "reconciliation evidence",
    )


def validate_cancellation(value: dict[str, object], _kind: str) -> None:
    require(
        value,
        {"status": "passed", "cancelled": True, "renewal_enabled": False},
        "subscription-cancellation evidence",
    )


def validate_watchdog(value: dict[str, object], _kind: str | None) -> None:
    require(value, {"status": "passed", "violations": []}, "watchdog evidence")


def validate_authorization(value: dict[str, object], _kind: str | None) -> None:
    require(
        value,
        {
            "status": "passed",
            "cross_tenant_bundle_denied": True,
            "successful_unauthorized_accesses": 0,
        },
        "cross-tenant authorization evidence",
    )


def validate_scratch(value: dict[str, object], _kind: str | None) -> None:
    require(
        value,
        {
            "status": "passed",
            "leaked_scratch_directories": 0,
            "unexpected_scratch_entries": 0,
        },
        "worker scratch evidence",
    )


VALIDATORS: dict[str, Callable[[dict[str, object], str | None], None]] = {
    "stripe_live_object": validate_stripe,
    "credit_ledger": validate_ledger,
    "refund_reversal": validate_refund,
    "reconciliation": validate_reconciliation,
    "subscription_cancellation": validate_cancellation,
    "watchdog": validate_watchdog,
    "cross_tenant_authorization": validate_authorization,
    "worker_scratch": validate_scratch,
}


def load_source(path: Path, name: str, release_sha: str, kind: str | None) -> dict[str, object]:
    path = E2E.private_regular_file(path, f"{name} source evidence")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError(f"{name} source evidence has the wrong schema")
    if value.get("release_sha") != release_sha:
        raise ValueError(f"{name} source evidence release SHA does not match")
    E2E.assert_public_evidence(value)
    VALIDATORS[name](value, kind)
    return {
        "name": name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "status": "passed",
        "validator": f"build_canary_attestation.py:{VALIDATORS[name].__name__}",
        "validator_sha256": VALIDATOR_SHA256,
    }


def write_private(path: Path, value: object) -> None:
    if path.is_symlink():
        raise ValueError("output must not be a symlink")
    parent = path.parent.resolve(strict=True)
    details = parent.stat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise ValueError("output directory must be owner-only")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    subcommands = parser.add_subparsers(dest="attestation_type", required=True)
    billing = subcommands.add_parser("billing")
    billing.add_argument("kind", choices=("topup", "subscription"))
    billing.add_argument("--stripe-live-object", type=Path, required=True)
    billing.add_argument("--credit-ledger", type=Path, required=True)
    billing.add_argument("--refund-reversal", type=Path, required=True)
    billing.add_argument("--reconciliation", type=Path, required=True)
    billing.add_argument("--subscription-cancellation", type=Path)
    audit = subcommands.add_parser("audit")
    audit.add_argument("--watchdog", type=Path, required=True)
    audit.add_argument("--cross-tenant-authorization", type=Path, required=True)
    audit.add_argument("--worker-scratch", type=Path, required=True)
    audit.add_argument("--reconciliation", type=Path, required=True)
    args = parser.parse_args()
    release_sha = E2E.canonical_sha(args.release_sha)
    if args.attestation_type == "billing":
        sources = {
            "stripe_live_object": args.stripe_live_object,
            "credit_ledger": args.credit_ledger,
            "refund_reversal": args.refund_reversal,
            "reconciliation": args.reconciliation,
        }
        if args.kind == "subscription":
            if args.subscription_cancellation is None:
                raise SystemExit("subscription billing evidence requires --subscription-cancellation")
            sources["subscription_cancellation"] = args.subscription_cancellation
        value: dict[str, object] = {
            "schema_version": 1,
            "release_sha": release_sha,
            "attestation_type": "billing",
            "kind": args.kind,
            "status": "passed",
            "synthetic": True,
            "refunded": True,
            "excluded_from_revenue": True,
            "cancelled": args.kind == "subscription",
            "source_evidence": [
                load_source(path, name, release_sha, args.kind)
                for name, path in sources.items()
            ],
        }
    else:
        sources = {
            "watchdog": args.watchdog,
            "cross_tenant_authorization": args.cross_tenant_authorization,
            "worker_scratch": args.worker_scratch,
            "reconciliation": args.reconciliation,
        }
        value = {
            "schema_version": 1,
            "release_sha": release_sha,
            "attestation_type": "audit",
            "status": "passed",
            **{field: 0 for field in E2E.ATTESTATION_ZERO_FIELDS},
            "source_evidence": [
                load_source(path, name, release_sha, None)
                for name, path in sources.items()
            ],
        }
    write_private(args.output, value)


if __name__ == "__main__":
    main()
