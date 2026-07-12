#!/usr/bin/env python3
"""Prepare, collect, reconcile, destroy, and verify the beta Stripe drill.

This operator deliberately keeps the browser-driven Stripe Checkout actions
outside the evidence file.  ``run`` consumes owner-only observations produced
by those real test-mode actions and verifies them against the disposable
PostgreSQL ledger before it writes release evidence.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
from typing import Any


SCHEMA = "stripe-sandbox-drill-v1"
STRIPE_API_VERSION = "2026-02-25.clover"
STRIPE_CLI_VERSION = "stripe version 1.43.7"
DATABASE_PREFIX = "tinyzkp_beta_stripe_drill_"
CASE_IDS = (
    "topup_card_once",
    "topup_async_success",
    "subscription_invoice_paid_only",
    "subscription_renewal_and_expiry",
    "payment_failure_and_recovery",
    "portal_cancel_at_period_end",
    "refund_full",
    "refund_partial",
    "refund_async_success",
    "refund_async_failure",
    "refund_after_consumption",
    "duplicate_event_delivery",
    "changed_payload_conflict",
    "semantic_duplicate_event",
    "reversed_event_order",
    "simultaneous_delivery",
)
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_DATABASE = re.compile(r"^tinyzkp_beta_stripe_drill_[0-9a-f]{12}$")
# Clover returns Payment Records (``pyr_``) for the current refund object,
# while older test fixtures and retained evidence can still use ``re_``.
STRIPE_ID = re.compile(r"^(acct|cus|cs|evt|in|pi|ch|re|pyr|sub|price|prod|bpc)_[A-Za-z0-9_]+$")
FORBIDDEN_KEY = re.compile(
    r"(secret|password|api.?key|cookie|authorization|checkout.?url|portal.?url|presigned|card.?number)",
    re.I,
)
FORBIDDEN_VALUE = re.compile(
    r"(sk_(?:test|live)_|rk_(?:test|live)_|whsec_|__Host-tinyzkp|X-Amz-Signature=|"
    r"tinyzkp_beta_[A-Za-z0-9_-]{40,}|\b(?:4000|4242)[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b)",
    re.I,
)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_private_json(path: Path) -> Any:
    if path.is_symlink():
        raise ValueError(f"{path} must not be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        details = os.fstat(handle.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid():
            raise ValueError(f"{path} must be an operator-owned regular file")
        if stat.S_IMODE(details.st_mode) & 0o077:
            raise ValueError(f"{path} must be owner-only")
        raw = handle.read(2 * 1024 * 1024 + 1)
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise ValueError(f"{path} is empty or oversized")
    return json.loads(raw, object_pairs_hook=reject_duplicate_keys)


def write_private_json(path: Path, value: Any, *, replace: bool = False) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists() and not replace:
        raise ValueError(f"refusing to replace {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True).encode() + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def reject_secrets(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if FORBIDDEN_KEY.search(str(key)) or str(key).startswith("http") or "X-Amz-" in str(key):
                raise ValueError(f"secret-like evidence field is forbidden: {path}.{key}")
            reject_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secrets(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if FORBIDDEN_VALUE.search(value) or (value.startswith("http") and "?" in value):
            raise ValueError(f"secret-like evidence value is forbidden: {path}")


def validate_case(value: Any, expected_id: str) -> dict[str, Any]:
    fields = {"id", "status", "object_ids", "event_ids", "assertions"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{expected_id}: case fields are missing or unknown")
    if value["id"] != expected_id or value["status"] != "passed":
        raise ValueError(f"{expected_id}: case did not pass")
    if not isinstance(value["object_ids"], list) or not all(
        isinstance(item, str) and STRIPE_ID.fullmatch(item) for item in value["object_ids"]
    ):
        raise ValueError(f"{expected_id}: malformed Stripe object IDs")
    if not isinstance(value["event_ids"], list) or not all(
        isinstance(item, str) and item.startswith("evt_") for item in value["event_ids"]
    ):
        raise ValueError(f"{expected_id}: malformed Stripe event IDs")
    assertions = value["assertions"]
    if not isinstance(assertions, dict) or not assertions or any(item is not True for item in assertions.values()):
        raise ValueError(f"{expected_id}: assertions must be non-empty and true")
    return value


def validate_evidence(value: Any, expected_sha: str | None = None) -> dict[str, Any]:
    fields = {
        "schema_version", "status", "release_sha", "stripe_api_version",
        "stripe_cli", "livemode", "database", "started_at", "completed_at",
        "cases", "reconciliation", "operation_digest",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Stripe drill evidence fields are missing or unknown")
    if value["schema_version"] != SCHEMA or value["status"] != "passed":
        raise ValueError("Stripe drill evidence is not a passing v1 record")
    release_sha = value["release_sha"]
    if not isinstance(release_sha, str) or not GIT_SHA.fullmatch(release_sha):
        raise ValueError("release SHA is malformed")
    if expected_sha is not None and release_sha != expected_sha:
        raise ValueError("release SHA does not match the candidate")
    if value["stripe_api_version"] != STRIPE_API_VERSION or value["stripe_cli"] != STRIPE_CLI_VERSION:
        raise ValueError("Stripe API or CLI version drifted")
    if value["livemode"] is not False or not SAFE_DATABASE.fullmatch(str(value["database"])):
        raise ValueError("drill must use the disposable test database and test mode")
    cases = value["cases"]
    if not isinstance(cases, list) or [item.get("id") for item in cases if isinstance(item, dict)] != list(CASE_IDS):
        raise ValueError("Stripe drill case set or order is incomplete")
    for expected, item in zip(CASE_IDS, cases, strict=True):
        validate_case(item, expected)
    reconciliation = value["reconciliation"]
    if not isinstance(reconciliation, dict) or set(reconciliation) != {
        "status", "unexplained_differences", "ledger_mismatches", "report_sha256", "report_hmac_sha256"
    }:
        raise ValueError("reconciliation evidence is malformed")
    if reconciliation["status"] != "passed" or reconciliation["unexplained_differences"] != 0 or reconciliation["ledger_mismatches"] != 0:
        raise ValueError("Stripe reconciliation is not clean")
    if not SHA256.fullmatch(str(reconciliation["report_sha256"])) or not SHA256.fullmatch(str(reconciliation["report_hmac_sha256"])):
        raise ValueError("reconciliation digests are malformed")
    if not SHA256.fullmatch(str(value["operation_digest"])):
        raise ValueError("operation digest is malformed")
    reject_secrets(value)
    return value


def _psycopg() -> tuple[Any, Any, Any]:
    try:
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
    except ImportError as error:
        raise RuntimeError("psycopg 3 is required for drill database actions") from error
    return psycopg, sql, (conninfo_to_dict, make_conninfo)


def target_dsn(admin_dsn: str, database: str) -> str:
    _, _, helpers = _psycopg()
    conninfo_to_dict, make_conninfo = helpers
    parameters = conninfo_to_dict(admin_dsn)
    parameters["dbname"] = database
    return make_conninfo(**parameters)


def create_database(admin_dsn: str, database: str) -> None:
    psycopg, sql, _ = _psycopg()
    if not SAFE_DATABASE.fullmatch(database):
        raise ValueError("unsafe drill database name")
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        exists = connection.execute("SELECT 1 FROM pg_database WHERE datname=%s", (database,)).fetchone()
        if exists:
            raise ValueError("drill database already exists")
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))


def drop_database(admin_dsn: str, database: str) -> None:
    psycopg, sql, _ = _psycopg()
    if not SAFE_DATABASE.fullmatch(database):
        raise ValueError("unsafe drill database name")
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        connection.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s AND pid<>pg_backend_pid()",
            (database,),
        )
        connection.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(database)))


def migrate_and_seed(dsn: str, release_sha: str, state_dir: Path) -> None:
    psycopg, _, _ = _psycopg()
    root = Path(__file__).resolve().parents[1]
    pepper = secrets.token_bytes(32)
    raw_keys: dict[str, str] = {}
    tenants = ("topup", "subscription", "refund", "consumed")
    with psycopg.connect(dsn) as connection:
        for migration in sorted((root / "crates" / "hc-beta-api" / "migrations").glob("*.sql")):
            connection.execute(migration.read_text(encoding="utf-8"))
        for label in tenants:
            tenant = f"tenant_stripe_drill_{label}_{release_sha[:12]}"
            raw = "tinyzkp_beta_" + secrets.token_urlsafe(32)
            digest = hmac.new(pepper, raw.encode(), hashlib.sha256).hexdigest()
            prefix = raw[:14]
            connection.execute(
                "INSERT INTO tenants (tenant_id,status,plan,created_at_ms,updated_at_ms) VALUES (%s,'active','builder',0,0)",
                (tenant,),
            )
            connection.execute("INSERT INTO beta_credit_accounts (tenant_id) VALUES (%s)", (tenant,))
            connection.execute(
                "INSERT INTO beta_api_keys (api_key_id,tenant_id,key_hash,key_prefix,label) VALUES (gen_random_uuid(),%s,%s,%s,'stripe drill')",
                (tenant, digest, prefix),
            )
            raw_keys[label] = raw
        connection.commit()
    credentials = state_dir / "credentials.env"
    descriptor = os.open(credentials, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("TINYZKP_SECRET_PEPPER=" + base64.b64encode(pepper).decode() + "\n")
        for label, raw in raw_keys.items():
            handle.write(f"TINYZKP_STRIPE_DRILL_{label.upper()}_API_KEY={raw}\n")


def collect_database_evidence(
    dsn: str, database: str, release_sha: str, cases: list[dict[str, Any]]
) -> dict[str, Any]:
    psycopg, _, _ = _psycopg()
    expected_events = {
        event_id for case in cases for event_id in case.get("event_ids", [])
    }
    with psycopg.connect(dsn) as connection:
        current_database = connection.execute("SELECT current_database()").fetchone()[0]
        if current_database != database:
            raise ValueError("database URL does not target the prepared drill database")
        rows = connection.execute(
            "SELECT stripe_event_id,processing_status FROM beta_stripe_events WHERE livemode=false"
        ).fetchall()
        event_status = {str(row[0]): str(row[1]) for row in rows}
        missing = sorted(expected_events - set(event_status))
        unprocessed = sorted(
            event_id for event_id in expected_events if event_status.get(event_id) != "processed"
        )
        if missing or unprocessed:
            raise ValueError(
                f"observed Stripe events are not durably processed: missing={missing}, unprocessed={unprocessed}"
            )
        queue_depth = connection.execute(
            "SELECT count(*) FROM beta_stripe_events WHERE processing_status<>'processed'"
        ).fetchone()[0]
        if queue_depth != 0:
            raise ValueError("Stripe event queue is not drained")
        ledger_mismatches = connection.execute(
            """
            WITH totals AS (
              SELECT tenant_id,
                     coalesce(sum(subscription_delta_millicredits),0) subscription_total,
                     coalesce(sum(purchased_delta_millicredits),0) purchased_total,
                     coalesce(sum(reserved_delta_millicredits),0) reserved_total
                FROM beta_credit_events GROUP BY tenant_id
            )
            SELECT count(*) FROM beta_credit_accounts a
            FULL JOIN totals t USING (tenant_id)
            WHERE coalesce(a.subscription_millicredits,0)<>coalesce(t.subscription_total,0)
               OR coalesce(a.purchased_millicredits,0)<>coalesce(t.purchased_total,0)
               OR coalesce(a.reserved_millicredits,0)<>coalesce(t.reserved_total,0)
            """
        ).fetchone()[0]
        unexplained = connection.execute(
            "SELECT count(*) FROM beta_billing_discrepancies WHERE resolved_at IS NULL"
        ).fetchone()[0]
        reconciliation = connection.execute(
            "SELECT status,report_sha256,report_hmac_sha256 FROM beta_reconciliation_runs "
            "WHERE release_sha=%s ORDER BY completed_at DESC NULLS LAST LIMIT 1",
            (release_sha,),
        ).fetchone()
        if reconciliation is None or reconciliation[0] != "clean":
            raise ValueError("latest exact-release reconciliation is not clean")
        grant_count = connection.execute("SELECT count(*) FROM beta_credit_grants").fetchone()[0]
        refund_count = connection.execute("SELECT count(*) FROM beta_refunds").fetchone()[0]
        if grant_count < 4 or refund_count < 4:
            raise ValueError("Stripe drill did not produce the required grants and refunds")
    return {
        "status": "passed",
        "unexplained_differences": int(unexplained),
        "ledger_mismatches": int(ledger_mismatches),
        "report_sha256": str(reconciliation[1]),
        "report_hmac_sha256": str(reconciliation[2]),
    }


def prepare(args: argparse.Namespace) -> None:
    release_sha = args.release_sha
    if not GIT_SHA.fullmatch(release_sha):
        raise ValueError("release SHA must be a full lowercase Git commit")
    database = DATABASE_PREFIX + release_sha[:12]
    args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(args.state_dir, 0o700)
    create_database(args.admin_dsn, database)
    try:
        migrate_and_seed(target_dsn(args.admin_dsn, database), release_sha, args.state_dir)
        write_private_json(
            args.state_dir / "state.json",
            {
                "schema_version": SCHEMA,
                "release_sha": release_sha,
                "database": database,
                "started_at": now(),
                "phase": "prepared",
                "required_cases": list(CASE_IDS),
            },
        )
    except Exception:
        drop_database(args.admin_dsn, database)
        raise
    print(json.dumps({"status": "prepared", "database": database, "state_dir": str(args.state_dir)}))


def run(args: argparse.Namespace) -> None:
    state_path = args.state_dir / "state.json"
    state = read_private_json(state_path)
    observations = read_private_json(args.observations)
    cases = observations.get("cases") if isinstance(observations, dict) else None
    if not isinstance(cases, list):
        raise ValueError("observations do not contain cases")
    for expected, item in zip(CASE_IDS, cases, strict=True):
        validate_case(item, expected)
    reconciliation = collect_database_evidence(
        args.database_url, state["database"], state["release_sha"], cases
    )
    evidence = {
        "schema_version": SCHEMA,
        "status": "passed",
        "release_sha": state["release_sha"],
        "stripe_api_version": STRIPE_API_VERSION,
        "stripe_cli": STRIPE_CLI_VERSION,
        "livemode": False,
        "database": state["database"],
        "started_at": state["started_at"],
        "completed_at": observations.get("completed_at", now()),
        "cases": cases,
        "reconciliation": reconciliation,
        "operation_digest": hashlib.sha256(canonical(cases)).hexdigest(),
    }
    validate_evidence(evidence, state["release_sha"])
    write_private_json(args.output, evidence)
    state["phase"] = "evidence_written"
    state["evidence_sha256"] = hashlib.sha256(canonical(evidence)).hexdigest()
    write_private_json(state_path, state, replace=True)
    print(json.dumps({"status": "passed", "evidence": str(args.output)}))


def reconcile(args: argparse.Namespace) -> None:
    evidence = validate_evidence(read_private_json(args.evidence), args.release_sha)
    print(json.dumps({"status": "passed", "report_sha256": evidence["reconciliation"]["report_sha256"]}))


def destroy(args: argparse.Namespace) -> None:
    state = read_private_json(args.state_dir / "state.json")
    if state.get("phase") != "evidence_written" and not args.force:
        raise ValueError("refusing to destroy a drill without validated evidence")
    drop_database(args.admin_dsn, str(state["database"]))
    credentials = args.state_dir / "credentials.env"
    if credentials.exists() and not credentials.is_symlink():
        credentials.unlink()
    state["phase"] = "destroyed"
    state["destroyed_at"] = now()
    write_private_json(args.state_dir / "state.json", state, replace=True)
    print(json.dumps({"status": "destroyed", "database": state["database"]}))


def verify(args: argparse.Namespace) -> None:
    evidence = validate_evidence(read_private_json(args.evidence), args.release_sha)
    print(json.dumps({"status": "passed", "operation_digest": evidence["operation_digest"]}))


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--admin-dsn", required=True)
    prepare_parser.add_argument("--release-sha", required=True)
    prepare_parser.add_argument("--state-dir", type=Path, required=True)
    prepare_parser.set_defaults(handler=prepare)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--state-dir", type=Path, required=True)
    run_parser.add_argument("--observations", type=Path, required=True)
    run_parser.add_argument("--database-url", required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.set_defaults(handler=run)
    reconcile_parser = subparsers.add_parser("reconcile")
    reconcile_parser.add_argument("--evidence", type=Path, required=True)
    reconcile_parser.add_argument("--release-sha", required=True)
    reconcile_parser.set_defaults(handler=reconcile)
    destroy_parser = subparsers.add_parser("destroy")
    destroy_parser.add_argument("--admin-dsn", required=True)
    destroy_parser.add_argument("--state-dir", type=Path, required=True)
    destroy_parser.add_argument("--force", action="store_true")
    destroy_parser.set_defaults(handler=destroy)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--evidence", type=Path, required=True)
    verify_parser.add_argument("--release-sha", required=True)
    verify_parser.set_defaults(handler=verify)
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
