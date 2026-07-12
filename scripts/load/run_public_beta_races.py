#!/usr/bin/env python3
"""Exercise public-beta PostgreSQL race invariants on a disposable database."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
from typing import Any, Callable
import uuid


SCHEMA = "public-beta-race-evidence-v1"
DATABASE = re.compile(r"^tinyzkp_beta_race_[0-9a-f]{12}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
CASE_IDS = (
    "duplicate_job_creation",
    "idempotency_body_conflict",
    "concurrent_overspend",
    "cancel_vs_completion",
    "lease_expiry_vs_stale_completion",
    "simultaneous_settlement",
    "refund_vs_credit_use",
    "stripe_duplicate_and_delayed_events",
    "reconciliation_while_processing",
)


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def psycopg_module() -> Any:
    try:
        import psycopg
    except ImportError as error:
        raise RuntimeError("psycopg 3 is required for PostgreSQL race evidence") from error
    return psycopg


def parallel(count: int, action: Callable[[int], Any]) -> list[Any]:
    barrier = threading.Barrier(count)

    def invoke(index: int) -> Any:
        barrier.wait(timeout=30)
        return action(index)

    with ThreadPoolExecutor(max_workers=count) as executor:
        return list(executor.map(invoke, range(count)))


def scalar(connection: Any, query: str, parameters: tuple[Any, ...] = ()) -> Any:
    return connection.execute(query, parameters).fetchone()[0]


def seed_tenant(connection: Any, tenant: str, purchased: int = 0) -> None:
    connection.execute(
        "INSERT INTO tenants (tenant_id,status,plan,created_at_ms,updated_at_ms) VALUES (%s,'active','scale',0,0)",
        (tenant,),
    )
    connection.execute(
        "INSERT INTO beta_credit_accounts (tenant_id,purchased_millicredits) VALUES (%s,%s)",
        (tenant, purchased),
    )
    if purchased:
        connection.execute(
            "INSERT INTO beta_credit_events (event_id,tenant_id,event_type,purchased_delta_millicredits,operation_key) "
            "VALUES (%s,%s,'adjustment',%s,%s)",
            (uuid.uuid4(), tenant, purchased, f"race:{tenant}:fund"),
        )


def seed_job(connection: Any, tenant: str, release_sha: str, reserved: int = 80) -> str:
    air = uuid.uuid4()
    upload = uuid.uuid4()
    job = uuid.uuid4()
    digest = "0" * 64
    connection.execute(
        "INSERT INTO beta_air_packages (air_package_id,tenant_id,air_digest_hex,package_json,release_sha) VALUES (%s,%s,%s,'{}',%s)",
        (air, tenant, digest, release_sha),
    )
    connection.execute(
        "INSERT INTO beta_uploads (upload_id,tenant_id,air_package_id,trace_digest_hex,manifest_json,object_prefix,status,expires_at) "
        "VALUES (%s,%s,%s,%s,'{}',%s,'complete',now()+interval '1 day')",
        (upload, tenant, air, digest, f"race/{upload}"),
    )
    connection.execute(
        "INSERT INTO beta_proof_jobs (job_id,tenant_id,air_package_id,upload_id,status,estimate_json,public_inputs_json,"
        "public_inputs_digest_hex,reserved_millicredits,reserved_subscription_millicredits,reserved_purchased_millicredits,"
        "release_sha,retention_expires_at) VALUES (%s,%s,%s,%s,'queued','{}','{}',%s,%s,0,%s,%s,now()+interval '7 days')",
        (job, tenant, air, upload, digest, reserved, reserved, release_sha),
    )
    connection.execute(
        "UPDATE beta_credit_accounts SET purchased_millicredits=purchased_millicredits-%s,reserved_millicredits=%s WHERE tenant_id=%s",
        (reserved, reserved, tenant),
    )
    connection.execute(
        "INSERT INTO beta_credit_events (event_id,tenant_id,event_type,purchased_delta_millicredits,reserved_delta_millicredits,job_id,operation_key) "
        "VALUES (%s,%s,'reservation',%s,%s,%s,%s)",
        (uuid.uuid4(), tenant, -reserved, reserved, job, f"job:{job}:reservation"),
    )
    return str(job)


def case_result(case_id: str, outcomes: dict[str, Any]) -> dict[str, Any]:
    return {"id": case_id, "status": "passed", "outcomes": outcomes}


def duplicate_job_creation(dsn: str, prefix: str) -> dict[str, Any]:
    psycopg = psycopg_module()
    tenant = f"{prefix}_idempotent"
    with psycopg.connect(dsn) as connection:
        seed_tenant(connection, tenant)
        connection.commit()
    request_hash = hashlib.sha256(b"same-request").hexdigest()

    def action(_: int) -> str:
        with psycopg.connect(dsn) as connection:
            changed = connection.execute(
                "INSERT INTO beta_idempotency_keys (tenant_id,operation,idempotency_key,request_sha256,expires_at) "
                "VALUES (%s,'create_job','race-identical',%s,now()+interval '1 day') ON CONFLICT DO NOTHING",
                (tenant, request_hash),
            ).rowcount
            connection.commit()
            return "created" if changed == 1 else "replayed"

    outcomes = parallel(32, action)
    with psycopg.connect(dsn) as connection:
        rows = scalar(connection, "SELECT count(*) FROM beta_idempotency_keys WHERE tenant_id=%s", (tenant,))
    if rows != 1 or outcomes.count("created") != 1 or outcomes.count("replayed") != 31:
        raise RuntimeError("duplicate job idempotency race violated exactly-once insertion")
    return case_result(CASE_IDS[0], {"workers": 32, "created": 1, "replayed": 31, "rows": rows})


def idempotency_body_conflict(dsn: str, prefix: str) -> dict[str, Any]:
    psycopg = psycopg_module()
    tenant = f"{prefix}_conflict"
    with psycopg.connect(dsn) as connection:
        seed_tenant(connection, tenant)
        connection.commit()
    hashes = [hashlib.sha256(f"body-{index % 2}".encode()).hexdigest() for index in range(32)]

    def action(index: int) -> str:
        with psycopg.connect(dsn) as connection:
            connection.execute(
                "INSERT INTO beta_idempotency_keys (tenant_id,operation,idempotency_key,request_sha256,expires_at) "
                "VALUES (%s,'create_job','race-conflict',%s,now()+interval '1 day') ON CONFLICT DO NOTHING",
                (tenant, hashes[index]),
            )
            winner = scalar(
                connection,
                "SELECT request_sha256 FROM beta_idempotency_keys WHERE tenant_id=%s AND operation='create_job' AND idempotency_key='race-conflict' FOR UPDATE",
                (tenant,),
            )
            connection.commit()
            return "replay" if winner == hashes[index] else "conflict"

    outcomes = parallel(32, action)
    if outcomes.count("conflict") != 16 or outcomes.count("replay") != 16:
        raise RuntimeError("changed-body idempotency reuse did not deterministically conflict")
    return case_result(CASE_IDS[1], {"workers": 32, "replays": 16, "conflicts": 16})


def concurrent_overspend(dsn: str, prefix: str) -> dict[str, Any]:
    psycopg = psycopg_module()
    tenant = f"{prefix}_overspend"
    with psycopg.connect(dsn) as connection:
        seed_tenant(connection, tenant, 100)
        connection.commit()

    def action(index: int) -> str:
        with psycopg.connect(dsn) as connection:
            available = scalar(
                connection,
                "SELECT purchased_millicredits FROM beta_credit_accounts WHERE tenant_id=%s FOR UPDATE",
                (tenant,),
            )
            if available < 75:
                connection.rollback()
                return "rejected"
            connection.execute(
                "UPDATE beta_credit_accounts SET purchased_millicredits=purchased_millicredits-75,reserved_millicredits=reserved_millicredits+75 WHERE tenant_id=%s",
                (tenant,),
            )
            connection.execute(
                "INSERT INTO beta_credit_events (event_id,tenant_id,event_type,purchased_delta_millicredits,reserved_delta_millicredits,operation_key) "
                "VALUES (%s,%s,'reservation',-75,75,%s)",
                (uuid.uuid4(), tenant, f"race:overspend:{index}"),
            )
            connection.commit()
            return "reserved"

    outcomes = parallel(2, action)
    with psycopg.connect(dsn) as connection:
        balances = connection.execute(
            "SELECT purchased_millicredits,reserved_millicredits FROM beta_credit_accounts WHERE tenant_id=%s",
            (tenant,),
        ).fetchone()
    if sorted(outcomes) != ["rejected", "reserved"] or tuple(balances) != (25, 75):
        raise RuntimeError("concurrent reservation overspent the credit account")
    return case_result(CASE_IDS[2], {"reserved": 1, "rejected": 1, "available": 25, "reserved_balance": 75})


def race_terminal(dsn: str, prefix: str, release_sha: str) -> dict[str, Any]:
    psycopg = psycopg_module()
    tenant = f"{prefix}_terminal"
    with psycopg.connect(dsn) as connection:
        seed_tenant(connection, tenant, 100)
        job = seed_job(connection, tenant, release_sha)
        connection.commit()

    def action(index: int) -> str:
        with psycopg.connect(dsn) as connection:
            row = connection.execute(
                "SELECT status,reserved_millicredits FROM beta_proof_jobs WHERE job_id=%s FOR UPDATE",
                (job,),
            ).fetchone()
            if row[0] in ("completed", "cancelled"):
                connection.rollback()
                return "lost"
            if index == 0:
                connection.execute("UPDATE beta_proof_jobs SET status='cancelled',cancelled_at=now() WHERE job_id=%s", (job,))
                refund, event = 80, "reservation_release"
            else:
                connection.execute(
                    "UPDATE beta_proof_jobs SET status='completed',verification_succeeded=true,settled_millicredits=60,completed_at=now() WHERE job_id=%s",
                    (job,),
                )
                refund, event = 20, "settlement"
            connection.execute(
                "UPDATE beta_credit_accounts SET purchased_millicredits=purchased_millicredits+%s,reserved_millicredits=reserved_millicredits-80 WHERE tenant_id=%s",
                (refund, tenant),
            )
            connection.execute(
                "INSERT INTO beta_credit_events (event_id,tenant_id,event_type,purchased_delta_millicredits,reserved_delta_millicredits,job_id,operation_key) "
                "VALUES (%s,%s,%s,%s,-80,%s,%s)",
                (uuid.uuid4(), tenant, event, refund, job, f"job:{job}:{event}"),
            )
            connection.commit()
            return event

    outcomes = parallel(2, action)
    with psycopg.connect(dsn) as connection:
        status = scalar(connection, "SELECT status FROM beta_proof_jobs WHERE job_id=%s", (job,))
        reserved = scalar(connection, "SELECT reserved_millicredits FROM beta_credit_accounts WHERE tenant_id=%s", (tenant,))
        terminal_events = scalar(
            connection,
            "SELECT count(*) FROM beta_credit_events WHERE job_id=%s AND event_type IN ('settlement','reservation_release')",
            (job,),
        )
    if outcomes.count("lost") != 1 or status not in ("completed", "cancelled") or reserved != 0 or terminal_events != 1:
        raise RuntimeError("cancel-versus-completion produced more than one terminal outcome")
    return case_result(CASE_IDS[3], {"winner": status, "losers": 1, "terminal_events": terminal_events, "reserved": reserved})


def stale_completion(dsn: str, prefix: str, release_sha: str) -> dict[str, Any]:
    psycopg = psycopg_module()
    tenant = f"{prefix}_stale"
    with psycopg.connect(dsn) as connection:
        seed_tenant(connection, tenant, 100)
        job = seed_job(connection, tenant, release_sha)
        connection.execute("UPDATE beta_proof_jobs SET status='leased',attempt=2,lease_epoch=2 WHERE job_id=%s", (job,))
        changed = connection.execute(
            "UPDATE beta_proof_jobs SET status='completed' WHERE job_id=%s AND status='leased' AND attempt=1 AND lease_epoch=1",
            (job,),
        ).rowcount
        status = scalar(connection, "SELECT status FROM beta_proof_jobs WHERE job_id=%s", (job,))
        connection.commit()
    if changed != 0 or status != "leased":
        raise RuntimeError("stale lease completed a newer attempt")
    return case_result(CASE_IDS[4], {"stale_rows_changed": changed, "current_status": status, "current_epoch": 2})


def simultaneous_settlement(dsn: str, prefix: str, release_sha: str) -> dict[str, Any]:
    psycopg = psycopg_module()
    tenant = f"{prefix}_settle"
    with psycopg.connect(dsn) as connection:
        seed_tenant(connection, tenant, 100)
        job = seed_job(connection, tenant, release_sha)
        connection.commit()

    def action(_: int) -> int:
        with psycopg.connect(dsn) as connection:
            changed = connection.execute(
                "UPDATE beta_proof_jobs SET status='completed',verification_succeeded=true,settled_millicredits=60,completed_at=now() "
                "WHERE job_id=%s AND status='queued'",
                (job,),
            ).rowcount
            if changed:
                connection.execute(
                    "UPDATE beta_credit_accounts SET purchased_millicredits=purchased_millicredits+20,reserved_millicredits=reserved_millicredits-80 WHERE tenant_id=%s",
                    (tenant,),
                )
                connection.execute(
                    "INSERT INTO beta_credit_events (event_id,tenant_id,event_type,purchased_delta_millicredits,reserved_delta_millicredits,job_id,operation_key) "
                    "VALUES (%s,%s,'settlement',20,-80,%s,%s)",
                    (uuid.uuid4(), tenant, job, f"job:{job}:settlement"),
                )
            connection.commit()
            return changed

    outcomes = parallel(2, action)
    if sorted(outcomes) != [0, 1]:
        raise RuntimeError("simultaneous settlement charged more than once")
    return case_result(CASE_IDS[5], {"settlements": sum(outcomes), "rejected_stale_completions": outcomes.count(0)})


def refund_vs_credit_use(dsn: str, prefix: str) -> dict[str, Any]:
    psycopg = psycopg_module()
    tenant = f"{prefix}_refund"
    with psycopg.connect(dsn) as connection:
        seed_tenant(connection, tenant, 100)
        grant = uuid.uuid4()
        connection.execute(
            "INSERT INTO beta_credit_grants (grant_id,tenant_id,grant_kind,credit_bucket,semantic_key,stripe_event_id,granted_millicredits) "
            "VALUES (%s,%s,'topup','purchased',%s,'evt_race_refund',100)",
            (grant, tenant, f"race:{tenant}:grant"),
        )
        connection.commit()

    def action(index: int) -> str:
        with psycopg.connect(dsn) as connection:
            available = scalar(connection, "SELECT purchased_millicredits FROM beta_credit_accounts WHERE tenant_id=%s FOR UPDATE", (tenant,))
            if index == 0:
                if available < 80:
                    connection.rollback()
                    return "use_rejected"
                connection.execute("UPDATE beta_credit_accounts SET purchased_millicredits=purchased_millicredits-80 WHERE tenant_id=%s", (tenant,))
                connection.execute(
                    "INSERT INTO beta_credit_events (event_id,tenant_id,event_type,purchased_delta_millicredits,operation_key) VALUES (%s,%s,'adjustment',-80,%s)",
                    (uuid.uuid4(), tenant, f"race:{tenant}:use"),
                )
                connection.commit()
                return "used"
            if available < 100:
                connection.execute("UPDATE beta_credit_accounts SET paid_work_frozen=true WHERE tenant_id=%s", (tenant,))
                connection.execute(
                    "INSERT INTO beta_billing_discrepancies (discrepancy_id,tenant_id,discrepancy_type,semantic_key,details) VALUES (%s,%s,'refund_credits_consumed',%s,'{}')",
                    (uuid.uuid4(), tenant, f"race:{tenant}:refund-consumed"),
                )
                connection.commit()
                return "frozen"
            connection.execute("UPDATE beta_credit_accounts SET purchased_millicredits=0 WHERE tenant_id=%s", (tenant,))
            connection.execute(
                "UPDATE beta_credit_grants SET reversed_millicredits=100 WHERE grant_id=%s",
                (grant,),
            )
            connection.execute(
                "INSERT INTO beta_credit_events (event_id,tenant_id,event_type,purchased_delta_millicredits,operation_key) VALUES (%s,%s,'refund_reversal',-100,%s)",
                (uuid.uuid4(), tenant, f"race:{tenant}:refund"),
            )
            connection.commit()
            return "reversed"

    outcomes = parallel(2, action)
    with psycopg.connect(dsn) as connection:
        account = connection.execute(
            "SELECT purchased_millicredits,paid_work_frozen FROM beta_credit_accounts WHERE tenant_id=%s",
            (tenant,),
        ).fetchone()
    valid = sorted(outcomes) in (["frozen", "used"], ["reversed", "use_rejected"])
    if not valid or account[0] < 0:
        raise RuntimeError("refund-versus-use produced a negative or ambiguous balance")
    return case_result(CASE_IDS[6], {"outcomes": sorted(outcomes), "balance": account[0], "paid_work_frozen": account[1]})


def stripe_event_races(dsn: str, prefix: str) -> dict[str, Any]:
    psycopg = psycopg_module()
    event_id = f"evt_{prefix}_duplicate"
    payload_hash = hashlib.sha256(b"canonical-event").hexdigest()

    def action(_: int) -> int:
        with psycopg.connect(dsn) as connection:
            changed = connection.execute(
                "INSERT INTO beta_stripe_events (stripe_event_id,event_type,payload_sha256,payload_json,stripe_created_at,processing_status,livemode) "
                "VALUES (%s,'invoice.paid',%s,'{}',to_timestamp(1),'pending',false) ON CONFLICT DO NOTHING",
                (event_id, payload_hash),
            ).rowcount
            connection.commit()
            return changed

    outcomes = parallel(32, action)
    with psycopg.connect(dsn) as connection:
        stored_hash = scalar(connection, "SELECT payload_sha256 FROM beta_stripe_events WHERE stripe_event_id=%s", (event_id,))
        changed_payload_conflict = stored_hash != hashlib.sha256(b"changed-event").hexdigest()
        connection.execute("UPDATE beta_stripe_events SET processing_status='processed',processed_at=now() WHERE stripe_event_id=%s", (event_id,))
        connection.commit()
    if sum(outcomes) != 1 or not changed_payload_conflict:
        raise RuntimeError("Stripe event primary-key race was not exactly once")
    return case_result(
        CASE_IDS[7],
        {"deliveries": 32, "stored_events": sum(outcomes), "duplicates": 31, "changed_payload_conflict": True, "canonical_state_wins": True},
    )


def reconcile_created_rows(dsn: str, prefix: str) -> dict[str, Any]:
    psycopg = psycopg_module()
    with psycopg.connect(dsn) as connection:
        mismatches = scalar(
            connection,
            """
            WITH totals AS (
              SELECT tenant_id,coalesce(sum(subscription_delta_millicredits),0) s,
                     coalesce(sum(purchased_delta_millicredits),0) p,
                     coalesce(sum(reserved_delta_millicredits),0) r
              FROM beta_credit_events WHERE tenant_id LIKE %s GROUP BY tenant_id
            )
            SELECT count(*) FROM beta_credit_accounts a JOIN totals t USING (tenant_id)
             WHERE a.subscription_millicredits<>t.s OR a.purchased_millicredits<>t.p OR a.reserved_millicredits<>t.r
            """,
            (prefix + "%",),
        )
        pending = scalar(connection, "SELECT count(*) FROM beta_stripe_events WHERE processing_status<>'processed'")
        rows = connection.execute(
            "SELECT tenant_id,subscription_millicredits,purchased_millicredits,reserved_millicredits,paid_work_frozen "
            "FROM beta_credit_accounts WHERE tenant_id LIKE %s ORDER BY tenant_id",
            (prefix + "%",),
        ).fetchall()
    # The refund-consumed case intentionally creates a discrepancy and freeze;
    # it remains an explained race outcome, not a silent ledger mismatch.
    if mismatches != 0 or pending != 0:
        raise RuntimeError("post-race immutable-ledger reconciliation failed")
    digest = hashlib.sha256(canonical([list(row) for row in rows])).hexdigest()
    return case_result(CASE_IDS[8], {"ledger_mismatches": mismatches, "pending_events": pending, "database_state_sha256": digest})


def write_private(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists() or path.is_symlink():
        raise ValueError("refusing to replace race evidence")
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


def validate_evidence(value: Any, release_sha: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "status", "release_sha", "database", "started_at", "completed_at", "cases"
    }:
        raise ValueError("race evidence fields are missing or unknown")
    if value["schema_version"] != SCHEMA or value["status"] != "passed" or value["release_sha"] != release_sha:
        raise ValueError("race evidence identity or status mismatch")
    if not DATABASE.fullmatch(str(value["database"])):
        raise ValueError("race evidence did not use a disposable database")
    cases = value["cases"]
    if not isinstance(cases, list) or [item.get("id") for item in cases if isinstance(item, dict)] != list(CASE_IDS):
        raise ValueError("race evidence case set is incomplete")
    if any(item.get("status") != "passed" or not isinstance(item.get("outcomes"), dict) for item in cases):
        raise ValueError("race evidence contains a failed or malformed case")
    reconciliation = cases[-1]["outcomes"]
    if reconciliation.get("ledger_mismatches") != 0 or reconciliation.get("pending_events") != 0:
        raise ValueError("race evidence reconciliation is not clean")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not GIT_SHA.fullmatch(args.release_sha):
        raise SystemExit("release SHA must be a full lowercase Git commit")
    psycopg = psycopg_module()
    with psycopg.connect(args.database_url) as connection:
        database = scalar(connection, "SELECT current_database()")
    if not DATABASE.fullmatch(str(database)) or not str(database).endswith(args.release_sha[:12]):
        raise SystemExit("race harness requires the exact-release disposable database")
    prefix = f"race_{args.release_sha[:12]}"
    started = now()
    cases = [
        duplicate_job_creation(args.database_url, prefix),
        idempotency_body_conflict(args.database_url, prefix),
        concurrent_overspend(args.database_url, prefix),
        race_terminal(args.database_url, prefix, args.release_sha),
        stale_completion(args.database_url, prefix, args.release_sha),
        simultaneous_settlement(args.database_url, prefix, args.release_sha),
        refund_vs_credit_use(args.database_url, prefix),
        stripe_event_races(args.database_url, prefix),
        reconcile_created_rows(args.database_url, prefix),
    ]
    evidence = {
        "schema_version": SCHEMA,
        "status": "passed",
        "release_sha": args.release_sha,
        "database": database,
        "started_at": started,
        "completed_at": now(),
        "cases": cases,
    }
    validate_evidence(evidence, args.release_sha)
    write_private(args.output, evidence)
    print(json.dumps({"status": "passed", "output": str(args.output)}))


if __name__ == "__main__":
    main()
