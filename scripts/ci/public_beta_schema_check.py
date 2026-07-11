#!/usr/bin/env python3
"""Fail closed when the public-beta PostgreSQL ledger loses required invariants."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "crates" / "hc-beta-api" / "migrations" / "0001_public_beta.sql"

REQUIRED = (
    "beta_auth_identities",
    "PRIMARY KEY (provider, provider_user_id)",
    "beta_oauth_states",
    "pkce_verifier_ciphertext BYTEA NOT NULL",
    "beta_sessions",
    "beta_sandbox_grants",
    "beta_api_keys",
    "WHERE revoked_at IS NULL",
    "beta_idempotency_keys",
    "beta_rate_limits",
    "PRIMARY KEY (tenant_id, operation, idempotency_key)",
    "beta_credit_accounts",
    "beta_credit_events",
    "UNIQUE (tenant_id, operation_key)",
    "beta_proof_jobs",
    "lease_epoch",
    "beta_job_attempts",
    "reserved_subscription_millicredits",
    "reserved_purchased_millicredits",
    "reserved_millicredits = reserved_subscription_millicredits + reserved_purchased_millicredits",
    "verification_succeeded AND settled_millicredits IS NOT NULL",
    "beta_workers",
    "max_slots BETWEEN 1 AND 4",
    "beta_stripe_events",
    "beta_billing_customers",
    "beta_subscriptions",
    "beta_reconciliation_runs",
    "beta_retention_deletions",
    "processing_status IN ('pending','processed','failed')",
    "DEFERRABLE INITIALLY DEFERRED",
)


def check(text: str) -> list[str]:
    failures = [f"missing PostgreSQL invariant: {marker}" for marker in REQUIRED if marker not in text]
    for forbidden in ("api_key_plaintext", "credit_balance DOUBLE", "DROP TABLE", "CASCADE;"):
        if forbidden in text:
            failures.append(f"unsafe PostgreSQL marker: {forbidden}")
    return failures


def main() -> int:
    failures = check(SCHEMA.read_text(encoding="utf-8"))
    if failures:
        print("Public-beta schema check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("PASS public-beta PostgreSQL schema invariants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
