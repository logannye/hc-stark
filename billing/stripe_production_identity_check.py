#!/usr/bin/env python3
"""Read-only production check for the exact TinyZKP Stripe account identity."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))

from deploy_readiness_check import (  # noqa: E402
    load_private_env_file,
    reject_conflicting_inherited_environment,
)
from contract_billing import (  # noqa: E402
    create_stripe_client,
    validate_customer_facing_sender_identity,
)
from legacy_billing_containment import verify_account  # noqa: E402
from stripe_account_context_check import redact  # noqa: E402


LIVE_SECRET = re.compile(r"^sk_live_[A-Za-z0-9]{24,128}$")
ACCOUNT_ID = re.compile(r"^acct_[A-Za-z0-9]{16,32}$")
REQUIRED = (
    "STRIPE_SECRET_KEY",
    "STRIPE_EXPECTED_ACCOUNT_ID",
    "STRIPE_EXPECTED_DISPLAY_NAME",
)


def identity_environment(
    env_file: Path,
    inherited: dict[str, str],
) -> dict[str, str]:
    configured = load_private_env_file(env_file)
    reject_conflicting_inherited_environment(
        configured,
        inherited,
        keys=set(REQUIRED),
    )
    missing = [key for key in REQUIRED if not configured.get(key, "").strip()]
    if missing:
        raise ValueError("missing Stripe identity setting(s): " + ", ".join(missing))
    if LIVE_SECRET.fullmatch(configured["STRIPE_SECRET_KEY"].strip()) is None:
        raise ValueError("STRIPE_SECRET_KEY must be a canonical sk_live_ secret")
    if ACCOUNT_ID.fullmatch(configured["STRIPE_EXPECTED_ACCOUNT_ID"].strip()) is None:
        raise ValueError("STRIPE_EXPECTED_ACCOUNT_ID must be a canonical acct_ ID")
    return configured


def run_check(
    env_file: Path,
    *,
    inherited: dict[str, str] | None = None,
    client_factory: Callable[[str], Any] = create_stripe_client,
) -> dict[str, object]:
    configured = identity_environment(
        env_file,
        dict(os.environ) if inherited is None else inherited,
    )
    client = client_factory(configured["STRIPE_SECRET_KEY"])
    account = client.v1.accounts.retrieve_current()
    verify_account(
        account,
        configured["STRIPE_EXPECTED_ACCOUNT_ID"],
        configured["STRIPE_EXPECTED_DISPLAY_NAME"],
    )
    validate_customer_facing_sender_identity(account)
    return {
        "status": "pass",
        "stripe_account_id_verified": True,
        "stripe_dashboard_identity_verified": True,
        "tinyzkp_customer_facing_identity_verified": True,
        "write_performed": False,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = run_check(args.env_file)
    except Exception as error:
        # Stripe may include request context in SDK exceptions. The shared
        # redactor removes live/test keys, IDs, and email addresses; never dump
        # the parsed environment or account object.
        print(f"FAIL Stripe production identity: {redact(error)}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
