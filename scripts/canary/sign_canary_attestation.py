#!/usr/bin/env python3
"""Sign a secret-free, release-bound canary operator attestation."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import stat


MODULE_PATH = Path(__file__).with_name("hc_beta_e2e.py")
SPEC = importlib.util.spec_from_file_location("hc_beta_e2e", MODULE_PATH)
assert SPEC and SPEC.loader
E2E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E2E)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    args = parser.parse_args()
    source = E2E.private_regular_file(args.input, "unsigned attestation")
    key_path = E2E.private_regular_file(args.key_file, "attestation HMAC key")
    if args.output.is_symlink():
        raise SystemExit("output must not be a symlink")
    output_parent = args.output.parent.resolve(strict=True)
    parent = output_parent.stat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise SystemExit("output directory must be owner-only")
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or "hmac_sha256" in value:
        raise SystemExit("input must be an unsigned JSON object")
    E2E.assert_public_evidence(value)
    key = key_path.read_bytes().strip()
    if len(key) < 32:
        raise SystemExit("attestation HMAC key must contain at least 32 bytes")
    value["hmac_sha256"] = hmac.new(
        key, E2E.canonical_json(value), hashlib.sha256
    ).hexdigest()
    E2E.validate_operator_attestation(
        value,
        release_sha=E2E.canonical_sha(str(value.get("release_sha", ""))),
        attestation_type=str(value.get("attestation_type", "")),
        kind=str(value["kind"]) if value.get("attestation_type") == "billing" else None,
        hmac_key=key,
    )
    temporary = args.output.with_name(f".{args.output.name}.{os.getpid()}.tmp")
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
        os.replace(temporary, args.output)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
