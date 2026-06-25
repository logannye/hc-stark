#!/usr/bin/env python3
"""Validate TinyZKP receipt-share metadata and page-side share-link behavior."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]

CONTRACT = Path("site/.well-known/tinyzkp-receipt-share.json")
SCHEMA = Path("site/schemas/tinyzkp-receipt-share.schema.json")
TRY_PAGE = Path("site/try.html")
VERIFY_PAGE = Path("site/verify.html")
DISCOVERY = Path("site/discovery.json")
LLMS = Path("site/llms.txt")
ROBOTS = Path("site/robots.txt")
INDEX = Path("site/index.html")
EVENTS = Path("site/functions/api/events.js")

REQUIRED_EVENTS = {
    "first_verify_share_created",
    "playground_share_copied",
    "client_verify_share_copied",
    "verifier_opened",
    "verifier_cta_clicked",
}


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def tinyzkp_url(value: object, *, label: str) -> str | None:
    if not isinstance(value, str):
        return f"{label} must be a URL string"
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.netloc != "tinyzkp.com":
        return f"{label} must be an https://tinyzkp.com URL"
    if not parsed.path.startswith("/"):
        return f"{label} must include an absolute path"
    return None


def require_markers(text: str, markers: list[str], label: str, failures: list[str]) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        failures.append(f"{label} missing markers: {', '.join(missing)}")


def validate_contract(root: Path) -> Check:
    failures: list[str] = []
    contract_path = root / CONTRACT
    schema_path = root / SCHEMA
    if not contract_path.is_file():
        return Check("FAIL", str(CONTRACT), "missing receipt-share contract")
    if not schema_path.is_file():
        failures.append(f"{SCHEMA} is missing")

    contract = load_json(contract_path)
    load_json(schema_path)
    if not isinstance(contract, dict):
        return Check("FAIL", str(CONTRACT), "contract must be a JSON object")

    if contract.get("$schema") != "https://tinyzkp.com/schemas/tinyzkp-receipt-share.schema.json":
        failures.append("contract $schema must point to tinyzkp-receipt-share.schema.json")
    if contract.get("canonical_url") != "https://tinyzkp.com/.well-known/tinyzkp-receipt-share.json":
        failures.append("canonical_url must be the TinyZKP well-known receipt-share URL")
    if contract.get("status") != "live":
        failures.append("status must be live")
    if contract.get("verifier_url") != "https://tinyzkp.com/verify":
        failures.append("verifier_url must be https://tinyzkp.com/verify")

    template = contract.get("share_url_template")
    if not isinstance(template, str):
        failures.append("share_url_template must be a string")
    else:
        for marker in (
            "https://tinyzkp.com/verify?",
            "source=receipt_share",
            "medium={medium}",
            "workflow={workflow}",
            "intent=verify_receipt",
            "#proof={base64url_json_proof}",
        ):
            if marker not in template:
                failures.append(f"share_url_template missing {marker!r}")

    fragment = contract.get("fragment") if isinstance(contract.get("fragment"), dict) else {}
    if fragment.get("parameter") != "proof":
        failures.append("fragment.parameter must be proof")
    if fragment.get("encoding") != "base64url":
        failures.append("fragment.encoding must be base64url")
    if fragment.get("decoded_format") != "utf-8 JSON":
        failures.append("fragment.decoded_format must be utf-8 JSON")
    max_chars = fragment.get("max_encoded_chars")
    if not isinstance(max_chars, int) or not 8000 <= max_chars <= 200000:
        failures.append("fragment.max_encoded_chars must be an integer between 8000 and 200000")
    boundary = str(fragment.get("browser_network_boundary", "")).lower()
    for marker in ("fragment", "not sent", "hosted verifier"):
        if marker not in boundary:
            failures.append(f"browser_network_boundary must mention {marker!r}")

    proof_shape = contract.get("proof_shape") if isinstance(contract.get("proof_shape"), dict) else {}
    required_fields = proof_shape.get("required_fields")
    if required_fields != ["version", "bytes"]:
        failures.append("proof_shape.required_fields must be ['version', 'bytes']")
    if proof_shape.get("current_public_template") != "accumulator_step":
        failures.append("proof_shape.current_public_template must be accumulator_step")

    attribution = contract.get("attribution") if isinstance(contract.get("attribution"), dict) else {}
    if attribution.get("required_source") != "receipt_share":
        failures.append("attribution.required_source must be receipt_share")
    if attribution.get("recommended_intent") != "verify_receipt":
        failures.append("attribution.recommended_intent must be verify_receipt")
    for event in REQUIRED_EVENTS:
        if event not in attribution.get("events", []):
            failures.append(f"attribution.events must include {event}")
    ctas = attribution.get("conversion_ctas") if isinstance(attribution.get("conversion_ctas"), dict) else {}
    for key in ("signup", "mcp"):
        error = tinyzkp_url(ctas.get(key), label=f"attribution.conversion_ctas.{key}")
        if error:
            failures.append(error)
            continue
        query = parse_qs(urlparse(ctas[key]).query)
        if query.get("source") != ["receipt_share"]:
            failures.append(f"attribution.conversion_ctas.{key} must include source=receipt_share")

    boundaries = " ".join(str(item).lower() for item in contract.get("data_boundaries", []))
    for marker in ("transparent", "secrets", "private customer data", "proof json"):
        if marker not in boundaries:
            failures.append(f"data_boundaries must mention {marker!r}")

    related = contract.get("related_assets") if isinstance(contract.get("related_assets"), dict) else {}
    for key in ("verifier", "playground", "offers", "discovery", "receipt_schema", "contract_schema"):
        error = tinyzkp_url(related.get(key), label=f"related_assets.{key}")
        if error:
            failures.append(error)

    return Check(
        "FAIL" if failures else "PASS",
        str(CONTRACT),
        "; ".join(failures) if failures else "receipt-share contract is valid",
    )


def validate_public_links(root: Path) -> Check:
    failures: list[str] = []
    marker = ".well-known/tinyzkp-receipt-share.json"
    for rel_path in (DISCOVERY, LLMS, ROBOTS, INDEX):
        path = root / rel_path
        if not path.is_file():
            failures.append(f"{rel_path} is missing")
            continue
        if marker not in path.read_text(encoding="utf-8"):
            failures.append(f"{rel_path} does not link the receipt-share contract")
    return Check(
        "FAIL" if failures else "PASS",
        "public receipt-share discovery links",
        "; ".join(failures) if failures else "receipt-share contract is discoverable",
    )


def validate_pages(root: Path, max_chars: int) -> Check:
    failures: list[str] = []
    try_text = (root / TRY_PAGE).read_text(encoding="utf-8") if (root / TRY_PAGE).is_file() else ""
    verify_text = (root / VERIFY_PAGE).read_text(encoding="utf-8") if (root / VERIFY_PAGE).is_file() else ""
    events_text = (root / EVENTS).read_text(encoding="utf-8") if (root / EVENTS).is_file() else ""
    if not try_text:
        failures.append(f"{TRY_PAGE} is missing")
    if not verify_text:
        failures.append(f"{VERIFY_PAGE} is missing")
    if not events_text:
        failures.append(f"{EVENTS} is missing")

    max_re = re.compile(rf"MAX_SHARE_FRAGMENT_CHARS\s*=\s*{re.escape(str(max_chars))}\b")
    if try_text and not max_re.search(try_text):
        failures.append(f"{TRY_PAGE} must enforce MAX_SHARE_FRAGMENT_CHARS={max_chars}")
    if verify_text and not max_re.search(verify_text):
        failures.append(f"{VERIFY_PAGE} must enforce MAX_SHARE_FRAGMENT_CHARS={max_chars}")

    require_markers(
        try_text,
        [
            "source', 'receipt_share'",
            "medium', 'playground'",
            "workflow', 'accumulator_step'",
            "intent', 'verify_receipt'",
            "b64UrlEncode(JSON.stringify(proof))",
            "Proof is too large for a safe share URL",
            "first_verify_share_created",
        ],
        str(TRY_PAGE),
        failures,
    )
    require_markers(
        verify_text,
        [
            "source', 'receipt_share'",
            "medium', 'verifier'",
            "workflow', 'accumulator_step'",
            "intent', 'verify_receipt'",
            "b64UrlDecode",
            "Shared proof fragment is larger than the public verifier contract allows",
            "verifier_opened",
        ],
        str(VERIFY_PAGE),
        failures,
    )
    for event in REQUIRED_EVENTS:
        if event not in events_text:
            failures.append(f"{EVENTS} must allow analytics event {event}")

    return Check(
        "FAIL" if failures else "PASS",
        "receipt-share page behavior",
        "; ".join(failures) if failures else "try/verify pages enforce the receipt-share contract",
    )


def validate(root: Path = ROOT) -> list[Check]:
    root = root.resolve()
    checks = [validate_contract(root), validate_public_links(root)]
    contract_path = root / CONTRACT
    max_chars = 120000
    if contract_path.is_file():
        contract = load_json(contract_path)
        if isinstance(contract, dict):
            fragment = contract.get("fragment") if isinstance(contract.get("fragment"), dict) else {}
            if isinstance(fragment.get("max_encoded_chars"), int):
                max_chars = fragment["max_encoded_chars"]
    checks.append(validate_pages(root, max_chars))
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} receipt-share contract check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll receipt-share contract checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
