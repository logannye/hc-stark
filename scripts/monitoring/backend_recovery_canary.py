#!/usr/bin/env python3
"""Verify that every live TinyZKP surface remains safely in backend recovery."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin


HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "TinyZKP-Recovery-Canary/1.0 (+https://tinyzkp.com/status)",
}
PUBLIC_EMAIL_RE = re.compile(
    rb"(?:mailto:|[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)
OBFUSCATED_EMAIL_MARKERS = (b"__cf_email__", b"/cdn-cgi/l/email-protection")


@dataclass(frozen=True)
class Observation:
    name: str
    status: int
    body: bytes


class ContactFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.fields: dict[str, tuple[str, dict[str, str | None]]] = {}

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag not in {"input", "select"}:
            return
        attributes = dict(attrs)
        name = attributes.get("name")
        if isinstance(name, str) and name:
            self.fields[name] = (tag, attributes)


def request(name: str, url: str, *, method: str = "GET", body: bytes | None = None, timeout: int = 20) -> Observation:
    req = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return Observation(name, response.status, response.read(1024 * 1024))
    except urllib.error.HTTPError as exc:
        return Observation(name, exc.code, exc.read(1024 * 1024))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{name} request failed: {exc.reason}") from exc


def json_object(observation: Observation) -> dict[str, object]:
    try:
        value = json.loads(observation.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{observation.name} did not return JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{observation.name} returned non-object JSON")
    return value


def validate(site_url: str, api_url: str, mcp_url: str, timeout: int) -> list[str]:
    failures: list[str] = []
    checks = [
        request("capabilities", urljoin(api_url.rstrip("/") + "/", "v1/capabilities"), timeout=timeout),
        request("prove", urljoin(api_url.rstrip("/") + "/", "prove"), method="POST", body=b"{}", timeout=timeout),
        request(
            "legacy verify",
            urljoin(api_url.rstrip("/") + "/", "verify"),
            method="POST",
            body=b'{"proof":{"version":7}}',
            timeout=timeout,
        ),
        request(
            "checkout",
            urljoin(site_url.rstrip("/") + "/", "api/create-checkout"),
            method="POST",
            body=b"{}",
            timeout=timeout,
        ),
        request("homepage", site_url.rstrip("/") + "/", timeout=timeout),
        request("contact", urljoin(site_url.rstrip("/") + "/", "contact"), timeout=timeout),
        request("security", urljoin(site_url.rstrip("/") + "/", "security"), timeout=timeout),
        request("privacy", urljoin(site_url.rstrip("/") + "/", "privacy"), timeout=timeout),
        request("terms", urljoin(site_url.rstrip("/") + "/", "terms"), timeout=timeout),
        request("requests", urljoin(site_url.rstrip("/") + "/", "requests"), timeout=timeout),
        request(
            "unknown path",
            urljoin(site_url.rstrip("/") + "/", "tinyzkp-containment-nonexistent-probe"),
            timeout=timeout,
        ),
        request(
            "security.txt",
            urljoin(site_url.rstrip("/") + "/", ".well-known/security.txt"),
            timeout=timeout,
        ),
        request(
            "retired website MCP card",
            urljoin(site_url.rstrip("/") + "/", ".well-known/mcp/server-card.json"),
            timeout=timeout,
        ),
        request(
            "retired verifier JavaScript",
            urljoin(site_url.rstrip("/") + "/", "vendor/tinyzkp-verify/tinyzkp-verify.js"),
            timeout=timeout,
        ),
        request(
            "retired verifier WASM",
            urljoin(site_url.rstrip("/") + "/", "vendor/tinyzkp-verify/tinyzkp-verify_bg.wasm"),
            timeout=timeout,
        ),
        request("status", urljoin(site_url.rstrip("/") + "/", "status"), timeout=timeout),
        request("mcp version", urljoin(mcp_url.rstrip("/") + "/", "version"), timeout=timeout),
    ]

    by_name = {check.name: check for check in checks}
    capabilities = json_object(by_name["capabilities"])
    if by_name["capabilities"].status != 200:
        failures.append(f"capabilities returned HTTP {by_name['capabilities'].status}")
    for field in ("proving_available", "verification_available", "checkout_enabled", "account_creation_enabled"):
        if capabilities.get(field) is not False:
            failures.append(f"capabilities {field} must be false")
    if capabilities.get("service_status") != "backend_recovery":
        failures.append("capabilities service_status must be backend_recovery")

    expected = {
        "prove": (503, "protocol_upgrade"),
        "legacy verify": (422, "legacy_statement_unbound"),
        "checkout": (503, "protocol_upgrade"),
    }
    for name, (status, code) in expected.items():
        observation = by_name[name]
        if observation.status != status:
            failures.append(f"{name} returned HTTP {observation.status}; expected {status}")
            continue
        if json_object(observation).get("code") != code:
            failures.append(f"{name} did not return {code}")

    forbidden_claims = ("v5", "private zero knowledge", "full-prover O(√N)", "100M-row", "self-serve pricing")
    for name in ("homepage", "status"):
        observation = by_name[name]
        text = observation.body.decode("utf-8", errors="replace").lower()
        if observation.status != 200:
            failures.append(f"{name} returned HTTP {observation.status}")
        if "backend recovery" not in text and "backend upgrade" not in text:
            failures.append(f"{name} does not disclose backend recovery")
        for claim in forbidden_claims:
            if claim.lower() in text:
                failures.append(f"{name} contains forbidden claim {claim!r}")

    for name in ("homepage", "contact", "security", "privacy", "terms", "requests", "status"):
        observation = by_name[name]
        if observation.status != 200:
            failures.append(f"{name} returned HTTP {observation.status}")
        match = PUBLIC_EMAIL_RE.search(observation.body)
        if match:
            failures.append(
                f"{name} publishes a forbidden email contact: {match.group(0).decode('utf-8', errors='replace')}"
            )
        if any(marker in observation.body.lower() for marker in OBFUSCATED_EMAIL_MARKERS):
            failures.append(f"{name} publishes an obfuscated email contact")

    request_page = by_name["requests"]
    request_text = request_page.body.decode("utf-8", errors="replace")
    request_parser = ContactFormParser()
    request_parser.feed(request_text)
    for field in ("category", "contact_method", "contact_handle"):
        parsed_field = request_parser.fields.get(field)
        if parsed_field is None or "required" not in parsed_field[1]:
            failures.append(f"requests form must require {field}")
    if 'id="request-form"' not in request_text and "id='request-form'" not in request_text:
        failures.append("requests route is not the operational request form")

    if by_name["unknown path"].status != 404:
        failures.append(
            f"unknown website path returned HTTP {by_name['unknown path'].status}; expected 404"
        )

    security_txt = by_name["security.txt"]
    security_text = security_txt.body.decode("utf-8", errors="replace")
    if security_txt.status != 200:
        failures.append(f"security.txt returned HTTP {security_txt.status}")
    contacts = [
        line.removeprefix("Contact:").strip()
        for line in security_text.splitlines()
        if line.startswith("Contact:")
    ]
    if not contacts or any(not contact.startswith("https://") for contact in contacts):
        failures.append("security.txt must publish HTTPS Contact fields only")
    if not any(line.startswith("Expires:") for line in security_text.splitlines()):
        failures.append("security.txt is missing Expires")
    match = PUBLIC_EMAIL_RE.search(security_txt.body)
    if match:
        failures.append("security.txt publishes a forbidden email contact")
    if any(marker in security_txt.body.lower() for marker in OBFUSCATED_EMAIL_MARKERS):
        failures.append("security.txt publishes an obfuscated email contact")

    retired_card = by_name["retired website MCP card"]
    if retired_card.status not in {404, 410}:
        failures.append(
            "obsolete website MCP server card must return 404 or 410, "
            f"not HTTP {retired_card.status}"
        )
    for name in ("retired verifier JavaScript", "retired verifier WASM"):
        if by_name[name].status not in {404, 410}:
            failures.append(f"{name} must return 404 or 410, not HTTP {by_name[name].status}")

    contact = by_name["contact"]
    contact_text = contact.body.decode("utf-8", errors="replace")
    parser = ContactFormParser()
    parser.feed(contact_text)
    contact_method = parser.fields.get("contact_method")
    contact_handle = parser.fields.get("contact_handle")
    if contact.status != 200:
        failures.append(f"contact returned HTTP {contact.status}")
    if parser.fields.get("email") is not None:
        failures.append("contact must not collect email")
    if (
        contact_method is None
        or contact_method[0] != "select"
        or "required" not in contact_method[1]
    ):
        failures.append("contact must require a no-email reply channel")
    if (
        contact_handle is None
        or contact_handle[0] != "input"
        or "required" not in contact_handle[1]
    ):
        failures.append("contact must require a no-email reply handle")
    normalized_contact = " ".join(contact_text.lower().replace("-", " ").split())
    if "no email" not in normalized_contact:
        failures.append("contact does not disclose the no-email recovery policy")

    mcp_version = json_object(by_name["mcp version"])
    if by_name["mcp version"].status != 200 or mcp_version.get("service") != "mcp":
        failures.append("MCP version endpoint is unavailable or malformed")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-url", default="https://tinyzkp.com")
    parser.add_argument("--api-url", default="https://api.tinyzkp.com")
    parser.add_argument("--mcp-url", default="https://mcp.tinyzkp.com")
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args(argv)
    try:
        failures = validate(args.site_url, args.api_url, args.mcp_url, args.timeout)
    except RuntimeError as exc:
        failures = [str(exc)]
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1
    print("PASS  live TinyZKP surfaces are consistently in backend recovery")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
