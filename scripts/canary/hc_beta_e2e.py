#!/usr/bin/env python3
"""Run the exact TinyZKP declarative AIR hosted lifecycle without leaking secrets."""

from __future__ import annotations

import argparse
from http.client import RemoteDisconnected
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid

from blake3 import blake3

import declarative_fixtures


TERMINAL = {"completed", "cancelled", "platform_failed", "customer_failed"}
SENSITIVE_EVIDENCE_KEYS = {
    "api_key",
    "authorization",
    "cookie",
    "headers",
    "presigned_url",
    "secret",
    "session",
    "url",
    "webhook_secret",
}
SECRET_VALUE_PREFIXES = ("Bearer ", "gho_", "github_pat_", "rk_", "sk_", "whsec_")
SIGNED_UPLOAD_ATTEMPTS = 4
SIGNED_UPLOAD_RETRY_SECONDS = 0.5


class ApiFailure(RuntimeError):
    def __init__(self, status: int, payload: object) -> None:
        super().__init__(f"API request failed with HTTP {status}")
        self.status = status
        self.payload = payload


def truncated_signed_upload_was_rejected(error: BaseException) -> bool:
    """Recognize the two fail-closed responses R2 uses for a short signed PUT."""
    return (
        isinstance(error, ApiFailure) and 400 <= error.status < 500
    ) or isinstance(error, RemoteDisconnected)


class ApiClient:
    def __init__(self, base_url: str, api_key: str | None, timeout: int = 60) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        payload: object | None = None,
        *,
        idempotency_key: str | None = None,
        authenticated: bool = True,
    ) -> tuple[int, Any]:
        headers = {"accept": "application/json"}
        if authenticated:
            if not self.api_key:
                raise RuntimeError("authenticated API request requires an API key")
            headers["authorization"] = f"Bearer {self.api_key}"
        if idempotency_key:
            headers["idempotency-key"] = idempotency_key
        body = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
            headers["content-type"] = "application/json"
        request = Request(f"{self.base_url}{path}", data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except HTTPError as error:
            raw = error.read()
            try:
                payload = json.loads(raw) if raw else None
            except ValueError:
                payload = {"error": "non_json_error"}
            raise ApiFailure(error.code, payload) from None

    def put_signed(
        self,
        signed: dict[str, object],
        payload: bytes,
        *,
        header_overrides: dict[str, str] | None = None,
    ) -> int:
        headers = {str(name): str(value) for name, value in dict(signed["headers"]).items()}
        headers.update(header_overrides or {})
        for attempt in range(1, SIGNED_UPLOAD_ATTEMPTS + 1):
            request = Request(
                str(signed["url"]), data=payload, headers=headers, method="PUT"
            )
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    response.read()
                    return response.status
            except HTTPError as error:
                error.read()
                failure = ApiFailure(error.code, {"error": "signed_upload_rejected"})
                if error.code < 500 or attempt == SIGNED_UPLOAD_ATTEMPTS:
                    raise failure from None
            except (RemoteDisconnected, TimeoutError, ConnectionError, URLError):
                if attempt == SIGNED_UPLOAD_ATTEMPTS:
                    raise
            time.sleep(SIGNED_UPLOAD_RETRY_SECONDS * attempt)
        raise AssertionError("signed upload retry loop exhausted")

    def get_signed(self, signed: dict[str, object]) -> bytes:
        headers = {str(name): str(value) for name, value in dict(signed["headers"]).items()}
        request = Request(str(signed["url"]), headers=headers, method="GET")
        with urlopen(request, timeout=self.timeout) as response:
            return response.read()


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def canonical_sha(value: str) -> str:
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError("release SHA must be a full lowercase Git commit")
    return value


def run(command: list[str], *, expect_json: bool = False) -> object | None:
    environment = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")}
    if os.environ.get("TINYZKP_RELEASE_SHA"):
        environment["HC_RELEASE_SHA"] = os.environ["TINYZKP_RELEASE_SHA"]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=65 * 60,
        check=False,
        env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"command failed: {completed.stderr[-1000:]}")
    if expect_json:
        return json.loads(completed.stdout)
    return None


def write_json(path: Path, value: object) -> None:
    declarative_fixtures.write_json(path, value)
    path.chmod(0o600)


def assert_public_evidence(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in SENSITIVE_EVIDENCE_KEYS or normalized.endswith("_secret"):
                raise RuntimeError(f"evidence contains sensitive field at {path}.{key}")
            assert_public_evidence(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_public_evidence(item, f"{path}[{index}]")
    elif isinstance(value, str):
        if "://" in value or value.startswith(SECRET_VALUE_PREFIXES):
            raise RuntimeError(f"evidence contains secret-like value at {path}")


def persist_evidence(result: dict[str, object]) -> None:
    assert_public_evidence(result)
    configured = os.environ.get("TINYZKP_E2E_EVIDENCE_DIR", "").strip()
    if not configured:
        return
    directory = Path(configured)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    details = directory.stat()
    if not stat.S_ISDIR(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o700:
        raise RuntimeError("evidence directory must be owner-only")
    name = f"{result['release_sha']}-{result['workload']}-{result['rows']}-{result['job_id']}.json"
    destination = directory / name
    temporary = directory / f".{name}.{os.getpid()}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(result, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def policy(root: Path) -> dict[str, object]:
    scratch = root / "scratch"
    scratch.mkdir(mode=0o700)
    return {
        "mode": "scratch",
        "max_resident_bytes": 2 * 1024**3,
        "max_scratch_bytes": 900 * 1024**3,
        "scratch_dir": str(scratch),
        "max_threads": 2,
        "checkpoint_policy": "retain_on_failure",
    }


def prepare_statement(
    cli: Path, selected: declarative_fixtures.Fixture, rows: int, root: Path
) -> dict[str, object]:
    air_path = root / "air.json"
    write_json(air_path, selected.air)
    validation = run(
        [str(cli), "plonky3", "validate-air", "--air", str(air_path)],
        expect_json=True,
    )
    if not isinstance(validation, dict) or validation.get("valid") is not True:
        raise RuntimeError("CLI rejected deterministic AIR")
    air_digest = str(validation["air_digest_hex"])
    policy_path = root / "policy.json"
    write_json(policy_path, policy(root))

    prepared: dict[str, object] = {"air": selected.air, "air_path": air_path, "air_digest": air_digest}
    for label, logical_rows in (("local", 1024), ("hosted", rows)):
        trace = root / f"{label}.trace"
        public_values = declarative_fixtures.write_trace(trace, selected, logical_rows)
        public = {"schema_version": 1, "air_digest_hex": air_digest, "values": public_values}
        public_path = root / f"{label}.public.json"
        write_json(public_path, public)
        packed = root / f"{label}.packed"
        packed.mkdir(mode=0o700)
        run(
            [
                str(cli), "plonky3", "pack-trace", "--air", str(air_path),
                "--trace", str(trace), "--rows", str(logical_rows), "--output-dir", str(packed),
                "--chunk-bytes", str(8 * 1024 * 1024),
            ]
        )
        prepared[f"{label}_public"] = public
        prepared[f"{label}_public_path"] = public_path
        prepared[f"{label}_packed"] = packed
        prepared[f"{label}_manifest"] = json.loads(
            (packed / "trace-manifest-v1.json").read_text(encoding="utf-8")
        )
    proof_path = root / "local.proof.json"
    run(
        [
            str(cli), "plonky3", "prove-air", "--air", str(air_path),
            "--trace-manifest", str(Path(prepared["local_packed"]) / "trace-manifest-v1.json"),
            "--chunks-dir", str(prepared["local_packed"]),
            "--public-inputs", str(prepared["local_public_path"]),
            "--policy", str(policy_path), "--output", str(proof_path),
        ]
    )
    run([str(cli), "plonky3", "verify-air", "--bundle", str(proof_path)])
    prepared["local_proof"] = json.loads(proof_path.read_text(encoding="utf-8"))
    return prepared


def operation(prefix: str, workload: str, rows: int) -> str:
    return f"e2e-{prefix}-{workload}-{rows}-{uuid.uuid4().hex}"


def upload_chunks(client: ApiClient, response: dict[str, object], packed: Path) -> None:
    for item in list(response["chunks"]):
        index = int(item["index"])
        payload = (packed / f"chunk-{index:06}.zst").read_bytes()
        client.put_signed(dict(item["upload"]), payload)


def credit_snapshot(me: dict[str, object]) -> tuple[int, int, int]:
    return (
        int(me["subscription_millicredits"]),
        int(me["purchased_millicredits"]),
        int(me["reserved_millicredits"]),
    )


def assert_credits_unchanged(
    before: tuple[int, int, int], after: tuple[int, int, int], label: str
) -> None:
    if after != before:
        raise RuntimeError(f"{label} changed the credit ledger")


def create_upload(
    client: ApiClient,
    upload_body: dict[str, object],
    workload: str,
    rows: int,
    label: str,
) -> dict[str, object]:
    status, response = client.request(
        "POST",
        "/v1/uploads",
        upload_body,
        idempotency_key=operation(f"upload-{label}", workload, rows),
    )
    if status != 201:
        raise RuntimeError(f"{label} upload was not created")
    return dict(response)


def failure_is_uncharged(
    client: ApiClient,
    job_body: dict[str, object],
    workload: str,
    rows: int,
    label: str,
) -> bool:
    before = credit_snapshot(client.request("GET", "/v1/me")[1])
    try:
        _, submitted = client.request(
            "POST",
            "/v1/proof-jobs",
            job_body,
            idempotency_key=operation(f"job-{label}", workload, rows),
        )
    except ApiFailure as error:
        if error.status < 400 or error.status >= 500:
            raise RuntimeError(f"{label} failed with an infrastructure error") from error
    else:
        terminal = poll_job(client, str(submitted["job_id"]))
        if terminal["status"] == "completed" or terminal.get("settled_millicredits") not in {
            None,
            0,
        }:
            raise RuntimeError(f"{label} unexpectedly completed or charged")
    after = credit_snapshot(client.request("GET", "/v1/me")[1])
    assert_credits_unchanged(before, after, label)
    return True


def run_negative_lifecycle_checks(
    client: ApiClient,
    upload_body: dict[str, object],
    valid_upload: dict[str, object],
    statement: dict[str, object],
    workload: str,
    rows: int,
) -> dict[str, bool]:
    packed = Path(statement["hosted_packed"])
    first_chunk = (packed / "chunk-000000.zst").read_bytes()
    if len(first_chunk) < 2:
        raise RuntimeError("fixture chunk is too small for negative upload tests")

    checksum_upload = create_upload(client, upload_body, workload, rows, "checksum")
    checksum_item = dict(list(checksum_upload["chunks"])[0])
    checksum_signed = dict(checksum_item["upload"])
    checksum_headers = {
        str(name): str(value) for name, value in dict(checksum_signed["headers"]).items()
    }
    metadata_header = next(
        (name for name in checksum_headers if "tinyzkp-blake3" in name.lower()), None
    )
    if metadata_header is None:
        raise RuntimeError("signed upload omitted the content-digest metadata header")
    value = checksum_headers[metadata_header]
    wrong_value = ("0" if not value.startswith("0") else "1") + value[1:]
    checksum_rejected = False
    try:
        client.put_signed(
            checksum_signed,
            first_chunk,
            header_overrides={metadata_header: wrong_value},
        )
    except ApiFailure as error:
        checksum_rejected = 400 <= error.status < 500
    if not checksum_rejected:
        raise RuntimeError("R2 accepted a mismatched signed checksum header")

    length_upload = create_upload(client, upload_body, workload, rows, "length")
    length_put_rejected = False
    for item in list(length_upload["chunks"]):
        index = int(item["index"])
        payload = (packed / f"chunk-{index:06}.zst").read_bytes()
        if index == 0:
            payload = payload[:-1]
        try:
            client.put_signed(dict(item["upload"]), payload)
        except (ApiFailure, RemoteDisconnected) as error:
            if index != 0 or not truncated_signed_upload_was_rejected(error):
                raise
            length_put_rejected = True
            break
    if not length_put_rejected:
        length_body = {
            "air_package_id": upload_body["air_package_id"],
            "upload_id": length_upload["upload_id"],
            "public_inputs": statement["hosted_public"],
        }
        failure_is_uncharged(client, length_body, workload, rows, "wrong-length")

    corrupt_upload = create_upload(client, upload_body, workload, rows, "corrupt")
    for item in list(corrupt_upload["chunks"]):
        index = int(item["index"])
        payload = (packed / f"chunk-{index:06}.zst").read_bytes()
        if index == 0:
            payload = bytes([payload[0] ^ 1]) + payload[1:]
        client.put_signed(dict(item["upload"]), payload)
    corrupt_body = {
        "air_package_id": upload_body["air_package_id"],
        "upload_id": corrupt_upload["upload_id"],
        "public_inputs": statement["hosted_public"],
    }
    corrupt_uncharged = failure_is_uncharged(
        client, corrupt_body, workload, rows, "corrupt-chunk"
    )

    wrong_public = json.loads(json.dumps(statement["hosted_public"]))
    wrong_public["values"][0] = (int(wrong_public["values"][0]) + 1) % declarative_fixtures.MODULUS
    wrong_public_body = {
        "air_package_id": upload_body["air_package_id"],
        "upload_id": valid_upload["upload_id"],
        "public_inputs": wrong_public,
    }
    wrong_public_uncharged = failure_is_uncharged(
        client, wrong_public_body, workload, rows, "wrong-public-inputs"
    )
    return {
        "wrong_checksum_rejected": checksum_rejected,
        "wrong_length_uncharged": True,
        "corrupt_chunk_uncharged": corrupt_uncharged,
        "wrong_public_inputs_uncharged": wrong_public_uncharged,
    }


def poll_job(client: ApiClient, job_id: str, timeout_seconds: int = 65 * 60) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        _, job = client.request("GET", f"/v1/proof-jobs/{job_id}")
        if job["status"] in TERMINAL:
            return dict(job)
        time.sleep(2)
    raise RuntimeError("hosted proof job did not reach a terminal state")


def execute_lifecycle(
    workload: str,
    rows: int,
    *,
    cancel: bool = False,
    negative_tests: bool = False,
) -> dict[str, object]:
    cli = Path(required("TINYZKP_CLI")).resolve(strict=True)
    release_sha = canonical_sha(required("TINYZKP_RELEASE_SHA"))
    identity = run([str(cli), "release"], expect_json=True)
    if not isinstance(identity, dict) or identity.get("release_sha") != release_sha:
        raise RuntimeError("CLI release identity does not match the canary release")
    client = ApiClient(required("TINYZKP_API_URL"), required("TINYZKP_API_KEY"))
    selected = declarative_fixtures.fixture(workload)
    root_parent = Path(os.environ.get("TINYZKP_E2E_STATE_DIR", "/var/lib/tinyzkp-e2e"))
    root_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    root_parent.chmod(0o700)
    root = Path(tempfile.mkdtemp(prefix=f"{workload}-", dir=root_parent))
    root.chmod(0o700)
    try:
        before = client.request("GET", "/v1/me")[1]
        statement = prepare_statement(cli, selected, rows, root)
        register_body = {"air": statement["air"], "local_proof": statement["local_proof"]}
        register_key = operation("air", workload, rows)
        status, registered = client.request(
            "POST", "/v1/air-packages", register_body, idempotency_key=register_key
        )
        retry_status, retry_registered = client.request(
            "POST", "/v1/air-packages", register_body, idempotency_key=register_key
        )
        if status != 201 or retry_status != status or retry_registered != registered:
            raise RuntimeError("AIR registration idempotency retry changed the resource")

        upload_body = {
            "air_package_id": registered["air_package_id"],
            "manifest": statement["hosted_manifest"],
        }
        upload_key = operation("upload", workload, rows)
        _, upload = client.request(
            "POST", "/v1/uploads", upload_body, idempotency_key=upload_key
        )
        _, retry_upload = client.request(
            "POST", "/v1/uploads", upload_body, idempotency_key=upload_key
        )
        if retry_upload != upload:
            raise RuntimeError("upload idempotency retry changed the resource")
        changed_conflict = False
        try:
            client.request(
                "POST",
                "/v1/uploads",
                {**upload_body, "manifest": statement["local_manifest"]},
                idempotency_key=upload_key,
            )
        except ApiFailure as error:
            changed_conflict = error.status == 409
        if not changed_conflict:
            raise RuntimeError("changed-body idempotency reuse did not return HTTP 409")
        upload_chunks(client, upload, Path(statement["hosted_packed"]))

        negative_results: dict[str, bool] = {}
        if negative_tests:
            negative_results = run_negative_lifecycle_checks(
                client,
                upload_body,
                dict(upload),
                statement,
                workload,
                rows,
            )

        job_body = {
            "air_package_id": registered["air_package_id"],
            "upload_id": upload["upload_id"],
            "public_inputs": statement["hosted_public"],
        }
        job_key = operation("job", workload, rows)
        _, submitted = client.request(
            "POST", "/v1/proof-jobs", job_body, idempotency_key=job_key
        )
        _, retry_submitted = client.request(
            "POST", "/v1/proof-jobs", job_body, idempotency_key=job_key
        )
        if retry_submitted != submitted:
            raise RuntimeError("job idempotency retry changed the resource")
        job_id = str(submitted["job_id"])

        if cancel:
            deadline = time.monotonic() + 10 * 60
            observed_active = False
            while time.monotonic() < deadline:
                _, current = client.request("GET", f"/v1/proof-jobs/{job_id}")
                if current["status"] in {"leased", "proving", "verifying"}:
                    observed_active = True
                    break
                if current["status"] in TERMINAL:
                    break
                time.sleep(1)
            if not observed_active:
                raise RuntimeError("cancellation workload did not remain active")
            client.request(
                "POST",
                f"/v1/proof-jobs/{job_id}/cancel",
                idempotency_key=operation("cancel", workload, rows),
            )
            terminal = poll_job(client, job_id)
            after = client.request("GET", "/v1/me")[1]
            reservation = int(submitted["estimate"]["reservation_millicredits"])
            released = (
                terminal["status"] == "cancelled"
                and int(after["reserved_millicredits"]) == int(before["reserved_millicredits"])
                and int(after["subscription_millicredits"]) + int(after["purchased_millicredits"])
                == int(before["subscription_millicredits"]) + int(before["purchased_millicredits"])
            )
            return {
                "schema_version": 1,
                "release_sha": release_sha,
                "workload": workload,
                "rows": rows,
                "job_id": job_id,
                "reservation_millicredits": reservation,
                "full_reservation_released": released,
                "status": terminal["status"],
            }

        terminal = poll_job(client, job_id)
        if terminal["status"] != "completed":
            raise RuntimeError(f"hosted proof failed: {terminal['status']}")
        _, bundle_response = client.request("GET", f"/v1/proof-jobs/{job_id}/bundle")
        bundle_bytes = client.get_signed(dict(bundle_response["download"]))
        bundle_digest = blake3(bundle_bytes).hexdigest()
        if len(bundle_bytes) != int(bundle_response["size_bytes"]) or bundle_digest != bundle_response["blake3_hex"]:
            raise RuntimeError("downloaded hosted bundle does not match authorized metadata")
        bundle_path = root / "hosted-bundle.json"
        bundle_path.write_bytes(bundle_bytes)
        bundle_path.chmod(0o600)
        run([str(cli), "plonky3", "verify-hosted", "--bundle", str(bundle_path)])
        bundle = json.loads(bundle_bytes)
        _, verified = client.request(
            "POST", "/v1/verify", {"bundle": bundle}, authenticated=False
        )
        if verified.get("valid") is not True:
            raise RuntimeError("public official verifier rejected hosted bundle")
        cross_tenant_denied = None
        secondary = os.environ.get("TINYZKP_SECONDARY_API_KEY", "").strip()
        if negative_tests:
            if not secondary:
                raise RuntimeError("TINYZKP_SECONDARY_API_KEY is required for negative tests")
            try:
                ApiClient(required("TINYZKP_API_URL"), secondary).request(
                    "GET", f"/v1/proof-jobs/{job_id}/bundle"
                )
            except ApiFailure as error:
                cross_tenant_denied = error.status in {403, 404}
            if cross_tenant_denied is not True:
                raise RuntimeError("cross-tenant bundle authorization did not fail closed")
        after = client.request("GET", "/v1/me")[1]
        reservation = int(submitted["estimate"]["reservation_millicredits"])
        charge = int(terminal["settled_millicredits"])
        before_available = int(before["subscription_millicredits"]) + int(before["purchased_millicredits"])
        after_available = int(after["subscription_millicredits"]) + int(after["purchased_millicredits"])
        if (
            charge > reservation
            or int(bundle["charge_millicredits"]) != charge
            or before_available - after_available != charge
            or int(after["reserved_millicredits"]) != int(before["reserved_millicredits"])
        ):
            raise RuntimeError("final charge exceeded or failed to release the reservation")
        proof = bundle["proof"]
        return {
            "schema_version": 1,
            "release_sha": release_sha,
            "workload": workload,
            "rows": rows,
            "job_id": job_id,
            "air_digest_hex": statement["air_digest"],
            "trace_digest_hex": statement["hosted_manifest"]["trace_digest_hex"],
            "public_inputs_digest_hex": proof["public_inputs_digest_hex"],
            "proof_digest_hex": proof["proof_digest_hex"],
            "bundle_digest_hex": bundle_digest,
            "quoted_charge_millicredits": submitted["estimate"]["quoted_charge_millicredits"],
            "reservation_millicredits": reservation,
            "charge_millicredits": charge,
            "reservation_remainder_released": True,
            "idempotency_retry_exact": True,
            "idempotency_changed_body_conflict": True,
            "cross_tenant_bundle_denied": cross_tenant_denied,
            "official_verification": True,
            **negative_results,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    proof = subcommands.add_parser("proof")
    proof.add_argument("workload", choices=("fibonacci", "poseidon2", "customer_cubic8"))
    proof.add_argument("--rows", type=int)
    proof.add_argument(
        "--negative-tests",
        action="store_true",
        help="exercise R2, public-input, refund, and cross-tenant fail-closed paths",
    )
    cancel = subcommands.add_parser("cancel")
    cancel.add_argument("--workload", choices=("fibonacci", "poseidon2", "customer_cubic8"), default="customer_cubic8")
    cancel.add_argument("--rows", type=int)
    billing = subcommands.add_parser("billing")
    billing.add_argument("kind", choices=("topup", "subscription"))
    subcommands.add_parser("audit")
    args = parser.parse_args()
    if args.command == "proof":
        rows = args.rows or int(os.environ.get("TINYZKP_CANARY_ROWS", str(1 << 14)))
        result = execute_lifecycle(
            args.workload,
            rows,
            negative_tests=args.negative_tests,
        )
    elif args.command == "cancel":
        rows = args.rows or int(os.environ.get("TINYZKP_CANCEL_ROWS", str(1 << 18)))
        result = execute_lifecycle(args.workload, rows, cancel=True)
    else:
        raise RuntimeError(f"{args.command} is unavailable until the billing/evidence PR lands")
    assert_public_evidence(result)
    persist_evidence(result)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
