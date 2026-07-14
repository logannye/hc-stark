import importlib.util
import hashlib
import hmac
from http.client import RemoteDisconnected
from io import BytesIO
from pathlib import Path
import sys
from urllib.error import HTTPError

import pytest


CANARY_DIR = Path(__file__).parent
sys.path.insert(0, str(CANARY_DIR))
import declarative_fixtures as fixtures  # noqa: E402

SPEC = importlib.util.spec_from_file_location("hc_beta_e2e", CANARY_DIR / "hc_beta_e2e.py")
assert SPEC and SPEC.loader
E2E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E2E)


def evaluate(
    air: dict[str, object],
    current: tuple[int, ...],
    following: tuple[int, ...],
    public: list[int],
) -> list[int]:
    values: list[int] = []
    for expression in air["expressions"]:
        operation = expression["op"]
        if operation == "constant":
            value = int(expression["value"])
        elif operation == "current":
            value = current[int(expression["column"])]
        elif operation == "next":
            value = following[int(expression["column"])]
        elif operation == "public":
            value = public[int(expression["index"])]
        elif operation == "add":
            value = values[int(expression["left"])] + values[int(expression["right"])]
        elif operation == "sub":
            value = values[int(expression["left"])] - values[int(expression["right"])]
        elif operation == "mul":
            value = values[int(expression["left"])] * values[int(expression["right"])]
        else:
            raise AssertionError(f"unsupported fixture operation: {operation}")
        values.append(value % fixtures.MODULUS)
    return values


@pytest.mark.parametrize("name", ["fibonacci", "poseidon2", "customer_cubic8"])
def test_fixture_trace_satisfies_every_declared_constraint(name):
    selected = fixtures.fixture(name)
    state = selected.initial_state
    rows: list[tuple[int, ...]] = []
    for _ in range(16):
        rows.append(selected.row(state))
        state = selected.step(state)
    final = (rows[-1][0],) if name == "poseidon2" else rows[-1]
    public = selected.public_values(selected.initial_state, final)

    first_values = evaluate(selected.air, rows[0], rows[1], public)
    last_values = evaluate(selected.air, rows[-1], rows[-1], public)
    for constraint in selected.air["constraints"]:
        expression = int(constraint["expression"])
        if constraint["kind"] == "first_row":
            assert first_values[expression] == 0
        elif constraint["kind"] == "last_row":
            assert last_values[expression] == 0
        else:
            for index in range(len(rows) - 1):
                values = evaluate(selected.air, rows[index], rows[index + 1], public)
                assert values[expression] == 0


def test_customer_cubic8_exercises_degree_three_and_all_boundaries():
    air = fixtures.customer_cubic8().air
    assert air["trace_width"] == 8
    assert len(air["public_inputs"]) == 16
    assert sum(item["op"] == "mul" for item in air["expressions"]) == 16
    assert {item["kind"] for item in air["constraints"]} == {
        "first_row",
        "transition",
        "last_row",
    }


def test_public_evidence_rejects_secrets_and_urls():
    E2E.assert_public_evidence({"release_sha": "a" * 40, "proof_digest_hex": "b" * 64})
    with pytest.raises(RuntimeError, match="sensitive field"):
        E2E.assert_public_evidence({"api_key": "value"})
    with pytest.raises(RuntimeError, match="secret-like value"):
        E2E.assert_public_evidence({"download": "https://example.test/signed"})
    with pytest.raises(RuntimeError, match="secret-like value"):
        E2E.assert_public_evidence({"value": "sk_test_secret"})


def signed_attestation(attestation_type, kind=None):
    source_names = E2E.ATTESTATION_SOURCES[(attestation_type, kind)]
    value = {
        "schema_version": 1,
        "release_sha": "a" * 40,
        "attestation_type": attestation_type,
        "status": "passed",
        "source_evidence": [
            {
                "name": name,
                "sha256": hashlib.sha256(name.encode()).hexdigest(),
                "status": "passed",
                "validator": f"validate-{name}",
                "validator_sha256": hashlib.sha256(f"validate-{name}".encode()).hexdigest(),
            }
            for name in sorted(source_names)
        ],
    }
    if attestation_type == "billing":
        value.update(
            {
                "kind": kind,
                "synthetic": True,
                "refunded": True,
                "excluded_from_revenue": True,
                "cancelled": kind == "subscription",
            }
        )
    else:
        value.update({field: 0 for field in E2E.ATTESTATION_ZERO_FIELDS})
    key = b"k" * 32
    value["hmac_sha256"] = hmac.new(
        key, E2E.canonical_json(value), hashlib.sha256
    ).hexdigest()
    return value, key


@pytest.mark.parametrize("kind", ["topup", "subscription"])
def test_live_billing_attestation_is_release_bound_complete_and_signed(kind):
    value, key = signed_attestation("billing", kind)
    checked = E2E.validate_operator_attestation(
        value,
        release_sha="a" * 40,
        attestation_type="billing",
        kind=kind,
        hmac_key=key,
    )
    assert checked["attestation_hmac_verified"] is True
    assert len(checked["attestation_payload_sha256"]) == 64


def test_operator_attestation_rejects_tampering_and_missing_sources():
    value, key = signed_attestation("billing", "topup")
    value["refunded"] = False
    with pytest.raises(RuntimeError, match="HMAC"):
        E2E.validate_operator_attestation(
            value,
            release_sha="a" * 40,
            attestation_type="billing",
            kind="topup",
            hmac_key=key,
        )
    value, key = signed_attestation("audit")
    value["source_evidence"] = value["source_evidence"][:-1]
    unsigned = {key_: item for key_, item in value.items() if key_ != "hmac_sha256"}
    value["hmac_sha256"] = hmac.new(
        key, E2E.canonical_json(unsigned), hashlib.sha256
    ).hexdigest()
    with pytest.raises(RuntimeError, match="missing source evidence"):
        E2E.validate_operator_attestation(
            value,
            release_sha="a" * 40,
            attestation_type="audit",
            kind=None,
            hmac_key=key,
        )


def test_credit_snapshot_covers_available_and_reserved_balances():
    assert E2E.credit_snapshot(
        {
            "subscription_millicredits": 100,
            "purchased_millicredits": 200,
            "reserved_millicredits": 30,
        }
    ) == (100, 200, 30)


def test_truncated_signed_upload_accepts_only_explicit_fail_closed_outcomes():
    assert E2E.truncated_signed_upload_was_rejected(
        E2E.ApiFailure(403, {"error": "signature_mismatch"})
    )
    assert E2E.truncated_signed_upload_was_rejected(
        RemoteDisconnected("R2 closed a body shorter than signed Content-Length")
    )
    assert not E2E.truncated_signed_upload_was_rejected(
        E2E.ApiFailure(503, {"error": "infrastructure_unavailable"})
    )
    assert not E2E.truncated_signed_upload_was_rejected(ConnectionError("network outage"))


class Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self):
        return b""


def test_signed_upload_retries_transient_5xx_with_identical_request(monkeypatch):
    requests = []

    def urlopen(request, *, timeout):
        requests.append((request.full_url, request.data, dict(request.headers), timeout))
        if len(requests) == 1:
            raise HTTPError(request.full_url, 502, "bad gateway", {}, BytesIO())
        return Response()

    monkeypatch.setattr(E2E, "urlopen", urlopen)
    monkeypatch.setattr(E2E.time, "sleep", lambda _delay: None)
    signed = {
        "url": "https://example.invalid/object",
        "headers": {"content-length": "3", "x-amz-checksum-sha256": "digest"},
    }
    assert E2E.ApiClient("https://api.invalid", "key").put_signed(signed, b"abc") == 200
    assert len(requests) == 2
    assert requests[0] == requests[1]


def test_signed_upload_never_retries_a_permanent_4xx(monkeypatch):
    attempts = 0

    def urlopen(request, *, timeout):
        nonlocal attempts
        attempts += 1
        raise HTTPError(request.full_url, 403, "forbidden", {}, BytesIO())

    monkeypatch.setattr(E2E, "urlopen", urlopen)
    with pytest.raises(E2E.ApiFailure) as failure:
        E2E.ApiClient("https://api.invalid", "key").put_signed(
            {"url": "https://example.invalid/object", "headers": {}}, b"abc"
        )
    assert failure.value.status == 403
    assert attempts == 1
