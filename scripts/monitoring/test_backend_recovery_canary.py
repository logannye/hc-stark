import json

import backend_recovery_canary as canary


def observation(name: str, status: int, payload: object) -> canary.Observation:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return canary.Observation(name, status, body)


def test_validate_accepts_consistent_maintenance_surfaces(monkeypatch):
    responses = iter([
        observation("capabilities", 200, {
            "service_status": "backend_recovery",
            "proving_available": False,
            "verification_available": False,
            "checkout_enabled": False,
            "account_creation_enabled": False,
        }),
        observation("prove", 503, {"code": "protocol_upgrade"}),
        observation("legacy verify", 422, {"code": "legacy_statement_unbound"}),
        observation("checkout", 503, {"code": "protocol_upgrade"}),
        observation("homepage", 200, b"Backend recovery in progress"),
        observation(
            "contact",
            200,
            b'<input name="email" type="email"><select name="contact_method" required></select><input name="contact_handle" required><p>No email will be sent.</p>',
        ),
        observation("security", 200, b"HTTPS security reporting"),
        observation("privacy", 200, b"HTTPS privacy requests"),
        observation("terms", 200, b"HTTPS operational requests"),
        observation(
            "requests",
            200,
            b'<form id="request-form"><select name="category" required></select><select name="contact_method" required></select><input name="contact_handle" required><p>No email is sent</p></form>',
        ),
        observation("unknown path", 404, b"not found"),
        observation(
            "security.txt",
            200,
            b"Contact: https://site/requests?intent=security\nExpires: 2027-07-10T00:00:00Z\n",
        ),
        observation("retired website MCP card", 410, b"gone"),
        observation("retired verifier JavaScript", 410, b"gone"),
        observation("retired verifier WASM", 410, b"gone"),
        observation("status", 200, b"Backend recovery in progress"),
        observation("mcp version", 200, {"service": "mcp"}),
    ])
    monkeypatch.setattr(canary, "request", lambda *args, **kwargs: next(responses))
    assert canary.validate("https://site", "https://api", "https://mcp", 1) == []


def test_validate_rejects_enabled_proving_and_legacy_acceptance(monkeypatch):
    responses = iter([
        observation("capabilities", 200, {
            "service_status": "operational",
            "proving_available": True,
            "verification_available": False,
            "checkout_enabled": False,
            "account_creation_enabled": False,
        }),
        observation("prove", 200, {"proof": "unsafe"}),
        observation("legacy verify", 200, {"valid": True}),
        observation("checkout", 503, {"code": "protocol_upgrade"}),
        observation("homepage", 200, b"All systems operational"),
        observation(
            "contact",
            200,
            b'<input name="email" type="email" required>',
        ),
        observation("security", 200, b"Email security@tinyzkp.com"),
        observation("privacy", 200, b"Privacy"),
        observation("terms", 200, b"mailto:hello@tinyzkp.com"),
        observation("requests", 404, b"missing"),
        observation("unknown path", 200, b"homepage fallback"),
        observation("security.txt", 200, b"Contact: mailto:logan@tinyzkp.com\n"),
        observation("retired website MCP card", 200, b'{"tools":["prove_template"]}'),
        observation("retired verifier JavaScript", 200, b"legacy verifier"),
        observation("retired verifier WASM", 200, b"legacy verifier"),
        observation("status", 200, b"All systems operational"),
        observation("mcp version", 200, {"service": "mcp"}),
    ])
    monkeypatch.setattr(canary, "request", lambda *args, **kwargs: next(responses))
    failures = canary.validate("https://site", "https://api", "https://mcp", 1)
    assert any("proving_available must be false" in failure for failure in failures)
    assert any("prove returned HTTP 200" in failure for failure in failures)
    assert any("legacy verify returned HTTP 200" in failure for failure in failures)
    assert any("contact email field must exist and remain optional" in failure for failure in failures)
    assert any("contact must require a no-email reply channel" in failure for failure in failures)
    assert any("contact must require a no-email reply handle" in failure for failure in failures)
    assert any("contact does not disclose the no-email recovery policy" in failure for failure in failures)
    assert any("security publishes a forbidden email contact" in failure for failure in failures)
    assert any("terms publishes a forbidden email contact" in failure for failure in failures)
    assert any("security.txt must publish HTTPS Contact fields only" in failure for failure in failures)
    assert any("obsolete website MCP server card" in failure for failure in failures)
    assert any("retired verifier JavaScript must return" in failure for failure in failures)
    assert any("retired verifier WASM must return" in failure for failure in failures)
    assert any("requests route is not the operational request form" in failure for failure in failures)
    assert any("unknown website path returned HTTP 200" in failure for failure in failures)
