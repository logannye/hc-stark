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
        observation("status", 200, b"All systems operational"),
        observation("mcp version", 200, {"service": "mcp"}),
    ])
    monkeypatch.setattr(canary, "request", lambda *args, **kwargs: next(responses))
    failures = canary.validate("https://site", "https://api", "https://mcp", 1)
    assert any("proving_available must be false" in failure for failure in failures)
    assert any("prove returned HTTP 200" in failure for failure in failures)
    assert any("legacy verify returned HTTP 200" in failure for failure in failures)
