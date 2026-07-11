from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/monitoring/api_health_audit.sh"


class FixtureHandler(BaseHTTPRequestHandler):
    reenable_path = ""
    wrong_code_path = ""
    discovery_status = "backend_recovery"

    def log_message(self, *_args):
        pass

    def _respond(self):
        path = self.path
        if path == "/discovery.json":
            return self._send(200, {"service_status": self.discovery_status})
        if path in {"/healthz", "/readyz", "/health", "/"}:
            return self._send(200, "ok")
        if path == "/mcp":
            return self._send(200, {"jsonrpc": "2.0", "result": {"protocolVersion": "2024-11-05"}})
        if path in {"/templates", "/estimate", "/prove", "/verify", "/v1/proofs", "/api/create-checkout", "/api/create-free-account", "/api/demo-prove"}:
            if path == self.reenable_path:
                return self._send(200, {"ok": True})
            code = "wrong_code" if path == self.wrong_code_path else "protocol_upgrade"
            return self._send(503, {"code": code})
        if path in {"/provision-free", "/session/resolve"}:
            return self._send(404, "")
        if path == "/research":
            return self._send(410, "retired")
        markers = {
            "/status": "Planned maintenance",
            "/security": "release gates",
            "/docs": "protocol_upgrade",
            "/pricing": "independent review",
        }
        if path in markers:
            return self._send(200, markers[path])
        return self._send(404, "missing")

    do_GET = _respond
    do_POST = _respond

    def _send(self, status, payload):
        body = json.dumps(payload).encode() if isinstance(payload, dict) else str(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def fixture_server(tmp_path):
    FixtureHandler.reenable_path = ""
    FixtureHandler.wrong_code_path = ""
    FixtureHandler.discovery_status = "backend_recovery"
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    env = os.environ | {
        "TINYZKP_AUDIT_MODE": "containment",
        "TINYZKP_AUDIT_API_BASE": base,
        "TINYZKP_AUDIT_SITE_BASE": base,
        "TINYZKP_AUDIT_WEBHOOK_BASE": base,
        "TINYZKP_AUDIT_MCP_BASE": base,
        "TINYZKP_AUDIT_LOG_DIR": str(tmp_path),
    }
    yield env
    server.shutdown()
    thread.join()


def run_audit(env):
    return subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)


def test_healthy_containment_contract_passes(fixture_server):
    result = run_audit(fixture_server)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULTS: 21/21 passed, 0 failed" in result.stdout


def test_accidentally_reenabled_checkout_fails(fixture_server):
    FixtureHandler.reenable_path = "/api/create-checkout"
    result = run_audit(fixture_server)
    assert result.returncode == 1
    assert "FAIL disabled checkout" in result.stdout


def test_wrong_protocol_error_code_fails(fixture_server):
    FixtureHandler.wrong_code_path = "/prove"
    result = run_audit(fixture_server)
    assert result.returncode == 1
    assert "expected='protocol_upgrade'" in result.stdout


def test_published_mode_disagreement_fails(fixture_server):
    FixtureHandler.discovery_status = "production"
    result = run_audit(fixture_server)
    assert result.returncode == 1
    assert "FAIL published recovery status" in result.stdout


def test_infrastructure_outage_fails(fixture_server):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        unused_port = sock.getsockname()[1]
    fixture_server["TINYZKP_AUDIT_API_BASE"] = f"http://127.0.0.1:{unused_port}"
    result = run_audit(fixture_server)
    assert result.returncode == 1
    assert "connection error" in result.stdout


def test_production_mode_requires_credentials(tmp_path):
    env = os.environ | {"TINYZKP_AUDIT_MODE": "production", "HOME": str(tmp_path)}
    env.pop("TINYZKP_AUDIT_API_KEY", None)
    env.pop("TINYZKP_INTERNAL_SECRET", None)
    result = run_audit(env)
    assert result.returncode == 2
    assert "requires TINYZKP_AUDIT_API_KEY and TINYZKP_INTERNAL_SECRET" in result.stderr


def test_missing_mode_fails_closed():
    env = os.environ.copy()
    env.pop("TINYZKP_AUDIT_MODE", None)
    result = run_audit(env)
    assert result.returncode == 2
    assert "must be explicitly set" in result.stderr
