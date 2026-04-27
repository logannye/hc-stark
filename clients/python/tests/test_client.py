"""Unit tests for the TinyZKP Python client.

These hit a respx mock — no live API required.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from tinyzkp import (
    HcClient,
    HcClientError,
    HcClientSync,
    ProofBytes,
    TemplateSummary,
)


@pytest.mark.asyncio
async def test_async_healthz_ok():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/healthz").mock(return_value=httpx.Response(200))
        async with HcClient("https://api.example.com") as client:
            assert await client.healthz() is True


@pytest.mark.asyncio
async def test_async_templates_list():
    payload = {
        "count": 1,
        "templates": [
            {
                "id": "range_proof",
                "summary": "Prove a value is in [min, max]",
                "tags": ["arithmetic"],
                "cost_category": "small",
                "backend": "vm",
            }
        ],
    }
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/templates").mock(return_value=httpx.Response(200, json=payload))
        async with HcClient("https://api.example.com") as client:
            templates = await client.templates()
            assert len(templates) == 1
            assert isinstance(templates[0], TemplateSummary)
            assert templates[0].id == "range_proof"
            assert templates[0].backend == "vm"


@pytest.mark.asyncio
async def test_async_prove_template_returns_job_id():
    payload = {"job_id": "prf_abc123"}
    with respx.mock(base_url="https://api.example.com") as mock:
        route = mock.post("/prove/template/range_proof").mock(
            return_value=httpx.Response(200, json=payload)
        )
        async with HcClient("https://api.example.com", api_key="tzk_test") as client:
            job_id = await client.prove_template(
                "range_proof",
                params={"min": 0, "max": 100, "witness_steps": [42, 44]},
            )
            assert job_id == "prf_abc123"
            assert route.called
            req = route.calls.last.request
            assert req.headers["authorization"] == "Bearer tzk_test"


@pytest.mark.asyncio
async def test_async_verify_ok():
    payload = {"ok": True}
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.post("/verify").mock(return_value=httpx.Response(200, json=payload))
        async with HcClient("https://api.example.com") as client:
            result = await client.verify(ProofBytes(version=3, bytes=b"\x01\x02"))
            assert result.ok


@pytest.mark.asyncio
async def test_async_error_raises_hc_client_error():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.post("/verify").mock(return_value=httpx.Response(429, text="rate limited"))
        async with HcClient("https://api.example.com") as client:
            with pytest.raises(HcClientError) as exc:
                await client.verify(ProofBytes(version=3, bytes=b""))
            assert exc.value.status_code == 429


def test_sync_healthz_ok():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/healthz").mock(return_value=httpx.Response(200))
        with HcClientSync("https://api.example.com") as client:
            assert client.healthz() is True


def test_sync_prove_template_returns_job_id():
    payload = {"job_id": "prf_sync"}
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.post("/prove/template/range_proof").mock(
            return_value=httpx.Response(200, json=payload)
        )
        with HcClientSync("https://api.example.com", api_key="tzk_test") as client:
            job_id = client.prove_template("range_proof", params={"min": 0, "max": 100})
            assert job_id == "prf_sync"


def test_proof_bytes_roundtrip():
    p = ProofBytes(version=3, bytes=b"\xde\xad\xbe\xef")
    assert ProofBytes.from_dict(p.to_dict()) == p
