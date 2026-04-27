"""Typed HTTP client for the TinyZKP proving API.

Both async and sync usage are supported. Async is recommended for production;
sync is convenient for scripts and notebooks.

Async::

    import asyncio
    from tinyzkp import TinyZKP

    async def main():
        async with TinyZKP("https://api.tinyzkp.com", api_key="tzk_...") as client:
            job_id = await client.prove_template(
                "range_proof",
                params={"min": 0, "max": 100, "witness_steps": [42, 44]},
            )
            proof = await client.wait_for_proof(job_id)
            result = await client.verify(proof)
            assert result.ok

    asyncio.run(main())

Sync::

    from tinyzkp import TinyZKPSync

    with TinyZKPSync("https://api.tinyzkp.com", api_key="tzk_...") as client:
        job_id = client.prove_template(
            "range_proof",
            params={"min": 0, "max": 100, "witness_steps": [42, 44]},
        )
        proof = client.wait_for_proof(job_id)
        assert client.verify(proof).ok
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx


@dataclass
class ProofBytes:
    """Serialized proof payload."""

    version: int
    bytes: bytes

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "bytes": list(self.bytes)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProofBytes:
        raw = data.get("bytes", [])
        if isinstance(raw, list):
            raw = bytes(raw)
        elif isinstance(raw, str):
            raw = raw.encode("utf-8")
        return cls(version=data["version"], bytes=raw)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class VerifyResult:
    ok: bool
    error: Optional[str] = None


@dataclass
class ProveJobStatus:
    """Status of a submitted prove job."""

    status: str  # "pending", "running", "succeeded", "failed"
    proof: Optional[ProofBytes] = None
    error: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProveJobStatus:
        status = data["status"]
        proof = None
        if status == "succeeded" and "proof" in data:
            proof = ProofBytes.from_dict(data["proof"])
        return cls(
            status=status,
            proof=proof,
            error=data.get("error"),
        )


@dataclass
class TemplateSummary:
    id: str
    summary: str
    tags: list[str]
    cost_category: str
    backend: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TemplateSummary:
        return cls(
            id=data["id"],
            summary=data.get("summary", ""),
            tags=list(data.get("tags", [])),
            cost_category=data.get("cost_category", ""),
            backend=data.get("backend", "vm"),
        )


class HcClientError(Exception):
    """Raised when an API request fails with a non-2xx status."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"HTTP {status_code}: {message}")


def _headers(api_key: Optional[str]) -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if api_key:
        h["Authorization"] = f"Bearer {api_key}"
    return h


def _build_prove_body(
    *,
    program: Optional[list[str]] = None,
    workload_id: Optional[str] = None,
    initial_acc: int = 0,
    final_acc: int = 0,
    block_size: int = 2,
    fri_final_poly_size: int = 2,
    query_count: int = 30,
    lde_blowup_factor: int = 2,
    zk_mask_degree: Optional[int] = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "initial_acc": initial_acc,
        "final_acc": final_acc,
        "block_size": block_size,
        "fri_final_poly_size": fri_final_poly_size,
        "query_count": query_count,
        "lde_blowup_factor": lde_blowup_factor,
    }
    if program is not None:
        body["program"] = program
    if workload_id is not None:
        body["workload_id"] = workload_id
    if zk_mask_degree is not None:
        body["zk_mask_degree"] = zk_mask_degree
    return body


def _build_template_body(
    params: dict[str, Any],
    *,
    zk: Optional[bool] = None,
    block_size: Optional[int] = None,
    fri_final_poly_size: Optional[int] = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"params": params}
    if zk is not None:
        body["zk"] = zk
    if block_size is not None:
        body["block_size"] = block_size
    if fri_final_poly_size is not None:
        body["fri_final_poly_size"] = fri_final_poly_size
    return body


# ── Async client ─────────────────────────────────────────────────────────────


class HcClient:
    """Async HTTP client for the TinyZKP proving server.

    Use as an async context manager: ``async with HcClient(...) as client``.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._session: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> HcClient:
        self._session = httpx.AsyncClient(
            base_url=self.base_url,
            headers=_headers(self.api_key),
            timeout=self.timeout,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session is not None:
            await self._session.aclose()
            self._session = None

    async def _request(self, method: str, path: str, *, json_body: Any = None) -> Any:
        if self._session is None:
            raise RuntimeError("Client not initialized; use `async with HcClient(...):`")
        resp = await self._session.request(method, path, json=json_body)
        if resp.status_code >= 400:
            raise HcClientError(resp.status_code, resp.text)
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return None

    async def healthz(self) -> bool:
        """Check server health. Returns True on 200, False otherwise."""
        try:
            await self._request("GET", "/healthz")
            return True
        except HcClientError:
            return False

    async def templates(self) -> list[TemplateSummary]:
        """List all available proof templates (no auth required)."""
        data = await self._request("GET", "/templates")
        return [TemplateSummary.from_dict(t) for t in data.get("templates", [])]

    async def template(self, template_id: str) -> dict[str, Any]:
        """Get full template info including parameter schema (no auth required)."""
        return await self._request("GET", f"/templates/{template_id}")

    async def verify(self, proof: ProofBytes, *, allow_legacy_v2: bool = True) -> VerifyResult:
        """Verify a proof. Always free; never charges your usage."""
        body = {"proof": proof.to_dict(), "allow_legacy_v2": allow_legacy_v2}
        data = await self._request("POST", "/verify", json_body=body)
        return VerifyResult(ok=data["ok"], error=data.get("error"))

    async def prove(self, **kwargs: Any) -> str:
        """Submit a raw prove job and return the job_id."""
        body = _build_prove_body(**kwargs)
        data = await self._request("POST", "/prove", json_body=body)
        return data["job_id"]

    async def prove_template(
        self,
        template_id: str,
        params: dict[str, Any],
        *,
        zk: Optional[bool] = None,
        block_size: Optional[int] = None,
        fri_final_poly_size: Optional[int] = None,
    ) -> str:
        """Submit a prove job using a named template. Returns the job_id."""
        body = _build_template_body(
            params, zk=zk, block_size=block_size, fri_final_poly_size=fri_final_poly_size
        )
        data = await self._request("POST", f"/prove/template/{template_id}", json_body=body)
        return data["job_id"]

    async def prove_status(self, job_id: str) -> ProveJobStatus:
        """Get the status of a prove job."""
        data = await self._request("GET", f"/prove/{job_id}")
        return ProveJobStatus.from_dict(data)

    async def wait_for_proof(
        self,
        job_id: str,
        *,
        poll_interval: float = 1.0,
        timeout: float = 300.0,
    ) -> ProofBytes:
        """Poll until the job completes; return the proof on success."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            status = await self.prove_status(job_id)
            if status.status == "succeeded" and status.proof is not None:
                return status.proof
            if status.status == "failed":
                raise HcClientError(500, status.error or "prove job failed")
            await asyncio.sleep(poll_interval)
        raise TimeoutError(f"prove job {job_id} did not complete within {timeout}s")


# ── Sync client ──────────────────────────────────────────────────────────────


class HcClientSync:
    """Synchronous HTTP client for scripts and notebooks.

    Mirrors HcClient one-for-one but blocks on each call.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._session: Optional[httpx.Client] = None

    def __enter__(self) -> HcClientSync:
        self._session = httpx.Client(
            base_url=self.base_url,
            headers=_headers(self.api_key),
            timeout=self.timeout,
        )
        return self

    def __exit__(self, *args: Any) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def _request(self, method: str, path: str, *, json_body: Any = None) -> Any:
        if self._session is None:
            raise RuntimeError("Client not initialized; use `with HcClientSync(...):`")
        resp = self._session.request(method, path, json=json_body)
        if resp.status_code >= 400:
            raise HcClientError(resp.status_code, resp.text)
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return None

    def healthz(self) -> bool:
        try:
            self._request("GET", "/healthz")
            return True
        except HcClientError:
            return False

    def templates(self) -> list[TemplateSummary]:
        data = self._request("GET", "/templates")
        return [TemplateSummary.from_dict(t) for t in data.get("templates", [])]

    def template(self, template_id: str) -> dict[str, Any]:
        return self._request("GET", f"/templates/{template_id}")

    def verify(self, proof: ProofBytes, *, allow_legacy_v2: bool = True) -> VerifyResult:
        body = {"proof": proof.to_dict(), "allow_legacy_v2": allow_legacy_v2}
        data = self._request("POST", "/verify", json_body=body)
        return VerifyResult(ok=data["ok"], error=data.get("error"))

    def prove(self, **kwargs: Any) -> str:
        body = _build_prove_body(**kwargs)
        data = self._request("POST", "/prove", json_body=body)
        return data["job_id"]

    def prove_template(
        self,
        template_id: str,
        params: dict[str, Any],
        *,
        zk: Optional[bool] = None,
        block_size: Optional[int] = None,
        fri_final_poly_size: Optional[int] = None,
    ) -> str:
        body = _build_template_body(
            params, zk=zk, block_size=block_size, fri_final_poly_size=fri_final_poly_size
        )
        data = self._request("POST", f"/prove/template/{template_id}", json_body=body)
        return data["job_id"]

    def prove_status(self, job_id: str) -> ProveJobStatus:
        data = self._request("GET", f"/prove/{job_id}")
        return ProveJobStatus.from_dict(data)

    def wait_for_proof(
        self,
        job_id: str,
        *,
        poll_interval: float = 1.0,
        timeout: float = 300.0,
    ) -> ProofBytes:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.prove_status(job_id)
            if status.status == "succeeded" and status.proof is not None:
                return status.proof
            if status.status == "failed":
                raise HcClientError(500, status.error or "prove job failed")
            time.sleep(poll_interval)
        raise TimeoutError(f"prove job {job_id} did not complete within {timeout}s")
