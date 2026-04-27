// ESM test — runs against the built ESM output.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HcClient, HcClientError, ProofBytes, TinyZKP } from "../dist/esm/client.js";

function withMockedFetch(handler, fn) {
  return async () => {
    const original = globalThis.fetch;
    globalThis.fetch = handler;
    try { await fn(); } finally { globalThis.fetch = original; }
  };
}

test("healthz returns true on 200", withMockedFetch(
  async (input) => { assert.match(String(input), /\/healthz$/); return new Response(null, { status: 200 }); },
  async () => {
    const c = new HcClient("https://api.example.com");
    assert.equal(await c.healthz(), true);
  },
));

test("healthz returns false on error", withMockedFetch(
  async () => new Response("nope", { status: 500 }),
  async () => {
    const c = new HcClient("https://api.example.com");
    assert.equal(await c.healthz(), false);
  },
));

test("templates() parses list response", withMockedFetch(
  async () => new Response(JSON.stringify({
    count: 1,
    templates: [{ id: "range_proof", summary: "x", tags: ["a"], cost_category: "small", backend: "vm" }],
  }), { status: 200, headers: { "content-type": "application/json" } }),
  async () => {
    const c = new HcClient("https://api.example.com");
    const t = await c.templates();
    assert.equal(t.length, 1);
    assert.equal(t[0].id, "range_proof");
  },
));

test("proveTemplate sends auth header and returns job_id", withMockedFetch(
  async (input, init) => {
    assert.match(String(input), /\/prove\/template\/range_proof$/);
    assert.equal(init?.method, "POST");
    assert.equal(init?.headers.Authorization, "Bearer tzk_test");
    return new Response(JSON.stringify({ job_id: "prf_abc" }), { status: 200, headers: { "content-type": "application/json" } });
  },
  async () => {
    const c = new HcClient("https://api.example.com", { apiKey: "tzk_test" });
    const jobId = await c.proveTemplate("range_proof", { min: 0, max: 100, witness_steps: [42, 44] });
    assert.equal(jobId, "prf_abc");
  },
));

test("verify returns ok=true", withMockedFetch(
  async () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } }),
  async () => {
    const c = new HcClient("https://api.example.com");
    const result = await c.verify({ version: 3, bytes: [1, 2, 3] });
    assert.equal(result.ok, true);
  },
));

test("non-2xx raises HcClientError", withMockedFetch(
  async () => new Response("rate limited", { status: 429 }),
  async () => {
    const c = new HcClient("https://api.example.com");
    await assert.rejects(
      () => c.verify({ version: 3, bytes: [] }),
      (err) => err instanceof HcClientError && err.statusCode === 429,
    );
  },
));

test("TinyZKP alias is exported", () => {
  assert.equal(TinyZKP, HcClient);
});

test("ProofBytes is a runtime class", () => {
  const p = new ProofBytes(3, [1, 2, 3]);
  assert.equal(p.version, 3);
  assert.deepEqual(p.bytes, [1, 2, 3]);
  assert.ok(p instanceof ProofBytes);
  assert.deepEqual(p.toJSON(), { version: 3, bytes: [1, 2, 3] });
  const p2 = ProofBytes.from({ version: 4, bytes: [9] });
  assert.ok(p2 instanceof ProofBytes);
  assert.equal(p2.version, 4);
});

test("proveStatus wraps succeeded proof in ProofBytes", withMockedFetch(
  async () => new Response(JSON.stringify({
    status: "succeeded",
    proof: { version: 3, bytes: [1, 2, 3] },
  }), { status: 200, headers: { "content-type": "application/json" } }),
  async () => {
    const c = new HcClient("https://api.example.com");
    const status = await c.proveStatus("prf_abc");
    assert.equal(status.status, "succeeded");
    assert.ok(status.proof instanceof ProofBytes);
    assert.equal(status.proof.version, 3);
  },
));
