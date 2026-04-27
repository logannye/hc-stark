import { test } from "node:test";
import assert from "node:assert/strict";
import { HcClient, HcClientError, TinyZKP } from "../dist/client.js";

// Mock fetch for the duration of one test, restoring it after.
function withMockedFetch(
  handler: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
  fn: () => Promise<void>,
): () => Promise<void> {
  return async () => {
    const original = globalThis.fetch;
    globalThis.fetch = handler as typeof globalThis.fetch;
    try {
      await fn();
    } finally {
      globalThis.fetch = original;
    }
  };
}

test(
  "healthz returns true on 200",
  withMockedFetch(
    async (input) => {
      assert.match(String(input), /\/healthz$/);
      return new Response(null, { status: 200 });
    },
    async () => {
      const client = new HcClient("https://api.example.com");
      assert.equal(await client.healthz(), true);
    },
  ),
);

test(
  "healthz returns false on error",
  withMockedFetch(
    async () => new Response("nope", { status: 500 }),
    async () => {
      const client = new HcClient("https://api.example.com");
      assert.equal(await client.healthz(), false);
    },
  ),
);

test(
  "templates() parses list response",
  withMockedFetch(
    async () =>
      new Response(
        JSON.stringify({
          count: 1,
          templates: [
            {
              id: "range_proof",
              summary: "Prove value in [min,max]",
              tags: ["arithmetic"],
              cost_category: "small",
              backend: "vm",
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    async () => {
      const client = new HcClient("https://api.example.com");
      const templates = await client.templates();
      assert.equal(templates.length, 1);
      assert.equal(templates[0]?.id, "range_proof");
    },
  ),
);

test(
  "proveTemplate sends auth header and returns job_id",
  withMockedFetch(
    async (input, init) => {
      assert.match(String(input), /\/prove\/template\/range_proof$/);
      assert.equal(init?.method, "POST");
      const headers = init?.headers as Record<string, string>;
      assert.equal(headers.Authorization, "Bearer tzk_test");
      return new Response(JSON.stringify({ job_id: "prf_abc" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
    async () => {
      const client = new HcClient("https://api.example.com", { apiKey: "tzk_test" });
      const jobId = await client.proveTemplate("range_proof", {
        min: 0,
        max: 100,
        witness_steps: [42, 44],
      });
      assert.equal(jobId, "prf_abc");
    },
  ),
);

test(
  "verify returns ok=true",
  withMockedFetch(
    async () =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    async () => {
      const client = new HcClient("https://api.example.com");
      const result = await client.verify({ version: 3, bytes: [1, 2, 3] });
      assert.equal(result.ok, true);
    },
  ),
);

test(
  "non-2xx raises HcClientError",
  withMockedFetch(
    async () => new Response("rate limited", { status: 429 }),
    async () => {
      const client = new HcClient("https://api.example.com");
      await assert.rejects(
        () => client.verify({ version: 3, bytes: [] }),
        (err: unknown) => {
          assert.ok(err instanceof HcClientError);
          assert.equal((err as HcClientError).statusCode, 429);
          return true;
        },
      );
    },
  ),
);

test("TinyZKP alias is exported", () => {
  assert.equal(TinyZKP, HcClient);
});
