#!/usr/bin/env node
// End-to-end test for `POST /v1/estimate` against the worker's *real* fetch
// handler — a `Request` goes in, a `Response` comes out, exactly as a real
// caller would receive it. Nothing here asserts on an in-process helper or a
// value read out of module internals; every assertion reads the `Response`
// (status, headers, parsed JSON body) `_worker.js` itself constructs.
import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { register } from "node:module";
import { tmpdir } from "node:os";
import test from "node:test";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = process.cwd();

// `_worker.js` statically imports a `.wasm` module — the correct, Wrangler-
// native form for an ES-module-format Worker (confirmed against a real
// `wrangler pages dev` run against `compatibility_date = "2025-12-01"`: a
// bare `.wasm` import resolves to a `WebAssembly.Module`, matching
// Cloudflare's documented behavior). Plain Node has no built-in support for
// that extension without a loader hook, so this registers one — scoped to
// this test process only, never shipped in the Worker itself — that
// reproduces the same "give me a Module" contract from the raw file bytes.
const WASM_LOADER_SOURCE = `
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
export async function load(url, context, nextLoad) {
  if (url.endsWith(".wasm")) {
    const bytes = await readFile(fileURLToPath(url));
    const source = "const bytes = Uint8Array.from(atob(" +
      JSON.stringify(bytes.toString("base64")) +
      "), (c) => c.charCodeAt(0));\\nexport default new WebAssembly.Module(bytes);\\n";
    return { format: "module", source, shortCircuit: true };
  }
  return nextLoad(url, context);
}
`;
register(`data:text/javascript,${encodeURIComponent(WASM_LOADER_SOURCE)}`, import.meta.url);

// `ANON_RATE_LIMIT_PER_HOUR` is deliberately NOT a named export of
// `_worker.js`: Cloudflare Pages' Advanced Mode runtime treats every
// top-level export as a candidate handler/Durable Object binding and
// refuses to start the Worker if one isn't a function or `ExportedHandler`
// (confirmed against a real `wrangler pages dev` run — adding a second
// named export there hard-crashes the Worker at startup). This reads the
// constant back out of the committed source text instead, so the test
// tracks the worker's real configured value without the test and the
// worker being able to silently drift apart, and without reintroducing the
// export that breaks the real runtime.
const ANON_RATE_LIMIT_SOURCE_RE = /const ANON_RATE_LIMIT_PER_HOUR = (\d+);/;

async function importWorker() {
  const temp = await mkdtemp(path.join(tmpdir(), "tinyzkp-estimate-worker-"));
  const workerSource = await readFile(path.join(root, "site", "_worker.js"), "utf8");
  const anonRateLimitMatch = workerSource.match(ANON_RATE_LIMIT_SOURCE_RE);
  assert.ok(anonRateLimitMatch, "site/_worker.js must declare `const ANON_RATE_LIMIT_PER_HOUR = <number>;`");
  const anonRateLimitPerHour = Number(anonRateLimitMatch[1]);

  await cp(path.join(root, "site", "_worker.js"), path.join(temp, "_worker.js"));
  await cp(
    path.join(root, "site", "vendor", "tinyzkp-estimate"),
    path.join(temp, "vendor", "tinyzkp-estimate"),
    { recursive: true },
  );
  await writeFile(path.join(temp, "package.json"), '{"type":"module"}\n');
  const module = await import(pathToFileURL(path.join(temp, "_worker.js")).href);
  return {
    worker: module.default,
    anonRateLimitPerHour,
    cleanup: () => rm(temp, { recursive: true, force: true }),
  };
}

function assetsMock() {
  return { async fetch() { return new Response("missing", { status: 404 }); } };
}

// A hand-written D1 stub, not a general SQL engine. This test suite runs on
// Node 20 (see .github/workflows/ci.yml's `node-version: "20"`), which
// predates `node:sqlite` (available from Node 22.5+); the worker's actual
// binding *mechanism* — `[[d1_databases]]` in site/wrangler.toml resolving
// to a real local D1 database — was instead verified directly against real
// `wrangler pages dev`/`wrangler d1 migrations apply --local` (Wrangler
// 4.85.0, matching toolchains/cloudflare/package.json's pinned version).
// This stub only needs to reproduce the exact query shape `site/_worker.js`
// issues for `rate_limit_windows` (see
// migrations/0000_rate_limit_windows.sql) faithfully enough to exercise the
// worker's own logic -- not to validate SQL.
function createD1Stub({ failRateLimit = false } = {}) {
  const rateLimitCounts = new Map();
  return {
    prepare(sql) {
      const normalized = sql.replace(/\s+/g, " ").trim();
      let boundArgs = [];
      const statement = {
        bind(...values) {
          boundArgs = values;
          return statement;
        },
        async first() {
          if (!normalized.includes("rate_limit_windows")) {
            throw new Error(`D1 stub: unsupported .first() query: ${normalized}`);
          }
          if (failRateLimit) throw new Error("D1 stub: injected rate-limit failure");
          const [ipHash, windowStart] = boundArgs;
          const key = `${ipHash}:${windowStart}`;
          const next = (rateLimitCounts.get(key) || 0) + 1;
          rateLimitCounts.set(key, next);
          return { request_count: next };
        },
      };
      return statement;
    },
  };
}

const SP1_SHAPED_REQUEST = JSON.stringify({
  schema_version: 1,
  field: "babybear",
  extension_degree: 4,
  logical_rows: 4194304,
  trace_width: 180,
  max_constraint_degree: 3,
  public_values: 8,
  has_next_row_columns: true,
  features: {
    uses_lookups: true,
    uses_buses: false,
    uses_permutations: false,
    uses_multi_table: true,
    uses_preprocessed_columns: false,
    uses_periodic_columns: false,
    uses_recursion: false,
    uses_gpu: false,
  },
  ram_budget_bytes: 2147483648,
});

test("POST /v1/estimate returns 200 with non-zero bounded and conventional estimates", async () => {
  const { worker, cleanup } = await importWorker();
  try {
    const response = await worker.fetch(
      new Request("https://tinyzkp.com/v1/estimate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: SP1_SHAPED_REQUEST,
      }),
      { ASSETS: assetsMock() },
    );
    assert.equal(response.status, 200);
    assert.match(response.headers.get("Content-Type"), /application\/json/);
    const body = await response.json();
    assert.equal(body.schema_version, 1);
    assert.ok(body.estimates.bounded.peak_resident_bytes > 0);
    assert.ok(body.estimates.conventional.peak_resident_bytes > 0);
    // The whole point of the bounded-space engine: it must actually be
    // cheaper than the conventional estimate for a config this shape.
    assert.ok(body.estimates.conventional.peak_resident_bytes > body.estimates.bounded.peak_resident_bytes);
  } finally {
    await cleanup();
  }
});

test("POST /v1/estimate with a malformed body returns a structured error, never internal_error", async () => {
  const { worker, cleanup } = await importWorker();
  try {
    const response = await worker.fetch(
      new Request("https://tinyzkp.com/v1/estimate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{ not json",
      }),
      { ASSETS: assetsMock() },
    );
    assert.equal(response.status, 200); // the engine's error envelope, not an HTTP failure
    assert.match(response.headers.get("Content-Type"), /application\/json/);
    const body = await response.json();
    assert.equal(body.ok, false);
    assert.ok(body.error.reason.code);
    assert.notEqual(body.error.reason.code, "internal_error");
    assert.notEqual(body.error.class, "internal_error");
  } finally {
    await cleanup();
  }
});

test("GET /v1/estimate returns 405", async () => {
  const { worker, cleanup } = await importWorker();
  try {
    const response = await worker.fetch(
      new Request("https://tinyzkp.com/v1/estimate", { method: "GET" }),
      { ASSETS: assetsMock() },
    );
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("Allow"), "POST");
  } finally {
    await cleanup();
  }
});

test("PUT /v1/estimate returns 405", async () => {
  const { worker, cleanup } = await importWorker();
  try {
    const response = await worker.fetch(
      new Request("https://tinyzkp.com/v1/estimate", { method: "PUT", body: "{}" }),
      { ASSETS: assetsMock() },
    );
    assert.equal(response.status, 405);
  } finally {
    await cleanup();
  }
});

test("an oversized body is rejected the same way malformed JSON is, not with internal_error", async () => {
  const { worker, cleanup } = await importWorker();
  try {
    const oversized = `{"padding":"${"x".repeat(9000)}"}`;
    const response = await worker.fetch(
      new Request("https://tinyzkp.com/v1/estimate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: oversized,
      }),
      { ASSETS: assetsMock() },
    );
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.ok, false);
    assert.notEqual(body.error.reason.code, "internal_error");
  } finally {
    await cleanup();
  }
});

test("/v1/estimate response carries the site's security headers", async () => {
  const { worker, cleanup } = await importWorker();
  try {
    const response = await worker.fetch(
      new Request("https://tinyzkp.com/v1/estimate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: SP1_SHAPED_REQUEST,
      }),
      { ASSETS: assetsMock() },
    );
    assert.match(response.headers.get("Content-Security-Policy"), /connect-src 'self' https:\/\/cloudflareinsights\.com/);
    assert.equal(response.headers.get("X-Frame-Options"), "DENY");
  } finally {
    await cleanup();
  }
});

// --- Task 3: anonymous rate limiting ---------------------------------

function estimateRequest(ip) {
  return new Request("https://tinyzkp.com/v1/estimate", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip },
    body: SP1_SHAPED_REQUEST,
  });
}

test("POST /v1/estimate rate-limits one anonymous IP after N requests/hour; a different IP is unaffected", async () => {
  const { worker, anonRateLimitPerHour, cleanup } = await importWorker();
  try {
    assert.equal(typeof anonRateLimitPerHour, "number");
    assert.ok(anonRateLimitPerHour > 0);
    const env = { ASSETS: assetsMock(), DB: createD1Stub() };

    for (let i = 1; i <= anonRateLimitPerHour; i += 1) {
      const response = await worker.fetch(estimateRequest("203.0.113.7"), env);
      assert.equal(response.status, 200, `request ${i} of ${anonRateLimitPerHour} must be within the window`);
    }

    // The N+1th request from the same IP within the window is rejected.
    const limited = await worker.fetch(estimateRequest("203.0.113.7"), env);
    assert.equal(limited.status, 429);
    const retryAfter = Number(limited.headers.get("Retry-After"));
    assert.ok(Number.isFinite(retryAfter) && retryAfter > 0);
    const limitedBody = await limited.json();
    assert.equal(limitedBody.ok, false);

    // A different IP has its own independent window.
    const otherIp = await worker.fetch(estimateRequest("203.0.113.99"), env);
    assert.equal(otherIp.status, 200);
  } finally {
    await cleanup();
  }
});

test("a D1 rate-limit-store failure fails open instead of blocking the estimator", async () => {
  const { worker, anonRateLimitPerHour, cleanup } = await importWorker();
  try {
    const env = { ASSETS: assetsMock(), DB: createD1Stub({ failRateLimit: true }) };
    for (let i = 0; i < anonRateLimitPerHour + 5; i += 1) {
      const response = await worker.fetch(estimateRequest("203.0.113.5"), env);
      assert.equal(response.status, 200, "a broken rate-limit store must never itself return 429");
    }
  } finally {
    await cleanup();
  }
});
