#!/usr/bin/env node
// End-to-end test for `POST /v1/estimate` against the worker's *real* fetch
// handler — a `Request` goes in, a `Response` comes out, exactly as a real
// caller would receive it. Nothing here asserts on an in-process helper or a
// value read out of module internals; every assertion reads the `Response`
// (status, headers, parsed JSON body) `_worker.js` itself constructs.
import assert from "node:assert/strict";
import { cp, mkdtemp, rm, writeFile } from "node:fs/promises";
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

async function importWorker() {
  const temp = await mkdtemp(path.join(tmpdir(), "tinyzkp-estimate-worker-"));
  await cp(path.join(root, "site", "_worker.js"), path.join(temp, "_worker.js"));
  await cp(
    path.join(root, "site", "vendor", "tinyzkp-estimate"),
    path.join(temp, "vendor", "tinyzkp-estimate"),
    { recursive: true },
  );
  await writeFile(path.join(temp, "package.json"), '{"type":"module"}\n');
  const module = await import(pathToFileURL(path.join(temp, "_worker.js")).href);
  return { worker: module.default, cleanup: () => rm(temp, { recursive: true, force: true }) };
}

function assetsMock() {
  return { async fetch() { return new Response("missing", { status: 404 }); } };
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
