import assert from "node:assert/strict";
import { TARGETS, probe } from "./worker.js";

const originalFetch = globalThis.fetch;

function responseFor(target, override = {}) {
  const body = override.body ?? (target.jsonField ? JSON.stringify({ [target.jsonField]: target.jsonValue }) : target.contains) ?? "ok";
  const status = override.status ?? target.expect;
  return new Response(body, { status });
}

try {
  for (const target of TARGETS) {
    globalThis.fetch = async (_url, options) => {
      assert.equal(options.method, target.method || "GET");
      return responseFor(target);
    };
    const result = await probe(target);
    assert.equal(result.ok, true, target.name);
  }

  const containment = TARGETS.find((target) => target.name === "checkout-contained");
  globalThis.fetch = async () => responseFor(containment, { status: 200, body: '{"ok":true}' });
  const reenabled = await probe(containment);
  assert.equal(reenabled.ok, false);
  assert.equal(reenabled.status, 200);

  globalThis.fetch = async () => responseFor(containment, { body: '{"code":"wrong"}' });
  const wrongCode = await probe(containment);
  assert.equal(wrongCode.ok, false);
  assert.equal(wrongCode.missing, containment.contains);
} finally {
  globalThis.fetch = originalFetch;
}
