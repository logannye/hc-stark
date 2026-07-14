import assert from "node:assert/strict";
import { TARGETS, PUBLIC_BETA_TARGETS, targetsForMode, probe, alert } from "./worker.js";

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
  for (const target of PUBLIC_BETA_TARGETS) {
    globalThis.fetch = async (_url, options) => {
      assert.equal(options.method, target.method || "GET");
      return responseFor(target);
    };
    const result = await probe(target);
    assert.equal(result.ok, true, target.name);
  }
  assert.equal(targetsForMode("containment"), TARGETS);
  assert.equal(targetsForMode("public_beta"), PUBLIC_BETA_TARGETS);
  assert.throws(() => targetsForMode("production"), /invalid AUDIT_MODE/);

  const containment = TARGETS.find((target) => target.name === "checkout-contained");
  globalThis.fetch = async () => responseFor(containment, { status: 200, body: '{"ok":true}' });
  const reenabled = await probe(containment);
  assert.equal(reenabled.ok, false);
  assert.equal(reenabled.status, 200);

  globalThis.fetch = async () => responseFor(containment, { body: '{"code":"wrong"}' });
  const wrongCode = await probe(containment);
  assert.equal(wrongCode.ok, false);
  assert.equal(wrongCode.missing, containment.contains);

  let alertRequest;
  globalThis.fetch = async (url, options) => {
    alertRequest = { url, options };
    return new Response(null, { status: 204 });
  };
  await alert(
    { ALERT_WEBHOOK_URL: "https://relay.example/alert", ALERT_WEBHOOK_TOKEN: "x".repeat(64) },
    [{ name: "api-ready", status: 503 }],
  );
  assert.equal(alertRequest.options.headers.authorization, `Bearer ${"x".repeat(64)}`);
  assert.deepEqual(JSON.parse(alertRequest.options.body), {
    text: "🔴 TinyZKP recovery surface failed: api-ready (503)",
    incident: "external_probe_failed",
  });
} finally {
  globalThis.fetch = originalFetch;
}
