import assert from "node:assert/strict";
import {
  BACKEND_RECOVERY_TARGETS,
  GUARD_PRELAUNCH_TARGETS,
  PUBLIC_BETA_TARGETS,
  targetsForMode,
  probe,
  alert,
  failureFingerprint,
  reconcileAlertState,
} from "./worker.js";

const originalFetch = globalThis.fetch;

function responseFor(target, override = {}) {
  const body = override.body ?? (target.jsonField ? JSON.stringify({ [target.jsonField]: target.jsonValue }) : target.contains) ?? "ok";
  const status = override.status ?? target.expect;
  return new Response(body, { status });
}

class FakeKv {
  constructor() {
    this.values = new Map();
  }

  async get(key, type) {
    const value = this.values.get(key);
    if (value === undefined) return null;
    return type === "json" ? JSON.parse(value) : value;
  }

  async put(key, value) {
    this.values.set(key, value);
  }

  async delete(key) {
    this.values.delete(key);
  }
}

try {
  for (const targets of [
    BACKEND_RECOVERY_TARGETS,
    GUARD_PRELAUNCH_TARGETS,
    PUBLIC_BETA_TARGETS,
  ]) {
    for (const target of targets) {
      globalThis.fetch = async (_url, options) => {
        assert.equal(options.method, target.method || "GET");
        return responseFor(target);
      };
      const result = await probe(target);
      assert.equal(result.ok, true, target.name);
    }
  }
  assert.equal(targetsForMode(), GUARD_PRELAUNCH_TARGETS);
  assert.equal(targetsForMode("guard_prelaunch"), GUARD_PRELAUNCH_TARGETS);
  assert.equal(targetsForMode("containment"), BACKEND_RECOVERY_TARGETS);
  assert.equal(targetsForMode("public_beta"), PUBLIC_BETA_TARGETS);
  assert.throws(() => targetsForMode("production"), /invalid AUDIT_MODE/);

  const containment = GUARD_PRELAUNCH_TARGETS.find(
    (target) => target.name === "checkout-contained",
  );
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
  const delivered = await alert(
    { ALERT_WEBHOOK_URL: "https://relay.example/alert", ALERT_WEBHOOK_TOKEN: "x".repeat(64) },
    [{ name: "api-ready", status: 503 }],
    "guard_prelaunch",
  );
  assert.equal(delivered, true);
  assert.equal(alertRequest.options.headers.authorization, `Bearer ${"x".repeat(64)}`);
  assert.deepEqual(JSON.parse(alertRequest.options.body), {
    text: "🔴 TinyZKP Guard prelaunch surface failed: api-ready (503)",
    incident: "external_probe_failed",
  });

  const fingerprint = failureFingerprint([
    { name: "z", status: 503 },
    { name: "a", status: 200, missing: "expected" },
  ]);
  assert.equal(
    fingerprint,
    '[{"name":"a","status":200,"missing":"expected","error":null},{"name":"z","status":503,"missing":null,"error":null}]',
  );

  const kv = new FakeKv();
  const payloads = [];
  const env = {
    ALERT_WEBHOOK_URL: "https://relay.example/alert",
    ALERT_WEBHOOK_TOKEN: "x".repeat(64),
    ALERT_REMINDER_SECONDS: "300",
    ALERT_STATE: kv,
  };
  globalThis.fetch = async (_url, options) => {
    payloads.push(JSON.parse(options.body));
    return new Response(null, { status: 204 });
  };
  const firstFailure = [{ name: "site-commerce-contained", status: 500 }];
  await reconcileAlertState(env, firstFailure, "guard_prelaunch", 0);
  await reconcileAlertState(env, firstFailure, "guard_prelaunch", 1_000);
  assert.equal(payloads.length, 1, "unchanged incidents are suppressed");

  const changedFailure = [{ name: "site-commerce-contained", status: 200, missing: "checkout_enabled=false" }];
  await reconcileAlertState(env, changedFailure, "guard_prelaunch", 2_000);
  assert.equal(payloads.length, 2, "a changed incident pages immediately");

  await reconcileAlertState(env, changedFailure, "guard_prelaunch", 303_000);
  assert.equal(payloads.length, 3, "an unchanged incident sends one bounded reminder");

  await reconcileAlertState(env, [], "guard_prelaunch", 304_000);
  await reconcileAlertState(env, [], "guard_prelaunch", 305_000);
  assert.equal(payloads.length, 4, "recovery is sent once");
  assert.equal(payloads[3].incident, "external_probe_recovered");
  assert.equal(kv.values.size, 0);
} finally {
  globalThis.fetch = originalFetch;
}
