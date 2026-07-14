import assert from "node:assert/strict";
import test from "node:test";
import worker, { emailText, tokenMatches, validPayload } from "./worker.js";

const token = "a".repeat(64);
const payload = {
  text: "TinyZKP automatically contained new obligations",
  release_sha: "b".repeat(40),
  incident: "new_obligations_contained",
};

function request(body = payload, overrides = {}) {
  return new Request(overrides.url || "https://relay.example/alert", {
    method: overrides.method || "POST",
    headers: {
      authorization: `Bearer ${overrides.token || token}`,
      "content-type": overrides.contentType || "application/json",
      ...(overrides.headers || {}),
    },
    body: overrides.method === "GET" ? undefined : JSON.stringify(body),
  });
}

function environment(send = async () => ({ messageId: "test" })) {
  return {
    ALERT_RELAY_TOKEN: token,
    ALERT_FROM: "alerts@tinyzkp.com",
    ALERT_TO: "logan@galenhealth.org",
    ALERT_EMAIL: { send },
  };
}

test("relay accepts one authenticated bounded alert and fixes sender and recipient", async () => {
  const messages = [];
  const response = await worker.fetch(request(), environment(async (message) => messages.push(message)));
  assert.equal(response.status, 204);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].from, "alerts@tinyzkp.com");
  assert.equal(messages[0].to, "logan@galenhealth.org");
  assert.equal(messages[0].subject, "TinyZKP production alert");
  assert.match(messages[0].text, /new_obligations_contained/);
  assert.doesNotMatch(messages[0].text, /Bearer|https:\/\//);
});

test("relay rejects wrong route, method, token, media type, and payload", async () => {
  const env = environment();
  assert.equal((await worker.fetch(request(payload, { url: "https://relay.example/nope" }), env)).status, 404);
  assert.equal((await worker.fetch(request(payload, { method: "GET" }), env)).status, 405);
  assert.equal((await worker.fetch(request(payload, { token: "z".repeat(64) }), env)).status, 401);
  assert.equal((await worker.fetch(request(payload, { contentType: "text/plain" }), env)).status, 415);
  assert.equal((await worker.fetch(request({ text: "x", extra: "forbidden" }), env)).status, 422);
  assert.equal((await worker.fetch(request({ text: "x\u0000y" }), env)).status, 422);
});

test("relay fails closed when delivery fails or its secret is missing", async () => {
  const failure = environment(async () => { throw new Error("upstream detail"); });
  assert.equal((await worker.fetch(request(), failure)).status, 502);
  const missing = environment();
  missing.ALERT_RELAY_TOKEN = "";
  assert.equal((await worker.fetch(request(), missing)).status, 503);
});

test("validation and token helpers reject malformed input", async () => {
  assert.equal(await tokenMatches(token, token), true);
  assert.equal(await tokenMatches("x", token), false);
  assert.equal(validPayload(payload), true);
  assert.equal(validPayload({ text: "" }), false);
  assert.equal(validPayload({ text: "ok", release_sha: "not-a-sha" }), false);
  assert.match(emailText(payload), /Release: b{40}/);
});
