// CJS test — verifies require('tinyzkp') still works.
// This test failing means we've broken CJS-consumer compat.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { HcClient, HcClientError, ProofBytes, TinyZKP } = require("../dist/cjs/client.js");

test("CJS: required module exposes the public API", () => {
  assert.equal(typeof HcClient, "function");
  assert.equal(typeof HcClientError, "function");
  assert.equal(typeof ProofBytes, "function"); // class is a function in JS
  assert.equal(TinyZKP, HcClient);
});

test("CJS: ProofBytes class works at runtime", () => {
  const p = new ProofBytes(3, [1, 2, 3]);
  assert.equal(p.version, 3);
  assert.ok(p instanceof ProofBytes);
});

test("CJS: HcClient construction does not throw", () => {
  const c = new HcClient("https://api.example.com", { apiKey: "tzk_test" });
  assert.ok(c);
});
