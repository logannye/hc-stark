const { test } = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/cjs/client.js");

test("CJS exports the local artifact API", () => {
  assert.equal(typeof sdk.fibonacciManifest, "function");
  assert.equal(typeof sdk.manifestDigestHex, "function");
  assert.equal(typeof sdk.Cli, "function");
  assert.equal(sdk.HcClient, undefined);
});
