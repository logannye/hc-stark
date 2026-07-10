import assert from "node:assert/strict";
import worker from "../../deploy/cloudflare/backup-ingest/worker.mjs";

const token = "a".repeat(64);
const stored = [];
const env = {
  BACKUP_TOKEN: token,
  BACKUP_BUCKET: {
    async put(key, body, options) {
      stored.push({ key, body: new Uint8Array(body), options });
    },
  },
};

async function digest(body) {
  const hash = await crypto.subtle.digest("SHA-256", body);
  return Array.from(new Uint8Array(hash), (value) => value.toString(16).padStart(2, "0")).join("");
}

const body = new TextEncoder().encode("owner-only-backup");
const sha256 = await digest(body);
const accepted = await worker.fetch(
  new Request("https://backup.example/v1/backups/2026-07-10/tenant_store.sqlite", {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Length": String(body.byteLength),
      "X-Content-SHA256": sha256,
    },
    body,
  }),
  env,
);
assert.equal(accepted.status, 201);
assert.equal(stored.length, 1);
assert.equal(stored[0].key, "production/2026-07-10/tenant_store.sqlite");
assert.equal(stored[0].options.customMetadata.sha256, sha256);

const unauthorized = await worker.fetch(
  new Request("https://backup.example/v1/backups/2026-07-10/tenant_store.sqlite", {
    method: "PUT",
    headers: { Authorization: "Bearer wrong", "X-Content-SHA256": sha256 },
    body,
  }),
  env,
);
assert.equal(unauthorized.status, 401);

const corrupt = await worker.fetch(
  new Request("https://backup.example/v1/backups/2026-07-10/tenant_store.sqlite", {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "X-Content-SHA256": "0".repeat(64) },
    body,
  }),
  env,
);
assert.equal(corrupt.status, 422);

const traversal = await worker.fetch(
  new Request("https://backup.example/v1/backups/2026-07-10/..%2Fsecret", {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "X-Content-SHA256": sha256 },
    body,
  }),
  env,
);
assert.equal(traversal.status, 400);

const health = await worker.fetch(new Request("https://backup.example/healthz"), env);
assert.equal(health.status, 200);
console.log("PASS Cloudflare backup ingest worker");
