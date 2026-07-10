const MAX_BACKUP_BYTES = 32 * 1024 * 1024;
const PATH_RE = /^\/v1\/backups\/(\d{4}-\d{2}-\d{2})\/([a-zA-Z0-9][a-zA-Z0-9._-]{0,127})$/;
const SHA256_RE = /^[a-f0-9]{64}$/;

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function hex(bytes) {
  return Array.from(new Uint8Array(bytes), (value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  return hex(await crypto.subtle.digest("SHA-256", value));
}

async function equalSecret(left, right) {
  const encoder = new TextEncoder();
  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right)),
  ]);
  const a = new Uint8Array(leftHash);
  const b = new Uint8Array(rightHash);
  let difference = a.length ^ b.length;
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) difference |= a[i] ^ b[i];
  return difference === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return json({ ok: true, service: "tinyzkp-backup-ingest" }, 200);
    }
    if (request.method !== "PUT") return json({ error: "not found" }, 404);
    if (!env.BACKUP_TOKEN || !env.BACKUP_BUCKET) {
      return json({ error: "service unavailable" }, 503);
    }

    const authorization = request.headers.get("Authorization") || "";
    const suppliedToken = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
    if (!suppliedToken || !(await equalSecret(suppliedToken, env.BACKUP_TOKEN))) {
      return json({ error: "unauthorized" }, 401);
    }

    const path = PATH_RE.exec(url.pathname);
    if (!path) return json({ error: "invalid backup path" }, 400);
    const contentLength = Number(request.headers.get("Content-Length") || "0");
    if (contentLength > MAX_BACKUP_BYTES) return json({ error: "backup too large" }, 413);
    const expectedSha256 = (request.headers.get("X-Content-SHA256") || "").toLowerCase();
    if (!SHA256_RE.test(expectedSha256)) return json({ error: "sha256 required" }, 400);

    const body = await request.arrayBuffer();
    if (body.byteLength === 0 || body.byteLength > MAX_BACKUP_BYTES) {
      return json({ error: "invalid backup size" }, body.byteLength > MAX_BACKUP_BYTES ? 413 : 400);
    }
    const actualSha256 = await sha256(body);
    if (actualSha256 !== expectedSha256) return json({ error: "checksum mismatch" }, 422);

    const key = `production/${path[1]}/${path[2]}`;
    await env.BACKUP_BUCKET.put(key, body, {
      httpMetadata: { contentType: "application/octet-stream" },
      customMetadata: { sha256: actualSha256 },
    });
    return json({ ok: true, key, bytes: body.byteLength, sha256: actualSha256 }, 201);
  },
};
