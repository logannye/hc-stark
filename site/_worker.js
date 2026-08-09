// Static-only Cloudflare Pages router for TinyZKP.com.
//
// This worker provides canonical routing, security headers, explicit 410
// responses for the retired hosted-service surfaces, `POST /v1/estimate`
// (a shape-only resource estimate backed by the compiled Rust cost model via
// a WASM import — the same core `hc-cli estimate` calls at the source
// level; a CI gate, `scripts/ci/estimate_wasm_cli_parity_gate.mjs`, fails
// the build if the committed wasm and the native CLI ever compute
// different numbers for the same input, so that never goes unnoticed), and
// `POST /v1/keys` (mints a free, opaque bearer key that raises the
// `/v1/estimate` rate-limit ceiling — Task 5, see below). It calls no
// upstream service.
//
// It DOES store data, in one D1 database bound as `env.DB` (see
// site/wrangler.toml and migrations/*.sql):
//
//   - a per-IP rate-limit counter keyed on a salted hash of
//     `CF-Connecting-IP` (never the raw address);
//   - a per-key rate-limit counter keyed on a caller's own opaque `key_id`
//     (migrations/0002_keys.sql) once they mint a free key;
//   - exactly a SHA-256 hash of each minted key (`estimator_keys.key_hash`)
//     -- the raw key is handed back to its caller once, at mint time, and
//     is never itself written to D1;
//   - a shape-only demand-log row per successful estimate (never a raw
//     request body, raw IP, email, path, AIR, or witness — see
//     migrations/0001_demand_log.sql for the exact bucketing), tagged with
//     exactly one of that caller's `key_id` or the anonymous salted IP
//     hash.
//
// `POST /v1/keys` takes only an email, used solely to check it is shaped
// like a real address before minting; that email is never stored anywhere,
// in any form, by this worker or by any migration in this repo. There is
// no account, password, confirmation flow, or lost-key recovery path that
// would need it, so persisting it would be pure unused liability — see the
// Task 5 report for the full reasoning.
//
// Every number in an `/v1/estimate` response still comes solely from
// `estimate_json`; the demand log separately re-reads the request's
// already-validated shape fields (field, extension_degree, trace
// width/row-count buckets, feature flags) purely to log them, and that
// read never feeds back into the estimate or the response.

import estimateWasmModule from "./vendor/tinyzkp-estimate/tinyzkp-estimate_bg.wasm";
import {
  initSync as initEstimateWasm,
  estimate_json as estimateJson,
} from "./vendor/tinyzkp-estimate/tinyzkp-estimate.js";

// Instantiated once per Worker isolate. `initSync` is both idempotent (safe
// to call more than once) and fully synchronous — Wrangler resolves a static
// `.wasm` import to an already-compiled `WebAssembly.Module`, so no
// cold-start `await` (and no network fetch of the module) is needed.
initEstimateWasm({ module: estimateWasmModule });

// A few KB is generous for this shape-only manifest (schema_version, field,
// row/width counts, feature flags): a real request serializes to well under
// 1 KB. This is not a security boundary — Cloudflare's own edge network caps
// request bodies far above this — it just keeps this endpoint from ever
// looking like a workload-upload surface.
const MAX_ESTIMATE_REQUEST_BYTES = 8192;

// --- Anonymous rate limiting (Task 3) ---------------------------------
//
// A fixed one-hour window keyed on a salted hash of `CF-Connecting-IP` —
// never the raw address. 30/hour is a conservative default for a free,
// no-signup resource estimator; Task 5's keyed tier raises this ceiling
// per caller.
//
// This is deliberately NOT a named export: Cloudflare Pages' Advanced Mode
// runtime treats every top-level export of `_worker.js` as a candidate
// handler/Durable Object binding and refuses to start if one isn't a
// function or `ExportedHandler` (confirmed against a real `wrangler pages
// dev` run — a second named export here hard-crashes the Worker at
// startup). scripts/ci/test_worker_estimate.mjs instead reads this exact
// constant back out of the committed source text, so the test and the
// worker can never silently drift apart.
const ANON_RATE_LIMIT_PER_HOUR = 30;
const RATE_LIMIT_WINDOW_SECONDS = 3600;

// This salt is an application-level constant compiled into this committed,
// publicly-readable source file — it is NOT a managed Cloudflare secret.
// It stops a casual precomputed-table correlation of the stored hash back
// to common IP strings; it is not a defense against an attacker who
// already has this source. There is no existing secret-provisioning
// surface for this static site (see scripts/ci/cloudflare_pages_secret_check.py,
// which asserts the static site has *no* application secrets), and
// inventing one unverified here would be worse than being explicit about
// the limitation. See the Task 3/4 report for the full rationale.
const IP_HASH_SALT = "tinyzkp-v1-estimate-ip-hash-salt";

// Retention. `demand_report.py` reads a trailing 90-day window; this keeps
// twice that and no more, so the analysis window is never truncated but the
// table does not accumulate indefinitely. The privacy notice states this
// number, and scripts/ci/privacy_disclosure_gate.py fails if the manifest
// and the code disagree about whether retention is enforced at all.
const RETENTION_DAYS = 180;
const RETENTION_SECONDS = RETENTION_DAYS * 86400;

// Pruning piggybacks on ordinary writes rather than a cron, because Pages
// has no scheduled trigger. Module scope persists for the life of an
// isolate, so this runs at most once per isolate per hour instead of on
// every request.
let lastPrunedHour = 0;

function pruneExpiredRows(env, ctx, nowSeconds) {
  const hour = Math.floor(nowSeconds / 3600) * 3600;
  if (hour === lastPrunedHour) return;
  lastPrunedHour = hour;
  const cutoff = hour - RETENTION_SECONDS;
  try {
    const work = Promise.all([
      env.DB.prepare("DELETE FROM demand_log WHERE observed_at_hour < ?").bind(cutoff).run(),
      env.DB.prepare("DELETE FROM rejected_log WHERE observed_at_hour < ?").bind(cutoff).run(),
      env.DB.prepare("DELETE FROM rate_limit_windows WHERE window_start < ?").bind(cutoff).run(),
      env.DB.prepare("DELETE FROM keyed_rate_limit_windows WHERE window_start < ?").bind(cutoff).run(),
    ]).catch(() => {});
    if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(work);
  } catch {
    // Retention must never affect a response. A failed prune retries on the
    // next isolate/hour; `estimator_keys` is deliberately NOT pruned, since
    // deleting a key would silently revoke a caller's access.
  }
}

// `CF-Connecting-IP` is set by the Cloudflare edge and cannot be removed by
// a client, so the empty branch is unreachable in production. It is handled
// explicitly anyway: hashing "" would put every such caller in ONE shared
// rate-limit bucket, so the first 30 requests from anywhere would 429
// everyone else. Returning null instead means an unidentifiable caller is
// simply not rate-limited, which matches this limiter's documented
// fail-open posture -- it is a courtesy limit, not a security boundary.
async function saltedIpHash(ip) {
  if (!ip) return null;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(IP_HASH_SALT),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(ip));
  return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// Fixed-window counter backed by D1 (`rate_limit_windows`,
// migrations/0000_rate_limit_windows.sql). Fails OPEN: the 30/hour ceiling
// is a courtesy limit protecting the free tier from runaway callers, not a
// security boundary, so a transient rate-limit-store error must never take
// down the estimator itself.
async function checkAnonymousRateLimit(env, ipHash) {
  // No usable caller identity: see `saltedIpHash`. Never share one bucket.
  if (!ipHash) return { limited: false };
  const nowSeconds = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(nowSeconds / RATE_LIMIT_WINDOW_SECONDS) * RATE_LIMIT_WINDOW_SECONDS;
  try {
    const row = await env.DB.prepare(
      `INSERT INTO rate_limit_windows (ip_hash, window_start, request_count)
       VALUES (?, ?, 1)
       ON CONFLICT (ip_hash, window_start) DO UPDATE SET request_count = request_count + 1
       RETURNING request_count`,
    ).bind(ipHash, windowStart).first();
    const count = Number(row && row.request_count);
    if (Number.isFinite(count) && count > ANON_RATE_LIMIT_PER_HOUR) {
      const retryAfterSeconds = Math.max(1, windowStart + RATE_LIMIT_WINDOW_SECONDS - nowSeconds);
      return { limited: true, retryAfterSeconds };
    }
    return { limited: false };
  } catch {
    return { limited: false };
  }
}

function rateLimitedResponse(retryAfterSeconds) {
  return new Response(JSON.stringify({ ok: false, error: "rate_limited" }), {
    status: 429,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Retry-After": String(retryAfterSeconds),
    },
  });
}

// --- Free keys and the keyed rate tier (Task 5) -------------------------
//
// A minted key raises the per-caller ceiling above the anonymous default:
// a courtesy for callers willing to identify themselves as a distinct
// organization, which is also what makes `scripts/ci/demand_report.py`'s
// kill-criterion count meaningful (see migrations/0001_demand_log.sql's
// `key_id` column) — not a security boundary and not a paid product. There
// is still no account, password, dashboard, or confirmation email:
// `POST /v1/keys` mints and returns a key synchronously from one email,
// and that is the entire flow.
const KEYED_RATE_LIMIT_PER_HOUR = 300;
const KEY_PREFIX = "tzk_live_";
const KEY_TOKEN_BYTES = 32; // 256 bits of randomness in the bearer key itself
const KEY_ID_BYTES = 16; // a second, independently-random 128-bit identifier
const MAX_KEYS_REQUEST_BYTES = 2048; // an email address plus JSON overhead is well under 1 KB
const EMAIL_SHAPE_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function randomUrlSafeToken(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// The same structured-error shape `rateLimitedResponse` already uses
// (`{ ok: false, error: <code> }`) so an invalid/unknown key, a malformed
// `/v1/keys` request, or a D1 outage while minting are all reported the
// same clear way — never as `internal_error`.
function structuredErrorResponse(status, code) {
  return new Response(JSON.stringify({ ok: false, error: code }), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

// Mints one free key. A SHA-256 hash of the returned bearer key is stored
// (`estimator_keys.key_hash`), never the key itself, alongside a second,
// independently-random `key_id` used everywhere a caller must be
// identified in logs (`demand_log.key_id`, `keyed_rate_limit_windows.key_id`)
// — so nobody who only reads those tables can work backward to the raw key
// or to `key_hash`. The submitted email is checked only for shape (it must
// look like an email, as a light guard against empty/junk submissions) and
// is never stored, here or anywhere else in this repo; see
// migrations/0002_keys.sql and the Task 5 report for why that is a
// deliberate choice, not an oversight. Minting itself rides the same
// anonymous per-IP rate limiter `/v1/estimate` uses (Task 3): unlike the
// demand log, an inflated count of free keys would directly corrupt the
// kill-criterion this whole feature exists to measure, so mass-minting
// from one IP is bounded the same way mass-estimating is.
async function keysResponse(request, env) {
  if (request.method !== "POST") {
    return new Response("method not allowed", {
      status: 405,
      headers: { Allow: "POST", "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  const ipHash = await saltedIpHash(request.headers.get("CF-Connecting-IP") || "");
  const rateLimit = await checkAnonymousRateLimit(env, ipHash);
  if (rateLimit.limited) {
    return rateLimitedResponse(rateLimit.retryAfterSeconds);
  }

  const declaredLength = Number(request.headers.get("content-length") ?? "");
  if (Number.isFinite(declaredLength) && declaredLength > MAX_KEYS_REQUEST_BYTES) {
    return structuredErrorResponse(400, "invalid_request");
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > MAX_KEYS_REQUEST_BYTES) {
    return structuredErrorResponse(400, "invalid_request");
  }

  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return structuredErrorResponse(400, "invalid_request");
  }
  const email = typeof parsed?.email === "string" ? parsed.email.trim() : "";
  if (!email || email.length > 320 || !EMAIL_SHAPE_RE.test(email)) {
    return structuredErrorResponse(400, "invalid_email");
  }

  if (!env.DB) {
    return structuredErrorResponse(503, "keys_unavailable");
  }

  const rawKey = KEY_PREFIX + randomUrlSafeToken(KEY_TOKEN_BYTES);
  const keyHash = await sha256Hex(rawKey);
  const keyId = randomUrlSafeToken(KEY_ID_BYTES);
  const mintedAtHour = Math.floor(Date.now() / 1000 / 3600) * 3600;

  try {
    await env.DB.prepare(
      `INSERT INTO estimator_keys (key_id, key_hash, minted_at_hour, revoked) VALUES (?, ?, ?, 0)`,
    ).bind(keyId, keyHash, mintedAtHour).run();
  } catch {
    return structuredErrorResponse(503, "keys_unavailable");
  }

  return new Response(
    JSON.stringify({ ok: true, key: rawKey, rate_limit_per_hour: KEYED_RATE_LIMIT_PER_HOUR }),
    { status: 200, headers: { "Content-Type": "application/json; charset=utf-8" } },
  );
}

// Resolves the caller's `Authorization: Bearer <key>` header, if any, into
// one of three states:
//   - `{ status: "none" }` — no key presented, OR D1 is unreachable (which
//     fails OPEN to the anonymous tier exactly like Task 3's rate limiter,
//     rather than failing the whole request over an infrastructure hiccup);
//   - `{ status: "invalid" }` — a key WAS presented but is malformed,
//     unknown, or revoked; a caller who asked to be treated as a keyed
//     caller must be told plainly that didn't work, never silently
//     downgraded to the anonymous tier without saying so;
//   - `{ status: "keyed", keyId }` — a valid, active key.
async function resolveKeyedCaller(env, authorizationHeader) {
  if (!authorizationHeader) return { status: "none" };
  const match = /^Bearer\s+(\S+)$/.exec(authorizationHeader.trim());
  if (!match) return { status: "invalid" };
  const token = match[1];
  if (!token.startsWith(KEY_PREFIX) || token.length < KEY_PREFIX.length + 16) {
    return { status: "invalid" };
  }
  if (!env.DB) return { status: "none" };
  try {
    const keyHash = await sha256Hex(token);
    const row = await env.DB.prepare(
      `SELECT key_id, revoked FROM estimator_keys WHERE key_hash = ?`,
    ).bind(keyHash).first();
    if (!row || row.revoked) return { status: "invalid" };
    return { status: "keyed", keyId: row.key_id };
  } catch {
    return { status: "none" };
  }
}

// Fixed-window counter structurally identical to `checkAnonymousRateLimit`
// but backed by `keyed_rate_limit_windows` and keyed on `key_id` instead of
// a salted IP hash (migrations/0002_keys.sql). Also fails OPEN: this
// ceiling is a courtesy, not a security boundary.
async function checkKeyedRateLimit(env, keyId) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(nowSeconds / RATE_LIMIT_WINDOW_SECONDS) * RATE_LIMIT_WINDOW_SECONDS;
  try {
    const row = await env.DB.prepare(
      `INSERT INTO keyed_rate_limit_windows (key_id, window_start, request_count)
       VALUES (?, ?, 1)
       ON CONFLICT (key_id, window_start) DO UPDATE SET request_count = request_count + 1
       RETURNING request_count`,
    ).bind(keyId, windowStart).first();
    const count = Number(row && row.request_count);
    if (Number.isFinite(count) && count > KEYED_RATE_LIMIT_PER_HOUR) {
      const retryAfterSeconds = Math.max(1, windowStart + RATE_LIMIT_WINDOW_SECONDS - nowSeconds);
      return { limited: true, retryAfterSeconds };
    }
    return { limited: false };
  } catch {
    return { limited: false };
  }
}

// --- Shape-only demand log (Task 4) ------------------------------------
//
// Every column here describes the SHAPE of a request the engine already
// accepted and estimated: never a raw request body, raw IP, email, path,
// AIR, or witness. See migrations/0001_demand_log.sql for the exact bucket
// boundaries and the full rationale.
const TRACE_WIDTH_BUCKET_SIZE = 32; // 8 fixed bands across the valid [1, 256] range

function bucketTraceWidth(width) {
  if (!Number.isInteger(width) || width < 1) return null;
  const start = Math.floor((width - 1) / TRACE_WIDTH_BUCKET_SIZE) * TRACE_WIDTH_BUCKET_SIZE + 1;
  return `${start}-${start + TRACE_WIDTH_BUCKET_SIZE - 1}`;
}

// `logical_rows` is only ever a power of two on [2^10, 2^24]. Storing the
// exact exponent would be equivalent to storing the exact row count, so
// this groups the exponent into 4 wide bands; each still collapses at
// least 3 distinct exact row counts into one label.
const LOGICAL_ROWS_BUCKETS = [
  { minExponent: 10, maxExponent: 13, label: "2^10-2^13" },
  { minExponent: 14, maxExponent: 17, label: "2^14-2^17" },
  { minExponent: 18, maxExponent: 21, label: "2^18-2^21" },
  { minExponent: 22, maxExponent: 24, label: "2^22-2^24" },
];

function bucketLogicalRows(rows) {
  if (!Number.isInteger(rows) || rows < 1) return null;
  const exponent = Math.round(Math.log2(rows));
  if (2 ** exponent !== rows) return null;
  const bucket = LOGICAL_ROWS_BUCKETS.find(
    (candidate) => exponent >= candidate.minExponent && exponent <= candidate.maxExponent,
  );
  return bucket ? bucket.label : null;
}

function boolToFlag(value) {
  return typeof value === "boolean" ? (value ? 1 : 0) : null;
}

// Appends one shape-only row for a successfully *estimated* request via
// `ctx.waitUntil`, so this never delays the response, and never turns a
// good estimate into an error: every failure mode here — a missing `env.DB`
// binding, a malformed body that cannot be re-parsed, a D1 write that
// rejects — is caught and silently dropped. `requestBody` is re-read here
// purely to bucket its already-validated declared shape fields for logging;
// that read never feeds back into the estimate itself, which remains
// entirely `estimateJson`'s untouched output. `caller` carries exactly one
// of `keyId` (a Task 5 keyed caller) or `ipHash` (an anonymous caller) —
// never both, matching migrations/0001_demand_log.sql's invariant.
function logDemand(env, ctx, requestBody, responseBody, caller) {
  try {
    let parsedRequest;
    let parsedResponse;
    try {
      parsedRequest = JSON.parse(requestBody);
      parsedResponse = JSON.parse(responseBody);
    } catch {
      return;
    }
    // Only `EstimateResponseV1` (the success shape) carries anything to
    // log; the error envelope (malformed manifest, oversized body, etc.)
    // has no `estimates`/`provable_today` and is never logged here.
    if (
      typeof parsedResponse.schema_version !== "number" ||
      typeof parsedResponse.provable_today !== "boolean" ||
      !parsedResponse.estimates
    ) {
      return;
    }

    const features =
      parsedRequest.features && typeof parsedRequest.features === "object" ? parsedRequest.features : {};
    const blockingReasonCodes = Array.isArray(parsedResponse.blocking_reasons)
      ? parsedResponse.blocking_reasons
          .map((reason) => reason && reason.code)
          .filter((code) => typeof code === "string")
      : [];
    const observedAtHour = Math.floor(Date.now() / 1000 / 3600) * 3600;

    const promise = env.DB.prepare(
      `INSERT INTO demand_log (
         observed_at_hour, request_digest, field, extension_degree,
         trace_width_bucket, logical_rows_bucket,
         uses_lookups, uses_buses, uses_permutations, uses_multi_table,
         uses_preprocessed_columns, uses_periodic_columns, uses_recursion, uses_gpu,
         provable_today, blocking_reason_codes, key_id, anon_ip_hash
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        observedAtHour,
        typeof parsedResponse.request_digest === "string" ? parsedResponse.request_digest : null,
        typeof parsedRequest.field === "string" ? parsedRequest.field : null,
        typeof parsedRequest.extension_degree === "number" ? parsedRequest.extension_degree : null,
        bucketTraceWidth(parsedRequest.trace_width),
        bucketLogicalRows(parsedRequest.logical_rows),
        boolToFlag(features.uses_lookups),
        boolToFlag(features.uses_buses),
        boolToFlag(features.uses_permutations),
        boolToFlag(features.uses_multi_table),
        boolToFlag(features.uses_preprocessed_columns),
        boolToFlag(features.uses_periodic_columns),
        boolToFlag(features.uses_recursion),
        boolToFlag(features.uses_gpu),
        parsedResponse.provable_today ? 1 : 0,
        JSON.stringify(blockingReasonCodes),
        caller && caller.keyId ? caller.keyId : null,
        caller && caller.ipHash ? caller.ipHash : null,
      )
      .run();

    const safe = Promise.resolve(promise).catch(() => {});
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(safe);
    }
  } catch {
    // A missing/misconfigured `env.DB` binding must never affect the
    // response that `estimateResponse` already computed independently.
  }
}

// Counts requests the engine REJECTED (migrations/0003_rejected_log.sql).
// `logDemand` above deliberately ignores them, which left every failed
// integration attempt invisible — a bias in the one metric the kill
// criterion reads. Someone who wires this up and gets the request shape
// wrong wanted the tool; silence and a malformed request are not the same
// observation, and `demand_report.py` now reports them separately.
//
// Nothing derived from the body is recorded — not the body, not a digest,
// not its length. A malformed body is exactly where a witness or a secret
// is most likely to turn up. Only the hour, the engine's own reason code,
// and the caller column.
function logRejection(env, ctx, responseBody, caller) {
  try {
    let parsed;
    try {
      parsed = JSON.parse(responseBody);
    } catch {
      return;
    }
    // The error envelope, and only it: `ok === false` with a reason code.
    // A successful `EstimateResponseV1` has no `ok` field at all and is
    // `logDemand`'s business, so the two can never double-count.
    if (parsed.ok !== false || !parsed.error || !parsed.error.reason) {
      return;
    }
    const reasonCode =
      typeof parsed.error.reason.code === "string" ? parsed.error.reason.code : null;
    const observedAtHour = Math.floor(Date.now() / 1000 / 3600) * 3600;

    const promise = env.DB.prepare(
      `INSERT INTO rejected_log (observed_at_hour, reason_code, key_id, anon_ip_hash)
       VALUES (?, ?, ?, ?)`,
    )
      .bind(
        observedAtHour,
        reasonCode,
        caller && caller.keyId ? caller.keyId : null,
        caller && caller.ipHash ? caller.ipHash : null,
      )
      .run();

    const safe = Promise.resolve(promise).catch(() => {});
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(safe);
    }
  } catch {
    // Same contract as `logDemand`: never affect the computed response.
  }
}

const CANONICAL_HOST = "tinyzkp.com";
const RETIRED_HOSTS = new Set([
  "api.tinyzkp.com",
  "mcp.tinyzkp.com",
  "webhook.tinyzkp.com",
]);

const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'self'; base-uri 'self'; connect-src 'self' https://cloudflareinsights.com; font-src 'self'; form-action 'none'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self' https://static.cloudflareinsights.com; style-src 'self'; upgrade-insecure-requests",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-site",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

const PUBLIC_ROUTES = new Set([
  "/",
  "/guard",
  "/compatibility",
  "/benchmarks",
  "/doctor",
  "/estimate",
  "/pricing",
  "/docs",
  "/troubleshooting",
  "/security",
  "/releases",
  "/support",
  "/plonky3-out-of-memory",
  "/resumable-plonky3-prover",
  "/ssd-backed-plonky3-proving",
  "/terms",
  "/privacy",
  "/refunds",
  "/eula",
]);

const PERMANENT_REDIRECTS = new Map([
  ["/engine", "/guard"],
  ["/plonky3", "/compatibility"],
  ["/status", "/releases"],
  ["/contact", "/support"],
]);

const GONE_PREFIXES = [
  "/account",
  "/agents",
  "/agent-",
  "/api/",
  "/apps",
  "/badges",
  "/calculator",
  "/compare",
  "/compute",
  "/enterprise",
  "/evaluation",
  "/examples",
  "/fit",
  "/functions/",
  "/integrations",
  "/limits",
  "/mcp",
  "/pilot",
  "/platform-rollout",
  "/receipts",
  "/recipes",
  "/requests",
  "/research",
  "/signup",
  "/templates",
  "/try",
  "/use-cases",
  "/vendor",
  "/verifiable-agent-output",
  "/verify",
  "/welcome",
];

const GONE_ASSETS = new Set([
  "/changelog.json",
  "/enterprise.json",
  "/evaluation.json",
  "/fit.json",
  "/integrations.json",
  "/limits.json",
  "/mcp.json",
  "/og-image.png",
  "/pilot-preview.jpg",
  "/openapi.json",
  "/platform-rollout.json",
  "/.well-known/mcp/server-card.json",
  "/.well-known/tinyzkp-badge.json",
  "/.well-known/tinyzkp-offers.json",
  "/.well-known/tinyzkp-receipt-share.json",
]);

// Every non-HTML file this site actually publishes, by exact request path.
//
// Cloudflare Pages' asset server answers a path it cannot resolve by serving
// the ROOT `index.html` at HTTP 200 — its single-page-app fallback — whenever
// a project ships no `404.html`, and this project cannot ship one:
// scripts/ci/site_route_check.py requires every `site/**/*.html` to be either
// a declared public page or a declared retired route, and a `404.html` is
// neither. That fallback made every published machine-readable contract URL
// unverifiable: `GET /schemas/estimate-request-v1.schema.json` — a schema
// this site has never published — answered 200 with a page of HTML, which a
// consumer cannot distinguish from "this contract exists". So existence is
// decided HERE, against a committed list, instead of being delegated to a
// fallback that has no way to say no.
//
// scripts/ci/test_worker_estimate.mjs walks `site/` and fails if this list
// and the files on disk disagree in EITHER direction, so a newly added asset
// cannot silently 404 and a deleted one cannot silently keep 200-ing.
//
// Deliberately absent, and why:
//   - `*.html` pages — routed by `PUBLIC_ROUTES` above, not by this list;
//   - `/og-image.png`, `/pilot-preview.jpg`, and everything under `/vendor/`
//     — retired surfaces that `retiredResponse` answers 410 before this list
//     is ever consulted; listing them here would resurrect them;
//   - `_worker.js`/`_headers` — Pages never serves its own control files;
//   - `wrangler.toml` and `.wrangler/` — deployment inputs that live in this
//     directory for tooling reasons and are not part of the public surface.
const STATIC_ASSETS = new Set([
  "/.well-known/security.txt",
  "/commerce.json",
  "/compatibility.json",
  "/discovery.json",
  "/estimate.js",
  "/favicon.svg",
  "/guard-social.png",
  "/indexnow-key.txt",
  "/llms.txt",
  "/offers.jsonld",
  "/pricing.json",
  "/privacy-disclosure-v1.json",
  "/release-channels-v1.json",
  "/release.json",
  "/robots.txt",
  "/roi.js",
  "/schemas/air-package-v1.schema.json",
  "/schemas/air-proof-bundle-v1.schema.json",
  "/schemas/benchmark-report-v1.schema.json",
  "/schemas/compatibility-manifest-v1.schema.json",
  "/schemas/compatibility-report-v1.schema.json",
  "/schemas/doctor-report-v1.schema.json",
  "/schemas/error-envelope-v1.schema.json",
  "/schemas/guard-channel-v1.schema.json",
  "/schemas/guard-release-index-v1.schema.json",
  "/schemas/job-inspect-result-v1.schema.json",
  "/schemas/job-manifest-v1.schema.json",
  "/schemas/job-result-v1.schema.json",
  "/schemas/policy-baseline-v1.schema.json",
  "/schemas/progress-event-v1.schema.json",
  "/schemas/proof-bundle-v1.schema.json",
  "/schemas/public-inputs-v1.schema.json",
  "/schemas/reason-v1.schema.json",
  "/schemas/support-report-v1.schema.json",
  "/schemas/trace-manifest-v1.schema.json",
  "/schemas/workload-manifest-v1.schema.json",
  "/shared.css",
  "/shared.js",
  "/site.webmanifest",
  "/sitemap.xml",
  "/social-card.png",
]);

function secured(response, preview = false) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  if (preview) headers.set("X-Robots-Tag", "noindex, nofollow");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function canonicalRedirect(url) {
  if (url.hostname.endsWith(".pages.dev")) return null;
  if (url.hostname === CANONICAL_HOST && url.protocol === "https:") return null;
  const target = new URL(url);
  target.protocol = "https:";
  target.hostname = CANONICAL_HOST;
  target.port = "";
  return new Response(null, {
    status: 308,
    headers: {
      "Cache-Control": "public, max-age=3600",
      Location: target.toString(),
    },
  });
}

function normalizedPath(pathname) {
  if (pathname === "/") return pathname;
  const withoutHtml = pathname.endsWith(".html") ? pathname.slice(0, -5) : pathname;
  return withoutHtml.endsWith("/") ? withoutHtml.slice(0, -1) : withoutHtml;
}

function goneResponse() {
  return new Response(
      "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>Retired surface — TinyZKP</title></head><body><main><h1>This surface has been retired.</h1><p>TinyZKP no longer operates hosted proving, accounts, receipts, MCP, or beta APIs.</p><p><a href=\"/guard\">Review TinyZKP Guard</a></p></main></body></html>",
      {
        status: 410,
        headers: {
          "Cache-Control": "public, max-age=3600",
          "Content-Type": "text/html; charset=utf-8",
          "X-Robots-Tag": "noindex, nofollow",
        },
      },
    );
}

// A 404 has to be legible to whoever asked for it. A machine consumer
// fetching a contract (`*.json`, `*.jsonld`) gets a machine-readable answer
// in the same `{ ok: false, error: <code> }` envelope the rest of this
// worker uses, with a matching content type — the entire point being that
// "published" and "never published" must be distinguishable without parsing
// HTML. Anything else gets a short page with a way back. Neither is
// cacheable: an asset added tomorrow must not be shadowed by a cached miss.
function notFoundResponse(pathname) {
  const headers = {
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow",
  };
  if (/\.(json|jsonld)$/i.test(pathname)) {
    return new Response(JSON.stringify({ ok: false, error: "not_found" }), {
      status: 404,
      headers: { ...headers, "Content-Type": "application/json; charset=utf-8" },
    });
  }
  return new Response(
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>Not found — TinyZKP</title></head><body><main><h1>Not found.</h1><p>TinyZKP publishes nothing at this address.</p><p><a href=\"/\">Go to the TinyZKP home page</a></p></main></body></html>",
    {
      status: 404,
      headers: { ...headers, "Content-Type": "text/html; charset=utf-8" },
    },
  );
}

function retiredResponse(pathname) {
  const normalized = normalizedPath(pathname);
  if (GONE_ASSETS.has(pathname) || GONE_PREFIXES.some((prefix) => normalized.startsWith(prefix))) {
    return goneResponse();
  }
  return null;
}

async function staticResponse(request, env, url, preview) {
  if (!new Set(["GET", "HEAD"]).has(request.method)) {
    return secured(new Response("method not allowed", {
      status: 405,
      headers: { Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" },
    }), preview);
  }

  const normalized = normalizedPath(url.pathname);
  const lastSegment = normalized.split("/").pop() || "";
  // A dot in the last segment means a file request (`normalizedPath` has
  // already stripped any `.html`, so pages never land here). Pages' asset
  // fallback cannot answer "no" for those — see `STATIC_ASSETS` — so an
  // unpublished file is settled from the committed list before `ASSETS` is
  // consulted at all, and never gets the chance to become a 200.
  if (lastSegment.includes(".")) {
    if (!STATIC_ASSETS.has(normalized)) return secured(notFoundResponse(normalized), preview);
  } else if (!PUBLIC_ROUTES.has(normalized)) {
    return secured(notFoundResponse(normalized), preview);
  }

  const direct = await env.ASSETS.fetch(request);
  // A 404 from the asset server for a path this worker believes IS published
  // is answered in this site's own shape rather than passed through as
  // Pages' generic page — but it stays a 404, and is never laundered into a
  // 200 by falling through to the clean-URL retry below.
  if (direct.status === 404 && (url.pathname === "/" || lastSegment.includes("."))) {
    return secured(notFoundResponse(normalized), preview);
  }
  if (direct.status !== 404) {
    return secured(direct, preview);
  }

  const htmlUrl = new URL(url);
  htmlUrl.pathname = `${normalized}.html`;
  const html = await env.ASSETS.fetch(new Request(htmlUrl, request));
  if (html.status === 404) return secured(notFoundResponse(normalized), preview);
  return secured(html, preview);
}

// `POST /v1/estimate` — the shape-only resource estimator. Every number in
// the response comes from `estimate_json`; this function never parses,
// recomputes, rounds, clamps, or otherwise "fixes up" any figure it returns,
// and it never reimplements the engine's error envelope. An oversized body
// is routed through the exact same "malformed manifest" path as any other
// unparseable input, rather than a bespoke JS-side error shape: replacing it
// with an empty string still fails `estimate_json`'s own JSON parse, so the
// engine itself produces the (non-`internal_error`) reason code.
//
// Three things happen around that untouched computation: resolving an
// optional `Authorization: Bearer <key>` caller (Task 5) into either the
// keyed or anonymous rate tier, the corresponding rate-limit check (Task 3
// for anonymous, Task 5 for keyed) that can turn the whole request into a
// 429 (or a 401 for a key that is present but invalid) before
// `estimate_json` ever runs, and a fire-and-forget shape-only demand-log
// write (Task 4) after it, via `ctx.waitUntil`, that can never delay or
// fail the response.
async function estimateResponse(request, env, ctx) {
  if (request.method !== "POST") {
    return new Response("method not allowed", {
      status: 405,
      headers: { Allow: "POST", "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  const keyResolution = await resolveKeyedCaller(env, request.headers.get("Authorization") || "");
  if (keyResolution.status === "invalid") {
    return structuredErrorResponse(401, "invalid_key");
  }

  let keyId = null;
  let ipHash = null;
  let rateLimit;
  if (keyResolution.status === "keyed") {
    keyId = keyResolution.keyId;
    rateLimit = await checkKeyedRateLimit(env, keyId);
  } else {
    ipHash = await saltedIpHash(request.headers.get("CF-Connecting-IP") || "");
    rateLimit = await checkAnonymousRateLimit(env, ipHash);
  }
  if (rateLimit.limited) {
    return rateLimitedResponse(rateLimit.retryAfterSeconds);
  }

  const declaredLength = Number(request.headers.get("content-length") ?? "");
  let body;
  if (Number.isFinite(declaredLength) && declaredLength > MAX_ESTIMATE_REQUEST_BYTES) {
    body = "";
  } else {
    const bytes = new Uint8Array(await request.arrayBuffer());
    body = bytes.byteLength > MAX_ESTIMATE_REQUEST_BYTES ? "" : new TextDecoder().decode(bytes);
  }

  const responseBody = estimateJson(body);
  logDemand(env, ctx, body, responseBody, { keyId, ipHash });
  logRejection(env, ctx, responseBody, { keyId, ipHash });
  pruneExpiredRows(env, ctx, Math.floor(Date.now() / 1000));

  return new Response(responseBody, {
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    // Retired service hostnames must never canonicalize to the website. Once
    // their custom domains are migrated to Pages, every path and method stays
    // origin-free and permanently unavailable without touching ASSETS.
    if (RETIRED_HOSTS.has(url.hostname.toLowerCase())) {
      return secured(goneResponse(), false);
    }
    const preview = url.hostname.endsWith(".pages.dev");
    const redirect = canonicalRedirect(url);
    if (redirect) return secured(redirect, preview);

    if (url.pathname === "/v1/estimate") {
      return secured(await estimateResponse(request, env, ctx), preview);
    }
    if (url.pathname === "/v1/keys") {
      return secured(await keysResponse(request, env), preview);
    }

    const normalized = normalizedPath(url.pathname);
    const permanent = PERMANENT_REDIRECTS.get(normalized);
    if (permanent) {
      return secured(new Response(null, {
        status: 308,
        headers: {
          "Cache-Control": "public, max-age=86400",
          Location: new URL(permanent, "https://tinyzkp.com").toString(),
        },
      }), preview);
    }

    const retired = retiredResponse(url.pathname);
    if (retired) return secured(retired, preview);
    return staticResponse(request, env, url, preview);
  },
};
