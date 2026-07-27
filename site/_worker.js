// Static-only Cloudflare Pages router for TinyZKP.com.
//
// This worker provides canonical routing, security headers, explicit 410
// responses for the retired hosted-service surfaces, and `POST /v1/estimate`
// (a shape-only resource estimate backed by the compiled Rust cost model via
// a WASM import — the same core `hc-cli estimate` calls at the source
// level; a CI gate, `scripts/ci/estimate_wasm_cli_parity_gate.mjs`, fails
// the build if the committed wasm and the native CLI ever compute
// different numbers for the same input, so that never goes unnoticed). It
// calls no upstream service.
//
// It DOES store one thing: a per-IP rate-limit counter for `/v1/estimate`,
// in a D1 database bound as `env.DB` (see site/wrangler.toml and
// migrations/0000_rate_limit_windows.sql), keyed on a salted hash of
// `CF-Connecting-IP` — never the raw address. No number in the estimate
// response itself is touched by any of this; it still comes solely from
// `estimate_json`.

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

async function saltedIpHash(ip) {
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
  if (!lastSegment.includes(".") && !PUBLIC_ROUTES.has(normalized)) {
    return secured(new Response("not found", {
      status: 404,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    }), preview);
  }

  const direct = await env.ASSETS.fetch(request);
  if (direct.status !== 404 || url.pathname === "/" || lastSegment.includes(".")) {
    return secured(direct, preview);
  }

  const htmlUrl = new URL(url);
  htmlUrl.pathname = `${normalized}.html`;
  return secured(await env.ASSETS.fetch(new Request(htmlUrl, request)), preview);
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
// An anonymous rate-limit check (Task 3) runs first and can turn the whole
// request into a 429 before `estimate_json` ever runs.
async function estimateResponse(request, env) {
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
  let body;
  if (Number.isFinite(declaredLength) && declaredLength > MAX_ESTIMATE_REQUEST_BYTES) {
    body = "";
  } else {
    const bytes = new Uint8Array(await request.arrayBuffer());
    body = bytes.byteLength > MAX_ESTIMATE_REQUEST_BYTES ? "" : new TextDecoder().decode(bytes);
  }

  return new Response(estimateJson(body), {
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

export default {
  async fetch(request, env) {
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
      return secured(await estimateResponse(request, env), preview);
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
