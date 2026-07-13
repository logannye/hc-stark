// Cloudflare Pages Advanced Mode worker for the TinyZKP backend recovery.
// Only release identity and evaluation intake execute server-side. Historical
// account, checkout, receipt, demo, and proving functions are not imported.

import * as contact from "./functions/api/contact.js";

const ROUTES = { "/api/contact": contact };

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cross-Origin-Opener-Policy": "same-origin",
};

const CANONICAL_HOST = "tinyzkp.com";
const PUBLIC_EXTENSIONLESS_PATHS = new Set([
  "/", "/engine", "/benchmarks", "/plonky3", "/security", "/docs",
  "/pricing", "/status", "/contact", "/privacy", "/terms", "/requests",
]);
const SITE_ASSET_MANIFEST_PATHS = [
  "/index.html",
  "/contact.html",
  "/requests.html",
  "/security.html",
  "/privacy.html",
  "/terms.html",
  "/status.html",
  "/.well-known/security.txt",
  "/pricing.json",
  "/openapi.json",
];

const PERMANENT_REDIRECTS = new Map([
  ["/account", "/status"],
  ["/welcome", "/status"],
  ["/compute", "/engine"],
  ["/receipts", "/engine"],
  ["/try", "/benchmarks"],
  ["/verify", "/status"],
  ["/signup", "/contact?intent=memory_bounded_evaluation"],
  ["/pilot", "/pricing"],
  ["/platform-rollout", "/pricing"],
  ["/enterprise", "/pricing"],
  ["/evaluation", "/pricing"],
  ["/mcp", "/docs"],
  ["/changelog", "/status"],
]);

const GONE_PREFIXES = [
  "/agents", "/agent-", "/verifiable-agent-output", "/roi", "/calculator",
  "/fit", "/use-cases", "/compare", "/integrations", "/apps", "/badges",
  "/examples", "/limits", "/recipes", "/research", "/templates",
  "/vendor",
];

const GONE_ASSETS = new Set([
  "/mcp.json", "/evaluation.json", "/enterprise.json", "/platform-rollout.json",
  "/changelog.json", "/fit.json", "/integrations.json", "/limits.json",
  "/.well-known/mcp/server-card.json",
  "/.well-known/tinyzkp-badge.json", "/.well-known/tinyzkp-offers.json",
  "/.well-known/tinyzkp-receipt-share.json", "/pilot-preview.jpg",
]);

const MAINTENANCE_DISABLED_API_ROUTES = new Set([
  "/api/create-checkout", "/api/create-free-account", "/api/create-pilot-checkout",
  "/api/demo-poll", "/api/demo-prove", "/api/demo-verify",
]);

function envString(env, key) {
  const value = env && typeof env[key] === "string" ? env[key].trim() : "";
  return value || null;
}

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function canonicalHostRedirect(url) {
  const host = url.hostname.toLowerCase();
  if (host === CANONICAL_HOST && url.protocol === "https:") return null;
  const target = new URL(url);
  target.protocol = "https:";
  target.hostname = CANONICAL_HOST;
  target.port = "";
  return new Response(null, {
    status: 308,
    headers: { Location: target.toString(), "Cache-Control": "public, max-age=3600" },
  });
}

function normalizedRetiredPath(pathname) {
  return pathname.endsWith(".html") ? pathname.slice(0, -5) : pathname;
}

function retiredSurfaceResponse(url) {
  const normalized = normalizedRetiredPath(url.pathname);
  const redirect = PERMANENT_REDIRECTS.get(normalized);
  if (redirect) {
    return new Response(null, {
      status: 308,
      headers: {
        Location: new URL(redirect, "https://tinyzkp.com").toString(),
        "Cache-Control": "public, max-age=86400",
      },
    });
  }
  const gone = GONE_ASSETS.has(url.pathname)
    || GONE_PREFIXES.some((prefix) => normalized.startsWith(prefix));
  if (!gone) return null;
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Retired surface — TinyZKP</title></head><body><main><h1>This surface has been retired.</h1><p>TinyZKP is focused on resource-bounded Plonky3 proving infrastructure.</p><p><a href="/engine">Review the engine</a> · <a href="/benchmarks">Run the benchmark</a></p></main></body></html>`, {
    status: 410,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

function protocolUpgradeResponse() {
  return new Response(JSON.stringify({
    code: "protocol_upgrade",
    error: "Hosted proving, account creation, and paid checkout are disabled while the Plonky3 resource-bounded backend is under review.",
    status: "https://tinyzkp.com/status",
  }), { status: 503, headers: { "Content-Type": "application/json" } });
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function siteAssetManifest(env) {
  const assets = [];
  for (const path of SITE_ASSET_MANIFEST_PATHS) {
    const response = await env.ASSETS.fetch(new Request(new URL(path, "https://tinyzkp.com")));
    if (response.status !== 200) {
      return { complete: false, sha256: null, assets: [], error: `${path} returned ${response.status}` };
    }
    const bytes = await response.arrayBuffer();
    assets.push({ path, bytes: bytes.byteLength, sha256: await sha256Hex(bytes) });
  }
  const canonical = new TextEncoder().encode(JSON.stringify(assets));
  return { complete: true, sha256: await sha256Hex(canonical), assets };
}

async function releaseInfo(env) {
  const assetManifest = await siteAssetManifest(env);
  return {
    service: "site",
    package_version: "0.1.0",
    release_sha: envString(env, "TINYZKP_RELEASE_SHA") || envString(env, "CF_PAGES_COMMIT_SHA"),
    release_ref: envString(env, "TINYZKP_RELEASE_REF") || envString(env, "CF_PAGES_BRANCH"),
    build_url: envString(env, "TINYZKP_RELEASE_BUILD_URL") || envString(env, "CF_PAGES_URL"),
    asset_manifest_complete: assetManifest.complete,
    asset_manifest_sha256: assetManifest.sha256,
  };
}

async function fetchStaticAsset(request, env, url) {
  const lastSegment = url.pathname.split("/").pop() || "";
  if (
    new Set(["GET", "HEAD"]).has(request.method)
    && !lastSegment.includes(".")
    && !PUBLIC_EXTENSIONLESS_PATHS.has(url.pathname)
  ) {
    return withSecurityHeaders(new Response("not found", {
      status: 404,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    }));
  }
  const direct = await env.ASSETS.fetch(request);
  if (direct.status !== 404) return withSecurityHeaders(direct);
  if (!new Set(["GET", "HEAD"]).has(request.method) || url.pathname === "/" || url.pathname.startsWith("/api/")) {
    return withSecurityHeaders(direct);
  }
  if (lastSegment.includes(".")) return withSecurityHeaders(direct);
  const htmlUrl = new URL(url);
  htmlUrl.pathname = `${url.pathname}.html`;
  return withSecurityHeaders(await env.ASSETS.fetch(new Request(htmlUrl, request)));
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const canonicalRedirect = canonicalHostRedirect(url);
    if (canonicalRedirect) return withSecurityHeaders(canonicalRedirect);
    const retired = retiredSurfaceResponse(url);
    if (retired) return withSecurityHeaders(retired);

    if (url.pathname === "/api/release" && request.method === "GET") {
      return withSecurityHeaders(new Response(JSON.stringify(await releaseInfo(env)), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }));
    }
    if (MAINTENANCE_DISABLED_API_ROUTES.has(url.pathname)) {
      return withSecurityHeaders(protocolUpgradeResponse());
    }
    if (ROUTES[url.pathname]) {
      const method = request.method.toUpperCase();
      const handler = method === "POST" ? contact.onRequestPost
        : method === "OPTIONS" ? contact.onRequestOptions : null;
      if (!handler) return withSecurityHeaders(new Response(null, { status: 405, headers: { Allow: "POST, OPTIONS" } }));
      try {
        return withSecurityHeaders(await handler({
          request,
          env,
          params: {},
          waitUntil: ctx && ctx.waitUntil ? ctx.waitUntil.bind(ctx) : (() => {}),
          data: {},
        }));
      } catch (error) {
        console.error("[worker] contact handler failed", error);
        return withSecurityHeaders(new Response(JSON.stringify({ error: "internal error" }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }));
      }
    }
    if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/functions/")) {
      return withSecurityHeaders(new Response(JSON.stringify({ error: "not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      }));
    }
    return fetchStaticAsset(request, env, url);
  },
};
