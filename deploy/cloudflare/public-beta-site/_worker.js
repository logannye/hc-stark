// Dedicated Cloudflare Pages policy for the TinyZKP self-service public beta.
// This file intentionally does not derive from the containment worker.

const HOST = "tinyzkp.com";
const PAGES_PREVIEW_SUFFIX = ".tinyzkp.pages.dev";
const PUBLIC = new Set(["/", "/docs", "/security", "/privacy", "/terms", "/requests", "/pricing", "/dashboard", "/status"]);
const ASSETS = ["/index.html", "/docs.html", "/security.html", "/privacy.html", "/terms.html", "/requests.html", "/pricing.html", "/dashboard.html", "/dashboard.js", "/status.html", "/discovery.json", "/pricing.json", "/openapi.json"];
const RETIRED = ["/enterprise", "/evaluation", "/pilot", "/platform-rollout", "/contact-sales", "/certified", "/fleet", "/oem", "/engine", "/benchmarks", "/plonky3", "/research"];
const CSP = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://api.tinyzkp.com; font-src 'self'; upgrade-insecure-requests";

function secured(response) {
  const headers = new Headers(response.headers);
  headers.set("Content-Security-Policy", CSP);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-site");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function redirect(location, status = 308) {
  return new Response(null, { status, headers: { Location: location, "Cache-Control": "public, max-age=3600" } });
}

function normalized(path) {
  return path.endsWith(".html") ? path.slice(0, -5) : path;
}

function isPagesPreview(url, env) {
  const branch = env.CF_PAGES_BRANCH;
  return url.protocol === "https:"
    && typeof branch === "string"
    && branch.length > 0
    && branch !== "main"
    && url.hostname.toLowerCase().endsWith(PAGES_PREVIEW_SUFFIX);
}

function siteLocation(url, env, path) {
  const origin = isPagesPreview(url, env) ? url.origin : `https://${HOST}`;
  return new URL(path, `${origin}/`).toString();
}

function assetRequest(request, path = null) {
  const asset = new URL(request.url);
  asset.protocol = "https:";
  asset.hostname = HOST;
  asset.port = "";
  if (path !== null) asset.pathname = path;
  return new Request(asset, request);
}

async function releaseInfo(env) {
  const assets = [];
  for (const path of ASSETS) {
    const response = await env.ASSETS.fetch(new Request(new URL(path, "https://tinyzkp.com")));
    if (response.status !== 200) return { service: "site", release_sha: env.TINYZKP_RELEASE_SHA || null, asset_manifest_complete: false };
    const bytes = await response.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    assets.push({ path, bytes: bytes.byteLength, sha256: [...new Uint8Array(digest)].map((v) => v.toString(16).padStart(2, "0")).join("") });
  }
  const canonical = new TextEncoder().encode(JSON.stringify(assets));
  const digest = await crypto.subtle.digest("SHA-256", canonical);
  return { service: "site", release_sha: env.TINYZKP_RELEASE_SHA || env.CF_PAGES_COMMIT_SHA || null,
    asset_manifest_complete: true, asset_manifest_sha256: [...new Uint8Array(digest)].map((v) => v.toString(16).padStart(2, "0")).join("") };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const canonicalHost = url.protocol === "https:" && url.hostname.toLowerCase() === HOST;
    if (!canonicalHost && !isPagesPreview(url, env)) {
      const target = new URL(url); target.protocol = "https:"; target.hostname = HOST; target.port = "";
      return secured(redirect(target.toString()));
    }
    const path = normalized(url.pathname);
    if (path === "/signup") return secured(redirect("https://api.tinyzkp.com/v1/auth/github/start?return_path=/dashboard", 302));
    if (path === "/contact") return secured(redirect(siteLocation(url, env, "/requests")));
    if (["/enterprise", "/evaluation", "/pilot", "/platform-rollout"].includes(path)) {
      return secured(redirect(siteLocation(url, env, "/pricing")));
    }
    if (RETIRED.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))) {
      return secured(new Response("This legacy surface has been retired. Use self-service pricing.", { status: 410, headers: { "Content-Type": "text/plain; charset=utf-8" } }));
    }
    if (url.pathname === "/api/release" && request.method === "GET") {
      return secured(new Response(JSON.stringify(await releaseInfo(env)), { headers: { "Content-Type": "application/json" } }));
    }
    if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/functions/")) {
      return secured(new Response(JSON.stringify({ error: { code: "not_found" } }), { status: 404, headers: { "Content-Type": "application/json" } }));
    }
    const segment = url.pathname.split("/").pop() || "";
    if (!segment.includes(".") && !PUBLIC.has(url.pathname)) return secured(new Response("not found", { status: 404 }));
    let response = await env.ASSETS.fetch(assetRequest(request));
    if (response.status === 404 && PUBLIC.has(url.pathname) && url.pathname !== "/") {
      response = await env.ASSETS.fetch(assetRequest(request, `${url.pathname}.html`));
    }
    return secured(response);
  },
};
