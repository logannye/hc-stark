// site/_worker.js — Cloudflare Pages Advanced Mode worker.
//
// When `_worker.js` exists at the project root, Cloudflare Pages uses it as
// the single Worker entry point and IGNORES auto-discovery of the
// `functions/` directory. We adopt this pattern because Cloudflare's
// auto-discovery silently dropped the new demo-{prove,poll,verify} functions
// from the deployed bundle even though the local build registered them
// correctly. Routing through this single worker is more deterministic.
//
// Structure: re-export each function module, build a route table, dispatch
// by (path, method). Anything unmatched falls through to the static asset
// handler via env.ASSETS.fetch().

import * as contact            from "./functions/api/contact.js";
import * as createCheckout     from "./functions/api/create-checkout.js";
import * as createFreeAccount  from "./functions/api/create-free-account.js";
import * as createPilotCheckout from "./functions/api/create-pilot-checkout.js";
import * as createPortal       from "./functions/api/create-portal-session.js";
import * as demoPoll           from "./functions/api/demo-poll.js";
import * as demoProve          from "./functions/api/demo-prove.js";
import * as demoVerify         from "./functions/api/demo-verify.js";
import * as events             from "./functions/api/events.js";
import * as rotateKey          from "./functions/api/rotate-key.js";
import * as sendMagicLink      from "./functions/api/send-magic-link.js";
import * as verifyMagicLink    from "./functions/api/verify-magic-link.js";
import * as sessionResolve     from "./functions/api/session-resolve.js";
import * as statusProbe        from "./functions/api/status-probe.js";
import * as revealKey          from "./functions/api/reveal-key.js";
import * as logout             from "./functions/api/logout.js";
import * as usage              from "./functions/api/usage.js";
import * as jobs               from "./functions/api/jobs.js";

const ROUTES = {
  "/api/contact":              contact,
  "/api/create-checkout":      createCheckout,
  "/api/create-free-account":  createFreeAccount,
  "/api/create-pilot-checkout": createPilotCheckout,
  "/api/create-portal-session": createPortal,
  "/api/demo-poll":            demoPoll,
  "/api/demo-prove":           demoProve,
  "/api/demo-verify":          demoVerify,
  "/api/events":               events,
  "/api/rotate-key":           rotateKey,
  "/api/send-magic-link":      sendMagicLink,
  "/api/verify-magic-link":    verifyMagicLink,
  "/api/session-resolve":      sessionResolve,
  "/api/status-probe":         statusProbe,
  "/api/reveal-key":           revealKey,
  "/api/logout":               logout,
  "/api/usage":                usage,
  "/api/jobs":                 jobs,
};

// Map HTTP method → expected export name on the function module.
const METHOD_HANDLER = {
  GET:     "onRequestGet",
  POST:    "onRequestPost",
  PUT:     "onRequestPut",
  DELETE:  "onRequestDelete",
  PATCH:   "onRequestPatch",
  HEAD:    "onRequestHead",
  OPTIONS: "onRequestOptions",
};

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cross-Origin-Opener-Policy": "same-origin",
};

const CANONICAL_HOST = "tinyzkp.com";
const TYPO_HOSTS = new Set([
  "www.tinyzkp.com",
  "tny" + "zkp.com",
  "www.tny" + "zkp.com",
]);

function envString(env, key) {
  const value = env && typeof env[key] === "string" ? env[key].trim() : "";
  return value || null;
}

function canonicalHostRedirect(url) {
  const host = url.hostname.toLowerCase();
  if (host === CANONICAL_HOST && url.protocol === "https:") return null;
  if (host !== CANONICAL_HOST && !TYPO_HOSTS.has(host)) return null;

  const target = new URL(url);
  target.protocol = "https:";
  target.hostname = CANONICAL_HOST;
  target.port = "";
  return new Response(null, {
    status: 308,
    headers: {
      "Location": target.toString(),
      "Cache-Control": "public, max-age=3600",
    },
  });
}

function releaseInfo(env) {
  return {
    service: "site",
    package_version: "0.1.0",
    release_sha: envString(env, "TINYZKP_RELEASE_SHA") || envString(env, "CF_PAGES_COMMIT_SHA"),
    release_ref: envString(env, "TINYZKP_RELEASE_REF") || envString(env, "CF_PAGES_BRANCH"),
    build_url: envString(env, "TINYZKP_RELEASE_BUILD_URL") || envString(env, "CF_PAGES_URL"),
  };
}

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    headers.set(name, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function fetchStaticAsset(request, env, url) {
  const direct = await env.ASSETS.fetch(request);
  if (direct.status !== 404) return withSecurityHeaders(direct);

  // Cloudflare Pages usually resolves extensionless HTML paths, but Advanced
  // Mode workers can bypass that behavior. Keep canonical URLs like /verify
  // and /use-cases/verifiable-state-transition working by trying .html on
  // static, non-API paths that do not already contain an extension.
  if (request.method !== "GET" && request.method !== "HEAD") return withSecurityHeaders(direct);
  if (url.pathname === "/" || url.pathname.startsWith("/api/")) return withSecurityHeaders(direct);
  const lastSegment = url.pathname.split("/").pop() || "";
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

    if (url.pathname === "/api/release" && request.method.toUpperCase() === "GET") {
      return withSecurityHeaders(new Response(JSON.stringify(releaseInfo(env)), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }));
    }

    const mod = ROUTES[url.pathname];

    if (mod) {
      const method = request.method.toUpperCase();
      const handlerName = METHOD_HANDLER[method];
      const fn = handlerName ? mod[handlerName] : undefined;
      // Fallback: a generic onRequest handler that runs for any method.
      const generic = mod.onRequest;

      if (fn || generic) {
        const context = {
          request,
          env,
          params: {},
          waitUntil: ctx && ctx.waitUntil ? ctx.waitUntil.bind(ctx) : (() => {}),
          next:     async () => fetchStaticAsset(request, env, url),
          data:     {},
        };
        try {
          return withSecurityHeaders(await (fn || generic)(context));
        } catch (e) {
          console.error(`[worker] handler error on ${url.pathname}:`, e);
          return withSecurityHeaders(new Response(JSON.stringify({ error: "internal error" }), {
            status: 500,
            headers: { "Content-Type": "application/json" },
          }));
        }
      }
      // Route exists but no handler for this method.
      return withSecurityHeaders(new Response(null, {
        status: 405,
        headers: { "Allow": Object.entries(METHOD_HANDLER)
          .filter(([_, h]) => mod[h])
          .map(([m]) => m).join(", ") },
      }));
    }

    // Not an /api/* route — fall through to static assets.
    return fetchStaticAsset(request, env, url);
  },
};
