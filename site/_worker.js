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
import * as createPortal       from "./functions/api/create-portal-session.js";
import * as demoPoll           from "./functions/api/demo-poll.js";
import * as demoProve          from "./functions/api/demo-prove.js";
import * as demoVerify         from "./functions/api/demo-verify.js";
import * as sendMagicLink      from "./functions/api/send-magic-link.js";
import * as verifyMagicLink    from "./functions/api/verify-magic-link.js";

const ROUTES = {
  "/api/contact":              contact,
  "/api/create-checkout":      createCheckout,
  "/api/create-free-account":  createFreeAccount,
  "/api/create-portal-session": createPortal,
  "/api/demo-poll":            demoPoll,
  "/api/demo-prove":           demoProve,
  "/api/demo-verify":          demoVerify,
  "/api/send-magic-link":      sendMagicLink,
  "/api/verify-magic-link":    verifyMagicLink,
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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
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
          next:     async () => env.ASSETS.fetch(request),
          data:     {},
        };
        try {
          return await (fn || generic)(context);
        } catch (e) {
          console.error(`[worker] handler error on ${url.pathname}:`, e);
          return new Response(JSON.stringify({ error: "internal error" }), {
            status: 500,
            headers: { "Content-Type": "application/json" },
          });
        }
      }
      // Route exists but no handler for this method.
      return new Response(null, {
        status: 405,
        headers: { "Allow": Object.entries(METHOD_HANDLER)
          .filter(([_, h]) => mod[h])
          .map(([m]) => m).join(", ") },
      });
    }

    // Not an /api/* route — fall through to static assets.
    return env.ASSETS.fetch(request);
  },
};
