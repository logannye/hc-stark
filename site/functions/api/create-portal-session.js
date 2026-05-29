// Cloudflare Pages Function — creates a Stripe Customer Portal session.
//
// Requires a valid tz_session cookie; the Stripe customer ID is server-resolved
// via the session (no client-supplied email, no Stripe customer search).
//
// Secrets required (set via `wrangler pages secret put`):
//   STRIPE_SECRET_KEY          — sk_live_... or sk_test_...
//   STRIPE_PORTAL_CONFIG_ID    — bpc_... (optional, uses default if omitted)
//   INTERNAL_SECRET            — shared secret for webhook calls
//   WEBHOOK_BASE_URL           — (optional) defaults to https://webhook.tinyzkp.com

import { readSessionCookie, webhookSession, corsHeaders, CLEAR_COOKIE } from "./_session.js";

const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_S = 300;

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/portal/${ip}`);
  const cached = await cache.match(key);
  let count = 0;
  if (cached) count = parseInt(await cached.text(), 10) || 0;
  if (count >= RATE_LIMIT_MAX) return false;
  await cache.put(key, new Response(String(count + 1), {
    headers: { "Cache-Control": `s-maxage=${RATE_LIMIT_WINDOW_S}` },
  }));
  return true;
}

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin") || "";
  const cors = corsHeaders(origin);
  const jsonHeaders = { "Content-Type": "application/json", ...cors };

  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    if (!(await checkRateLimit(ip))) {
      return new Response(JSON.stringify({ error: "Too many requests. Try again later." }), {
        status: 429, headers: jsonHeaders,
      });
    }

    // Require a valid session cookie — no client-supplied email accepted.
    const token = readSessionCookie(context.request);
    if (!token) {
      return new Response(JSON.stringify({ error: "no session" }), {
        status: 401, headers: jsonHeaders,
      });
    }

    // Resolve the session to get the Stripe customer ID server-side.
    const { ok, status, body } = await webhookSession(context.env, "/session/resolve", token);
    if (!ok) {
      const headers = status === 401
        ? { ...jsonHeaders, "Set-Cookie": CLEAR_COOKIE }
        : jsonHeaders;
      return new Response(JSON.stringify({ error: body.error || "invalid session" }), {
        status, headers,
      });
    }

    const stripeCustomerId = body.stripe_customer_id;
    if (!stripeCustomerId) {
      return new Response(JSON.stringify({ error: "No billing account for this account." }), {
        status: 404, headers: jsonHeaders,
      });
    }

    const STRIPE_SECRET_KEY = context.env.STRIPE_SECRET_KEY;
    if (!STRIPE_SECRET_KEY) {
      return new Response(JSON.stringify({ error: "server misconfigured" }), {
        status: 500, headers: jsonHeaders,
      });
    }

    // Create a portal session using the server-resolved customer ID directly.
    const params = new URLSearchParams();
    params.append("customer", stripeCustomerId);
    if (context.env.STRIPE_PORTAL_CONFIG_ID) {
      params.append("configuration", context.env.STRIPE_PORTAL_CONFIG_ID);
    }
    params.append("return_url", "https://tinyzkp.com/account");

    const portalResp = await fetch("https://api.stripe.com/v1/billing_portal/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    const portalSession = await portalResp.json();
    if (!portalResp.ok) {
      console.error("Stripe portal error:", JSON.stringify(portalSession));
      return new Response(JSON.stringify({ error: "Could not create portal session." }), {
        status: 502, headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify({ url: portalSession.url }), {
      status: 200, headers: jsonHeaders,
    });
  } catch (err) {
    console.error("Portal error:", err);
    return new Response(JSON.stringify({ error: "internal error" }), {
      status: 500, headers: jsonHeaders,
    });
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("Origin") || "";
  return new Response(null, { headers: corsHeaders(origin) });
}
