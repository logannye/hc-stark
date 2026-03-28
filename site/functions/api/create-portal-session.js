// Cloudflare Pages Function — creates a Stripe Customer Portal session.
//
// Allows paying customers to manage billing, update payment methods,
// view invoices, and cancel subscriptions.
//
// Secrets required (set via `wrangler pages secret put`):
//   STRIPE_SECRET_KEY          — sk_live_... or sk_test_...
//   STRIPE_PORTAL_CONFIG_ID    — bpc_... (optional, uses default if omitted)

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
  const allowedOrigin = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com"
    ? origin : "https://tinyzkp.com";
  const corsHeaders = {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    if (!(await checkRateLimit(ip))) {
      return new Response(JSON.stringify({ error: "Too many requests. Try again later." }), {
        status: 429, headers: jsonHeaders,
      });
    }

    const { email } = await context.request.json();
    if (!email || !email.includes("@") || email.length > 254) {
      return new Response(JSON.stringify({ error: "valid email required" }), {
        status: 400,
        headers: jsonHeaders,
      });
    }

    const STRIPE_SECRET_KEY = context.env.STRIPE_SECRET_KEY;
    if (!STRIPE_SECRET_KEY) {
      return new Response(JSON.stringify({ error: "server misconfigured" }), {
        status: 500,
        headers: jsonHeaders,
      });
    }

    // Look up the customer by email.
    const searchResp = await fetch(
      `https://api.stripe.com/v1/customers/search?query=email:'${encodeURIComponent(email)}'`,
      {
        headers: {
          Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
        },
      }
    );

    const searchResult = await searchResp.json();
    if (!searchResp.ok || !searchResult.data || searchResult.data.length === 0) {
      return new Response(JSON.stringify({ error: "No billing account found for this email. Free-tier accounts don't have billing." }), {
        status: 404,
        headers: jsonHeaders,
      });
    }

    const customerId = searchResult.data[0].id;

    // Create a portal session using the activated portal configuration.
    const params = new URLSearchParams();
    params.append("customer", customerId);
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
        status: 502,
        headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify({ url: portalSession.url }), {
      status: 200,
      headers: jsonHeaders,
    });
  } catch (err) {
    console.error("Portal error:", err);
    return new Response(JSON.stringify({ error: "internal error" }), {
      status: 500,
      headers: jsonHeaders,
    });
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("Origin") || "";
  const allowedOrigin = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com"
    ? origin : "https://tinyzkp.com";
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
