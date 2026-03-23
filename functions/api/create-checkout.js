// Cloudflare Pages Function — creates a Stripe Checkout session.
//
// Secrets required (set via `wrangler pages secret put`):
//   STRIPE_SECRET_KEY — sk_live_... or sk_test_...
//   STRIPE_PRICE_ID  — price_...

const RATE_LIMIT_MAX = 10;         // max requests per window per IP
const RATE_LIMIT_WINDOW_S = 300;   // 5-minute window

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/checkout/${ip}`);
  const cached = await cache.match(key);

  let count = 0;
  if (cached) {
    count = parseInt(await cached.text(), 10) || 0;
  }

  if (count >= RATE_LIMIT_MAX) {
    return false;
  }

  const resp = new Response(String(count + 1), {
    headers: { "Cache-Control": `s-maxage=${RATE_LIMIT_WINDOW_S}` },
  });
  await cache.put(key, resp);
  return true;
}

export async function onRequestPost(context) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

  try {
    // Rate limit by IP.
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    const allowed = await checkRateLimit(ip);
    if (!allowed) {
      return new Response(JSON.stringify({ error: "too many requests, try again later" }), {
        status: 429,
        headers: jsonHeaders,
      });
    }

    const { email, plan } = await context.request.json();
    if (!email || !email.includes("@") || email.length > 254) {
      return new Response(JSON.stringify({ error: "valid email required" }), {
        status: 400,
        headers: jsonHeaders,
      });
    }

    const selectedPlan = (plan === "team" || plan === "scale") ? plan : "developer";

    const STRIPE_SECRET_KEY = context.env.STRIPE_SECRET_KEY;
    const STRIPE_PRICE_ID_METERED = context.env.STRIPE_PRICE_ID_METERED || context.env.STRIPE_PRICE_ID;
    const STRIPE_PRICE_ID_TEAM = context.env.STRIPE_PRICE_ID_TEAM;
    const STRIPE_PRICE_ID_SCALE = context.env.STRIPE_PRICE_ID_SCALE;

    if (!STRIPE_SECRET_KEY || !STRIPE_PRICE_ID_METERED) {
      return new Response(JSON.stringify({ error: "server misconfigured" }), {
        status: 500,
        headers: jsonHeaders,
      });
    }

    const params = new URLSearchParams();
    params.append("mode", "subscription");
    params.append("customer_email", email);
    params.append("line_items[0][price]", STRIPE_PRICE_ID_METERED);

    if (selectedPlan === "team" && STRIPE_PRICE_ID_TEAM) {
      params.append("line_items[1][price]", STRIPE_PRICE_ID_TEAM);
      params.append("line_items[1][quantity]", "1");
    } else if (selectedPlan === "scale" && STRIPE_PRICE_ID_SCALE) {
      params.append("line_items[1][price]", STRIPE_PRICE_ID_SCALE);
      params.append("line_items[1][quantity]", "1");
    }

    params.append("metadata[plan]", selectedPlan);
    params.append("subscription_data[metadata][plan]", selectedPlan);
    params.append("success_url", "https://tinyzkp.com/welcome?plan=" + selectedPlan);
    params.append("cancel_url", "https://tinyzkp.com/signup?cancelled=true");

    const resp = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    const session = await resp.json();
    if (!resp.ok) {
      console.error("Stripe error:", JSON.stringify(session));
      return new Response(JSON.stringify({ error: "checkout creation failed" }), {
        status: 502,
        headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify({ url: session.url }), {
      status: 200,
      headers: jsonHeaders,
    });
  } catch (err) {
    console.error("Checkout error:", err);
    return new Response(JSON.stringify({ error: "internal error" }), {
      status: 500,
      headers: jsonHeaders,
    });
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
