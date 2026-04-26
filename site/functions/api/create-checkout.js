// Cloudflare Pages Function — creates a Stripe Checkout session.
//
// Secrets required (set via `wrangler pages secret put --project-name tinyzkp`):
//   STRIPE_SECRET_KEY               — sk_live_... or sk_test_...
//   STRIPE_PRICE_ID_METERED         — metered usage price (replaces legacy STRIPE_PRICE_ID)
//   STRIPE_PRICE_ID_DEVELOPER       — $9/mo Developer flat price
//   STRIPE_PRICE_ID_DEVELOPER_ANNUAL — $86.40/yr Developer annual
//   STRIPE_PRICE_ID_TEAM            — $49/mo Team flat price
//   STRIPE_PRICE_ID_TEAM_ANNUAL     — $470.40/yr Team annual
//   STRIPE_PRICE_ID_SCALE           — $199/mo Scale flat price
//   STRIPE_PRICE_ID_SCALE_ANNUAL    — $1,910.40/yr Scale annual
//
// Request body: { email, plan, cadence }
//   plan    ∈ {"developer", "team", "scale"}      (free/verifier-only handled elsewhere)
//   cadence ∈ {"monthly", "annual"}               (default "monthly")

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

// Resolve the flat-fee price ID for (plan, cadence). Returns null if the
// matching env secret isn't set; caller falls back to metered-only billing
// so an incomplete deploy never breaks a signup.
function flatPriceFor(env, plan, cadence) {
  const annual = cadence === "annual";
  switch (plan) {
    case "developer":
      return annual
        ? (env.STRIPE_PRICE_ID_DEVELOPER_ANNUAL || env.STRIPE_PRICE_ID_DEVELOPER || null)
        : (env.STRIPE_PRICE_ID_DEVELOPER || null);
    case "team":
      return annual
        ? (env.STRIPE_PRICE_ID_TEAM_ANNUAL || env.STRIPE_PRICE_ID_TEAM || null)
        : (env.STRIPE_PRICE_ID_TEAM || null);
    case "scale":
      return annual
        ? (env.STRIPE_PRICE_ID_SCALE_ANNUAL || env.STRIPE_PRICE_ID_SCALE || null)
        : (env.STRIPE_PRICE_ID_SCALE || null);
    default:
      return null;
  }
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
    // Rate limit by IP.
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    const allowed = await checkRateLimit(ip);
    if (!allowed) {
      return new Response(JSON.stringify({ error: "too many requests, try again later" }), {
        status: 429,
        headers: jsonHeaders,
      });
    }

    const body = await context.request.json();
    const { email } = body;
    if (!email || !email.includes("@") || email.length > 254) {
      return new Response(JSON.stringify({ error: "valid email required" }), {
        status: 400,
        headers: jsonHeaders,
      });
    }

    const planRaw = body.plan;
    const selectedPlan = (planRaw === "team" || planRaw === "scale") ? planRaw : "developer";
    const cadence = body.cadence === "annual" ? "annual" : "monthly";

    const STRIPE_SECRET_KEY = context.env.STRIPE_SECRET_KEY;
    // Metered usage price (all paid plans). Legacy fallback to STRIPE_PRICE_ID.
    const STRIPE_PRICE_ID_METERED = context.env.STRIPE_PRICE_ID_METERED || context.env.STRIPE_PRICE_ID;

    if (!STRIPE_SECRET_KEY || !STRIPE_PRICE_ID_METERED) {
      return new Response(JSON.stringify({ error: "server misconfigured" }), {
        status: 500,
        headers: jsonHeaders,
      });
    }

    const params = new URLSearchParams();
    params.append("mode", "subscription");
    params.append("customer_email", email);

    // All paid plans include metered usage billing.
    params.append("line_items[0][price]", STRIPE_PRICE_ID_METERED);

    // Add the flat-fee price for the selected (plan, cadence). If the
    // matching env var isn't set yet (e.g., a partial Cloudflare deploy
    // before secrets are pushed), fall back to metered-only so the signup
    // doesn't break — customer pays $0 base + usage until the env is
    // complete, which is graceful in the customer-friendly direction.
    const flatPriceId = flatPriceFor(context.env, selectedPlan, cadence);
    if (flatPriceId) {
      params.append("line_items[1][price]", flatPriceId);
      params.append("line_items[1][quantity]", "1");
    }

    // Pass plan + cadence in metadata so the webhook can extract them
    // during tenant provisioning.
    params.append("metadata[plan]", selectedPlan);
    params.append("metadata[cadence]", cadence);
    params.append("subscription_data[metadata][plan]", selectedPlan);
    params.append("subscription_data[metadata][cadence]", cadence);
    params.append("success_url", `https://tinyzkp.com/welcome?plan=${selectedPlan}&cadence=${cadence}`);
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
