// Cloudflare Pages Function — creates a Stripe Checkout session.
//
// Secrets required (set via `wrangler pages secret put --project-name tinyzkp`):
//   STRIPE_SECRET_KEY                  — sk_live_... or sk_test_...
//   STRIPE_PRICE_ID_METERED            — metered proof-count price (legacy fallback STRIPE_PRICE_ID)
//   STRIPE_PRICE_ID_TRACE_STEP_METERED — metered trace-step price ($0.50/M, used for Compute and as
//                                        the large-T overage line on Developer/Pro)
//   STRIPE_PRICE_ID_DEVELOPER          — $19/mo Developer flat price (v2; legacy $9 was DEVELOPER_V1)
//   STRIPE_PRICE_ID_DEVELOPER_ANNUAL   — $182/yr Developer annual
//   STRIPE_PRICE_ID_PRO                — $199/mo Pro flat price (renamed from Scale)
//   STRIPE_PRICE_ID_PRO_ANNUAL         — $1,910/yr Pro annual
//
// Request body: { email, plan, cadence }
//   plan    ∈ {"developer", "pro", "compute"}     (free/verifier-only handled elsewhere)
//   cadence ∈ {"monthly", "annual"}               (default "monthly"; ignored for "compute")
//
// Compute is pure usage-based (no flat fee, just the trace-step meter).

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
// matching env secret isn't set OR the plan is purely usage-based; caller
// falls back to metered-only billing so an incomplete deploy never breaks
// a signup.
//
// Legacy plan slugs ("team", "scale") map to "pro" so existing signup
// links keep working through the rollout.
function flatPriceFor(env, plan, cadence) {
  const annual = cadence === "annual";
  switch (plan) {
    case "developer":
      return annual
        ? (env.STRIPE_PRICE_ID_DEVELOPER_ANNUAL || env.STRIPE_PRICE_ID_DEVELOPER || null)
        : (env.STRIPE_PRICE_ID_DEVELOPER || null);
    case "pro":
    case "team":   // legacy alias → Pro
    case "scale":  // legacy alias → Pro
      return annual
        ? (env.STRIPE_PRICE_ID_PRO_ANNUAL
            || env.STRIPE_PRICE_ID_PRO
            || env.STRIPE_PRICE_ID_SCALE_ANNUAL
            || env.STRIPE_PRICE_ID_SCALE
            || null)
        : (env.STRIPE_PRICE_ID_PRO || env.STRIPE_PRICE_ID_SCALE || null);
    case "compute":
      return null;  // pure usage-based, no flat fee
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

    // Plan slug normalization. Legacy "team"/"scale" still map to "pro"
    // for any signup link minted before the v2 pricing rollout.
    const planRaw = body.plan;
    const validPlans = new Set(["developer", "pro", "compute", "team", "scale"]);
    let selectedPlan = validPlans.has(planRaw) ? planRaw : "developer";
    if (selectedPlan === "team" || selectedPlan === "scale") selectedPlan = "pro";
    const cadence = body.cadence === "annual" ? "annual" : "monthly";

    const STRIPE_SECRET_KEY = context.env.STRIPE_SECRET_KEY;
    // Per-proof metered price (small-T plans). Legacy fallback to STRIPE_PRICE_ID.
    const STRIPE_PRICE_ID_METERED = context.env.STRIPE_PRICE_ID_METERED || context.env.STRIPE_PRICE_ID;
    // Per-trace-step metered price ($0.50/M, used for Compute and overage on Developer/Pro).
    const STRIPE_PRICE_ID_TRACE_STEP_METERED = context.env.STRIPE_PRICE_ID_TRACE_STEP_METERED;

    if (!STRIPE_SECRET_KEY) {
      return new Response(JSON.stringify({ error: "server misconfigured" }), {
        status: 500,
        headers: jsonHeaders,
      });
    }

    const params = new URLSearchParams();
    params.append("mode", "subscription");
    params.append("customer_email", email);

    // Line-item assembly:
    //   - Developer / Pro: flat fee + per-proof meter + (if env set) trace-step overage meter
    //   - Compute: trace-step meter only (no flat fee, no per-proof line)
    let lineItem = 0;

    if (selectedPlan === "compute") {
      if (!STRIPE_PRICE_ID_TRACE_STEP_METERED) {
        return new Response(JSON.stringify({ error: "compute tier not yet available" }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      params.append(`line_items[${lineItem}][price]`, STRIPE_PRICE_ID_TRACE_STEP_METERED);
      lineItem += 1;
    } else {
      // Developer / Pro
      if (STRIPE_PRICE_ID_METERED) {
        params.append(`line_items[${lineItem}][price]`, STRIPE_PRICE_ID_METERED);
        lineItem += 1;
      }
      const flatPriceId = flatPriceFor(context.env, selectedPlan, cadence);
      if (flatPriceId) {
        params.append(`line_items[${lineItem}][price]`, flatPriceId);
        params.append(`line_items[${lineItem}][quantity]`, "1");
        lineItem += 1;
      }
      if (STRIPE_PRICE_ID_TRACE_STEP_METERED) {
        params.append(`line_items[${lineItem}][price]`, STRIPE_PRICE_ID_TRACE_STEP_METERED);
        lineItem += 1;
      }
    }

    if (lineItem === 0) {
      return new Response(JSON.stringify({ error: "server misconfigured: no price ids set" }), {
        status: 500,
        headers: jsonHeaders,
      });
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
