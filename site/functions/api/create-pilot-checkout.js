// Cloudflare Pages Function — creates a Stripe Checkout session for the
// $5,000 production pilot. This is intentionally separate from
// create-checkout.js because pilot checkout is a one-time payment, not a
// subscription with metered usage.
//
// Secrets required:
//   STRIPE_SECRET_KEY       — sk_live_... or sk_test_...
//   STRIPE_PRICE_ID_PILOT  — optional one-time $5,000 Production Pilot price.
//                            If absent, checkout uses server-defined inline
//                            price_data so revenue is not blocked on Stripe
//                            product/price catalog write permissions.

const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_S = 300;
const CHECKOUT_ENABLED = false; // v9 protocol-upgrade maintenance gate
const MAX_FIELD_CHARS = 160;
const PILOT_PRODUCT_NAME = "TinyZKP Production Pilot";
const PILOT_PRODUCT_DESCRIPTION = "14-day scoped TinyZKP proof-receipt workflow pilot, creditable toward annual, platform, or reserved-capacity agreement if converted within 60 days";
const PILOT_UNIT_AMOUNT_CENTS = "500000";
const PILOT_CURRENCY = "usd";

const ATTRIBUTION_FIELDS = [
  "source",
  "medium",
  "campaign",
  "platform",
  "use_case",
  "workflow",
  "intent",
  "landing_path",
  "referrer_host",
  "first_seen_at",
];

function corsHeadersFor(request) {
  const origin = request.headers.get("Origin") || "";
  const allowedOrigin = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com"
    ? origin : "https://tinyzkp.com";
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function pilotCheckoutAvailable(env) {
  return Boolean(env.STRIPE_SECRET_KEY);
}

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/pilot-checkout/${ip}`);
  const cached = await cache.match(key);

  let count = 0;
  if (cached) count = parseInt(await cached.text(), 10) || 0;
  if (count >= RATE_LIMIT_MAX) return false;

  await cache.put(key, new Response(String(count + 1), {
    headers: { "Cache-Control": `s-maxage=${RATE_LIMIT_WINDOW_S}` },
  }));
  return true;
}

function cleanField(value) {
  if (typeof value !== "string") return "";
  return value
    .trim()
    .replace(/[^\w .:/@-]/g, "")
    .slice(0, MAX_FIELD_CHARS);
}

function collectMetadata(body) {
  const metadata = {
    plan: "production_pilot",
    package: "production_pilot",
    cadence: "one_time",
    intent: cleanField(body.intent) || "paid_pilot_checkout",
  };
  for (const field of ATTRIBUTION_FIELDS) {
    const clean = cleanField(body[field]);
    if (clean) metadata[field] = clean;
  }
  const workflowSummary = cleanField(body.pilot_workflow || body.workflow_summary);
  if (workflowSummary) metadata.pilot_workflow = workflowSummary;
  return metadata;
}

function appendMetadata(params, metadata, prefix) {
  for (const [field, value] of Object.entries(metadata)) {
    params.append(`${prefix}[${field}]`, value);
  }
}

function appendPilotLineItem(params, priceId) {
  if (priceId) {
    params.append("line_items[0][price]", priceId);
  } else {
    params.append("line_items[0][price_data][currency]", PILOT_CURRENCY);
    params.append("line_items[0][price_data][unit_amount]", PILOT_UNIT_AMOUNT_CENTS);
    params.append("line_items[0][price_data][product_data][name]", PILOT_PRODUCT_NAME);
    params.append("line_items[0][price_data][product_data][description]", PILOT_PRODUCT_DESCRIPTION);
    params.append("line_items[0][price_data][product_data][metadata][package]", "production_pilot");
    params.append("line_items[0][price_data][product_data][metadata][offer]", "paid_pilot");
  }
  params.append("line_items[0][quantity]", "1");
}

function pilotReturnUrl(pathname, status, metadata) {
  const url = new URL(`https://tinyzkp.com${pathname}`);
  url.searchParams.set("checkout", status);
  url.searchParams.set("plan", "production_pilot");
  url.searchParams.set("session_id", "{CHECKOUT_SESSION_ID}");
  for (const [field, value] of Object.entries(metadata)) {
    if (ATTRIBUTION_FIELDS.includes(field) || field === "pilot_workflow") {
      url.searchParams.set(field, value);
    }
  }
  return url.toString();
}

export async function onRequestPost(context) {
  const corsHeaders = corsHeadersFor(context.request);
  const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

  if (!CHECKOUT_ENABLED) {
    return new Response(JSON.stringify({
      error: "Production checkout is paused during the v9 protocol upgrade. Memory-bounded evaluation inquiries remain open through the contact form.",
      code: "protocol_upgrade",
      contact: "https://tinyzkp.com/contact?category=Memory-Bounded%20Prover%20Evaluation",
    }), { status: 503, headers: jsonHeaders });
  }

  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    if (!(await checkRateLimit(ip))) {
      return new Response(JSON.stringify({ error: "too many requests, try again later" }), {
        status: 429,
        headers: jsonHeaders,
      });
    }

    const body = await context.request.json();
    const email = cleanField(body.email).toLowerCase();
    if (!email || !email.includes("@") || email.length > 254) {
      return new Response(JSON.stringify({ error: "valid email required" }), {
        status: 400,
        headers: jsonHeaders,
      });
    }

    const STRIPE_SECRET_KEY = context.env.STRIPE_SECRET_KEY;
    const STRIPE_PRICE_ID_PILOT = context.env.STRIPE_PRICE_ID_PILOT;
    if (!pilotCheckoutAvailable(context.env)) {
      return new Response(JSON.stringify({ error: "pilot checkout not yet available" }), {
        status: 503,
        headers: jsonHeaders,
      });
    }

    const metadata = collectMetadata(body);
    const params = new URLSearchParams();
    params.append("mode", "payment");
    params.append("customer_email", email);
    params.append("client_reference_id", email);
    appendPilotLineItem(params, STRIPE_PRICE_ID_PILOT);
    appendMetadata(params, metadata, "metadata");
    appendMetadata(params, metadata, "payment_intent_data[metadata]");
    params.append("success_url", pilotReturnUrl("/pilot", "pilot_success", metadata));
    params.append("cancel_url", pilotReturnUrl("/pilot", "pilot_cancelled", metadata));

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
      console.error("Stripe pilot checkout error:", JSON.stringify(session));
      return new Response(JSON.stringify({ error: "pilot checkout creation failed" }), {
        status: 502,
        headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify({ url: session.url }), {
      status: 200,
      headers: jsonHeaders,
    });
  } catch (err) {
    console.error("Pilot checkout error:", err);
    return new Response(JSON.stringify({ error: "internal error" }), {
      status: 500,
      headers: jsonHeaders,
    });
  }
}

export async function onRequestGet(context) {
  const corsHeaders = corsHeadersFor(context.request);
  return new Response(JSON.stringify({
    available: false,
    plan: "memory_bounded_prover_evaluation",
    mode: "contact",
    amount: 20000,
    currency: "USD",
    pricing_source: "protocol_upgrade",
    catalog_price_configured: false,
    fallback_url: "https://tinyzkp.com/contact?category=Memory-Bounded%20Prover%20Evaluation",
  }), {
    status: 200,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}

export async function onRequestOptions(context) {
  return new Response(null, {
    headers: corsHeadersFor(context.request),
  });
}
