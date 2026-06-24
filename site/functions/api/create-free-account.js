// Cloudflare Pages Function — creates a free-tier account.
// Sends a request to the billing webhook to provision a tenant without Stripe.

const RATE_LIMIT_MAX = 3;
const RATE_LIMIT_WINDOW_S = 600;
const ATTRIBUTION_MAX_LEN = 80;
const ATTRIBUTION_FIELDS = ["source", "platform", "use_case", "workflow", "intent"];

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/free-signup/${ip}`);
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

function cleanAttribution(value) {
  if (typeof value !== "string") return "";
  return value
    .trim()
    .replace(/[^\w .:/-]/g, "")
    .slice(0, ATTRIBUTION_MAX_LEN);
}

function collectAttribution(body) {
  const out = {};
  for (const field of ATTRIBUTION_FIELDS) {
    const clean = cleanAttribution(body[field]);
    if (clean) out[field] = clean;
  }
  return out;
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
    const allowed = await checkRateLimit(ip);
    if (!allowed) {
      return new Response(JSON.stringify({ error: "Too many signups. Try again later." }), {
        status: 429,
        headers: jsonHeaders,
      });
    }

    const body = await context.request.json();
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    if (!email || !email.includes("@") || email.length > 254) {
      return new Response(JSON.stringify({ error: "Valid email required." }), {
        status: 400,
        headers: jsonHeaders,
      });
    }
    const attribution = collectAttribution(body);

    // Provision free tenant via the billing webhook on the backend server.
    const WEBHOOK_URL = context.env.WEBHOOK_BASE_URL || "https://webhook.tinyzkp.com";
    const resp = await fetch(`${WEBHOOK_URL}/provision-free`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": context.env.INTERNAL_SECRET || "",
      },
      body: JSON.stringify({ email, plan: "free", ...attribution }),
    });

    if (!resp.ok) {
      // Read the raw upstream body once so NON-JSON failures stay diagnosable
      // (e.g. a Cloudflare/Caddy "error code: 502" edge page from the webhook
      // origin, which JSON.parse would silently flatten to a generic message).
      const raw = await resp.text().catch(() => "");
      let upstreamError = "";
      try { upstreamError = (JSON.parse(raw) || {}).error || ""; } catch { /* non-JSON body */ }
      console.error(`Provision failed: upstream_status=${resp.status} body=${raw.slice(0, 300)}`);
      return new Response(
        JSON.stringify({
          error: upstreamError || "Account creation failed.",
          upstream_status: resp.status,
        }),
        { status: 502, headers: jsonHeaders },
      );
    }

    const result = await resp.json().catch(() => ({ ok: true }));
    return new Response(JSON.stringify({ ok: true, dashboard_token: result.dashboard_token || null }), {
      status: 200,
      headers: jsonHeaders,
    });
  } catch (err) {
    console.error("Free signup error:", err);
    return new Response(JSON.stringify({ error: "Internal error." }), {
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
