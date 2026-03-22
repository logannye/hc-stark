// Cloudflare Pages Function — creates a free-tier account.
// Sends a request to the billing webhook to provision a tenant without Stripe.

const RATE_LIMIT_MAX = 3;
const RATE_LIMIT_WINDOW_S = 600;

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

export async function onRequestPost(context) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
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

    const { email } = await context.request.json();
    if (!email || !email.includes("@") || email.length > 254) {
      return new Response(JSON.stringify({ error: "Valid email required." }), {
        status: 400,
        headers: jsonHeaders,
      });
    }

    // Provision free tenant via the billing webhook on the backend server.
    const WEBHOOK_URL = context.env.WEBHOOK_BASE_URL || "https://webhook.tinyzkp.com";
    const resp = await fetch(`${WEBHOOK_URL}/provision-free`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": context.env.INTERNAL_SECRET || "",
      },
      body: JSON.stringify({ email, plan: "free" }),
    });

    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      console.error("Provision error:", JSON.stringify(body));
      return new Response(JSON.stringify({ error: body.error || "Account creation failed." }), {
        status: 502,
        headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify({ ok: true }), {
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

export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
