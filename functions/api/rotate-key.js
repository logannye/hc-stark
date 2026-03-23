// Cloudflare Pages Function — rotates a tenant's API key.
// Authenticates via the current Bearer token, forwards to billing webhook.

const RATE_LIMIT_MAX = 1;
const RATE_LIMIT_WINDOW_S = 86400; // 24 hours

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/rotate-key/${ip}`);
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
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
  const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    const allowed = await checkRateLimit(ip);
    if (!allowed) {
      return new Response(JSON.stringify({ error: "Key rotation limited to once per 24 hours." }), {
        status: 429,
        headers: jsonHeaders,
      });
    }

    // Extract Bearer token from Authorization header.
    const authHeader = context.request.headers.get("Authorization") || "";
    if (!authHeader.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "Authorization: Bearer <api_key> header required." }), {
        status: 401,
        headers: jsonHeaders,
      });
    }
    const currentKey = authHeader.slice(7).trim();

    if (!currentKey || !currentKey.startsWith("tzk_")) {
      return new Response(JSON.stringify({ error: "Invalid API key format." }), {
        status: 401,
        headers: jsonHeaders,
      });
    }

    // Forward to billing webhook backend.
    const WEBHOOK_URL = context.env.WEBHOOK_BASE_URL || "https://webhook.tinyzkp.com";
    const resp = await fetch(`${WEBHOOK_URL}/rotate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": context.env.INTERNAL_SECRET || "",
      },
      body: JSON.stringify({ current_key: currentKey }),
    });

    const body = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      return new Response(JSON.stringify({ error: body.error || "Key rotation failed." }), {
        status: resp.status,
        headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify(body), {
      status: 200,
      headers: jsonHeaders,
    });
  } catch (err) {
    console.error("Rotate key error:", err);
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
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}
