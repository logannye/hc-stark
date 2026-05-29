// Cloudflare Pages Function — rotates a tenant's API key.
// Auth path 1 (dashboard): tz_session cookie → {session_token} forwarded to webhook /rotate.
// Auth path 2 (direct API users): Authorization: Bearer tzk_... → {current_key} forwarded.
// CORS is locked to the tinyzkp.com allowlist.

import { readSessionCookie, corsHeaders } from "./_session.js";

const RATE_LIMIT_MAX = 1;
const RATE_LIMIT_WINDOW_S = 86400; // 24 hours

async function checkRateLimit(ip, identifier) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/rotate-key/${ip}/${identifier}`);
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
  const origin = context.request.headers.get("Origin") || "";
  const cors = corsHeaders(origin);
  const jsonHeaders = {
    "Content-Type": "application/json",
    ...cors,
    // Keep Authorization in the allowed CORS headers for direct API users.
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };

  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";

    // --- Session-cookie path (dashboard) ---
    const sessionToken = readSessionCookie(context.request);
    if (sessionToken) {
      const allowed = await checkRateLimit(ip, `session:${sessionToken.slice(0, 8)}`);
      if (!allowed) {
        return new Response(JSON.stringify({ error: "Key rotation limited to once per 24 hours." }), {
          status: 429, headers: jsonHeaders,
        });
      }

      const WEBHOOK_URL = context.env.WEBHOOK_BASE_URL || "https://webhook.tinyzkp.com";
      const resp = await fetch(`${WEBHOOK_URL}/rotate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Internal-Secret": context.env.INTERNAL_SECRET || "",
        },
        body: JSON.stringify({ session_token: sessionToken }),
      });

      const body = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        return new Response(JSON.stringify({ error: body.error || "Key rotation failed." }), {
          status: resp.status, headers: jsonHeaders,
        });
      }
      return new Response(JSON.stringify(body), { status: 200, headers: jsonHeaders });
    }

    // --- Bearer-token path (direct API users) ---
    const authHeader = context.request.headers.get("Authorization") || "";
    const keyPrefix = authHeader.startsWith("Bearer tzk_") ? authHeader.slice(7, 15) : "unknown";
    const allowed = await checkRateLimit(ip, keyPrefix);
    if (!allowed) {
      return new Response(JSON.stringify({ error: "Key rotation limited to once per 24 hours." }), {
        status: 429, headers: jsonHeaders,
      });
    }

    // Validate Bearer token format.
    if (!authHeader.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "Authorization: Bearer <api_key> header required." }), {
        status: 401, headers: jsonHeaders,
      });
    }
    const currentKey = authHeader.slice(7).trim();

    if (!currentKey || !currentKey.startsWith("tzk_")) {
      return new Response(JSON.stringify({ error: "Invalid API key format." }), {
        status: 401, headers: jsonHeaders,
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
        status: resp.status, headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify(body), { status: 200, headers: jsonHeaders });
  } catch (err) {
    console.error("Rotate key error:", err);
    return new Response(JSON.stringify({ error: "Internal error." }), {
      status: 500, headers: jsonHeaders,
    });
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("Origin") || "";
  const cors = corsHeaders(origin);
  return new Response(null, {
    headers: {
      ...cors,
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}
