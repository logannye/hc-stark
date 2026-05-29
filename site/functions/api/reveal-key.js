// Cloudflare Pages Function — reveals the raw API key to a session-authenticated user.
// Rate-limited; requires a valid tz_session cookie.

import { readSessionCookie, webhookSession, corsHeaders, CLEAR_COOKIE } from "./_session.js";

const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_S = 300;

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/reveal-key/${ip}`);
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
      return new Response(JSON.stringify({ error: "Too many attempts. Try again later." }), {
        status: 429, headers: jsonHeaders,
      });
    }

    const token = readSessionCookie(context.request);
    if (!token) {
      return new Response(JSON.stringify({ error: "no session" }), {
        status: 401, headers: jsonHeaders,
      });
    }

    const { ok, status, body } = await webhookSession(context.env, "/session/reveal-key", token);

    if (!ok) {
      const headers = status === 401
        ? { ...jsonHeaders, "Set-Cookie": CLEAR_COOKIE }
        : jsonHeaders;
      return new Response(JSON.stringify({ error: body.error || "Key unavailable." }), {
        status, headers,
      });
    }

    return new Response(JSON.stringify({ api_key: body.api_key }), {
      status: 200, headers: jsonHeaders,
    });
  } catch (err) {
    console.error("reveal-key error:", err);
    return new Response(JSON.stringify({ error: "Internal error." }), {
      status: 500, headers: jsonHeaders,
    });
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("Origin") || "";
  return new Response(null, { headers: corsHeaders(origin) });
}
