// Cloudflare Pages Function — verifies a demo proof against api.tinyzkp.com
// using the server-side demo API key. Rate-limited by IP.
//
// The playground calls this after the proof completes. Future: swap to
// browser-side WASM verification once @tinyzkp/verify ships to npm and we
// can host the wasm bundle locally.
//
// Request body: {proof: {version: number, bytes: string}}

const RATE_LIMIT_MAX = 30;        // 30 verify requests per IP per window
const RATE_LIMIT_WINDOW_S = 600;  // 10-minute window
const UPSTREAM = "https://api.tinyzkp.com/verify";

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/demo-verify/${ip}`);
  const cached = await cache.match(key);
  let count = 0;
  if (cached) count = parseInt(await cached.text(), 10) || 0;
  if (count >= RATE_LIMIT_MAX) return false;
  const resp = new Response(String(count + 1), {
    headers: { "Cache-Control": `s-maxage=${RATE_LIMIT_WINDOW_S}` },
  });
  await cache.put(key, resp);
  return true;
}

function corsHeaders(origin) {
  const allowed = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com"
    ? origin : "https://tinyzkp.com";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin") || "";
  const headers = { "Content-Type": "application/json", ...corsHeaders(origin) };
  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    if (!(await checkRateLimit(ip))) {
      return new Response(JSON.stringify({ error: "rate limited" }), {
        status: 429, headers,
      });
    }
    const body = await context.request.json();
    if (!body || !body.proof || typeof body.proof !== "object") {
      return new Response(JSON.stringify({ error: "proof object required" }), {
        status: 400, headers,
      });
    }
    const apiKey = context.env.TINYZKP_DEMO_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({ error: "demo unavailable" }), {
        status: 500, headers,
      });
    }
    const t0 = Date.now();
    const upstream = await fetch(UPSTREAM, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ proof: body.proof, allow_legacy_v2: false }),
    });
    const json = await upstream.json();
    const elapsed = Date.now() - t0;
    if (!upstream.ok) {
      return new Response(JSON.stringify({ error: "upstream verify failed" }), {
        status: 502, headers,
      });
    }
    return new Response(JSON.stringify({ ...json, round_trip_ms: elapsed }), {
      status: 200, headers,
    });
  } catch (e) {
    console.error("demo-verify error:", e);
    return new Response(JSON.stringify({ error: "internal error" }), { status: 500, headers });
  }
}

export async function onRequestOptions(context) {
  return new Response(null, { headers: corsHeaders(context.request.headers.get("Origin") || "") });
}
