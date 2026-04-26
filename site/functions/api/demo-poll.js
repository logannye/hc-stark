// Cloudflare Pages Function — polls a demo proof job by ID using the
// server-side demo API key. Rate-limited by IP.
//
// The browser playground polls this every 700ms after submitting a demo
// proof until status is "completed" or "failed".
//
// Path: /api/demo-poll?id=prf_a1b2c3

const RATE_LIMIT_MAX = 60;        // 60 poll requests per IP per window
const RATE_LIMIT_WINDOW_S = 300;  // 5-minute window
const UPSTREAM_BASE = "https://api.tinyzkp.com/prove";

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/demo-poll/${ip}`);
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
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export async function onRequestGet(context) {
  const origin = context.request.headers.get("Origin") || "";
  const headers = { "Content-Type": "application/json", ...corsHeaders(origin) };
  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    if (!(await checkRateLimit(ip))) {
      return new Response(JSON.stringify({ error: "rate limited" }), {
        status: 429, headers,
      });
    }
    const url = new URL(context.request.url);
    const id = url.searchParams.get("id");
    if (!id || !/^prf_[A-Za-z0-9]+$/.test(id)) {
      return new Response(JSON.stringify({ error: "valid job_id required" }), {
        status: 400, headers,
      });
    }
    const apiKey = context.env.TINYZKP_DEMO_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({ error: "demo unavailable" }), {
        status: 500, headers,
      });
    }
    const upstream = await fetch(`${UPSTREAM_BASE}/${id}`, {
      headers: { "Authorization": `Bearer ${apiKey}` },
    });
    const json = await upstream.json();
    if (!upstream.ok) {
      return new Response(JSON.stringify({ error: "upstream poll failed" }), {
        status: 502, headers,
      });
    }
    return new Response(JSON.stringify(json), { status: 200, headers });
  } catch (e) {
    console.error("demo-poll error:", e);
    return new Response(JSON.stringify({ error: "internal error" }), { status: 500, headers });
  }
}

export async function onRequestOptions(context) {
  return new Response(null, { headers: corsHeaders(context.request.headers.get("Origin") || "") });
}
