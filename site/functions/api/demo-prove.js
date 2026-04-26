// Cloudflare Pages Function — proxies a single canned `range_proof` to
// api.tinyzkp.com using a server-side demo API key. Heavily rate-limited
// by IP so this is safe to expose to anonymous /try traffic.
//
// Secret required (set via wrangler):
//   TINYZKP_DEMO_API_KEY  — a tzk_... key for a demo tenant with low caps.
//
// Request body: {min: number, max: number, witness_steps: number[]}
//   - min must be 0..1000
//   - max must be 0..1000 and >= min
//   - witness_steps must be 1..10 ints, each 0..1000
//
// Returns: {job_id, status, eta_ms} from upstream, or {error}.

const RATE_LIMIT_MAX = 5;          // 5 demo proofs per IP per window
const RATE_LIMIT_WINDOW_S = 3600;  // 1-hour window
const UPSTREAM = "https://api.tinyzkp.com/prove/template/range_proof";

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/demo-prove/${ip}`);
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

function validate(body) {
  const { min, max, witness_steps } = body || {};
  if (typeof min !== "number" || min < 0 || min > 1000 || !Number.isFinite(min)) {
    return "min must be a number in [0, 1000]";
  }
  if (typeof max !== "number" || max < 0 || max > 1000 || !Number.isFinite(max)) {
    return "max must be a number in [0, 1000]";
  }
  if (max < min) return "max must be >= min";
  if (!Array.isArray(witness_steps) || witness_steps.length < 1 || witness_steps.length > 10) {
    return "witness_steps must be an array of 1..10 ints";
  }
  for (const s of witness_steps) {
    if (typeof s !== "number" || !Number.isFinite(s) || s < 0 || s > 1000) {
      return "each witness step must be in [0, 1000]";
    }
  }
  return null;
}

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin") || "";
  const headers = { "Content-Type": "application/json", ...corsHeaders(origin) };
  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    if (!(await checkRateLimit(ip))) {
      return new Response(JSON.stringify({
        error: "Rate limit reached. Try again in an hour, or sign up for a free key for unlimited proofs.",
        signup: "https://tinyzkp.com/signup",
      }), { status: 429, headers });
    }
    const body = await context.request.json();
    const err = validate(body);
    if (err) return new Response(JSON.stringify({ error: err }), { status: 400, headers });

    const apiKey = context.env.TINYZKP_DEMO_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({ error: "demo unavailable (server misconfigured)" }), {
        status: 500, headers,
      });
    }

    const upstream = await fetch(UPSTREAM, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        params: {
          min: body.min,
          max: body.max,
          witness_steps: body.witness_steps,
        },
      }),
    });
    const json = await upstream.json();
    if (!upstream.ok) {
      console.error("demo-prove upstream error:", JSON.stringify(json));
      return new Response(JSON.stringify({ error: "upstream proving failed" }), {
        status: 502, headers,
      });
    }
    return new Response(JSON.stringify(json), { status: 200, headers });
  } catch (e) {
    console.error("demo-prove error:", e);
    return new Response(JSON.stringify({ error: "internal error" }), { status: 500, headers });
  }
}

export async function onRequestOptions(context) {
  return new Response(null, { headers: corsHeaders(context.request.headers.get("Origin") || "") });
}
