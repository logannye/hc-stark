// Cloudflare Pages Function — proxies a single canned `accumulator_step` proof
// to api.tinyzkp.com using a server-side demo API key. Heavily rate-limited by
// IP so this is safe to expose to anonymous /try traffic.
//
// Secret required (set via wrangler):
//   TINYZKP_DEMO_API_KEY  — a tzk_... key for a demo tenant with low caps.
//
// Request body: {initial: number, deltas: number[]} or
//   {params: {initial: number, deltas: number[], final?: number}}
//   - initial: 0..1000
//   - deltas: 1..10 ints, each 0..1000
//   final is computed server-side as initial + sum(deltas) so the proof always
//   builds (the template rejects a mismatched final).
//
// Returns: {job_id, status, eta_ms} from upstream, or {error}.

const RATE_LIMIT_MAX = 5;          // 5 demo proofs per IP per window
const RATE_LIMIT_WINDOW_S = 3600;  // 1-hour window
const UPSTREAM = "https://api.tinyzkp.com/prove/template/accumulator_step";

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

function normalize(body) {
  const input = body && typeof body.params === "object" ? body.params : body;
  if (!input || typeof input !== "object") return {};
  return { initial: input.initial, deltas: input.deltas };
}

function validate(input) {
  const { initial, deltas } = input || {};
  if (typeof initial !== "number" || !Number.isFinite(initial) || initial < 0 || initial > 1000) {
    return "initial must be a number in [0, 1000]";
  }
  if (!Array.isArray(deltas) || deltas.length < 1 || deltas.length > 10) {
    return "deltas must be an array of 1..10 ints";
  }
  for (const d of deltas) {
    if (typeof d !== "number" || !Number.isFinite(d) || d < 0 || d > 1000) {
      return "each delta must be in [0, 1000]";
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
        error: "Rate limit reached. Try again in an hour, or sign up for a free key for higher self-serve limits.",
        signup: "https://tinyzkp.com/signup",
        limits: "https://tinyzkp.com/limits",
      }), { status: 429, headers });
    }
    const body = await context.request.json();
    const input = normalize(body);
    const err = validate(input);
    if (err) return new Response(JSON.stringify({ error: err }), { status: 400, headers });

    const apiKey = context.env.TINYZKP_DEMO_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({
        error: "The anonymous playground is temporarily unavailable. You can still create a free API key and run the same proof from the quickstart.",
        signup: "https://tinyzkp.com/signup",
        docs: "https://tinyzkp.com/docs",
      }), {
        status: 500, headers,
      });
    }

    const finalVal = input.deltas.reduce((a, d) => a + d, input.initial);
    const upstream = await fetch(UPSTREAM, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        params: { initial: input.initial, final: finalVal, deltas: input.deltas },
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
