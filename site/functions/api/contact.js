// Cloudflare Pages Function — contact form intake.
//
// Forwards submissions to the billing-webhook service on Hetzner, which
// holds the SMTP creds and delivers to logan@galenhealth.org. Mirrors
// the send-magic-link.js pattern for consistency + single source of
// truth on outbound email infrastructure.

const RATE_LIMIT_MAX = 3;          // max contact submissions per window per IP
const RATE_LIMIT_WINDOW_S = 600;   // 10-minute window
const MAX_MESSAGE_LEN = 5000;
const MAX_QUAL_FIELD_LEN = 160;

const VALID_CATEGORIES = new Set([
  "General Inquiry",
  "Bug Report",
  "Feature Request",
  "Compute Inquiry",
  "Design Partner",
  "Fit Assessment",
  "Business Case",
  "Paid Pilot",
  "Platform Rollout",
  "Billing",
  "Enterprise",
]);

const QUALIFICATION_FIELDS = [
  "source",
  "platform",
  "plan",
  "workflow",
  "intent",
  "current_path",
  "referrer",
  "use_case",
  "trace_length",
  "proof_frequency",
  "verification_environment",
  "privacy_requirement",
  "latency_requirement",
  "current_alternative",
  "budget_owner",
];

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/contact/${ip}`);
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

function cleanString(value, maxLen) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLen);
}

function sanitizeQualification(raw) {
  const out = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
  for (const field of QUALIFICATION_FIELDS) {
    const clean = cleanString(raw[field], MAX_QUAL_FIELD_LEN);
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
    // Rate limit by IP.
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    const allowed = await checkRateLimit(ip);
    if (!allowed) {
      return new Response(JSON.stringify({ error: "too many requests, try again later" }), {
        status: 429,
        headers: jsonHeaders,
      });
    }

    const body = await context.request.json();
    const { qualification, context: leadContext, _honeypot } = body;
    const name = cleanString(body.name, 200);
    const email = cleanString(body.email, 254).toLowerCase();
    const category = cleanString(body.category, 80);
    const message = cleanString(body.message, MAX_MESSAGE_LEN);

    // Honeypot — if filled, silently succeed (bot).
    if (_honeypot) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: jsonHeaders,
      });
    }

    if (!name || !email || !message) {
      return new Response(
        JSON.stringify({ error: "name, email, and message are required" }),
        { status: 400, headers: jsonHeaders }
      );
    }

    if (
      (typeof body.name === "string" && body.name.length > 200) ||
      (typeof body.email === "string" && body.email.length > 254) ||
      (typeof body.message === "string" && body.message.length > MAX_MESSAGE_LEN)
    ) {
      return new Response(
        JSON.stringify({ error: "input too long" }),
        { status: 400, headers: jsonHeaders }
      );
    }

    const safeCategory = VALID_CATEGORIES.has(category) ? category : "General Inquiry";
    const safeQualification = sanitizeQualification({
      ...(leadContext && typeof leadContext === "object" && !Array.isArray(leadContext) ? leadContext : {}),
      ...(qualification && typeof qualification === "object" && !Array.isArray(qualification) ? qualification : {}),
    });

    const WEBHOOK_URL = context.env.WEBHOOK_BASE_URL || "https://webhook.tinyzkp.com";
    const resp = await fetch(`${WEBHOOK_URL}/send-contact`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": context.env.INTERNAL_SECRET || "",
      },
      body: JSON.stringify({
        name,
        email,
        category: safeCategory,
        message,
        qualification: safeQualification,
      }),
    });

    if (!resp.ok) {
      const errBody = await resp.json().catch(() => ({}));
      console.error("Contact webhook error:", resp.status, errBody);
      return new Response(JSON.stringify({ error: errBody.error || "Failed to send message. Please try again in a few minutes." }), {
        status: 502,
        headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: jsonHeaders,
    });
  } catch (err) {
    console.error("Contact form error:", err);
    return new Response(JSON.stringify({ error: "internal error" }), {
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
