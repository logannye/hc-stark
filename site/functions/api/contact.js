// Cloudflare Pages Function — contact form intake.
//
// Forwards submissions to the billing-webhook service on Hetzner, which
// holds the SMTP creds and delivers to logan@galenhealth.org. Mirrors
// the send-magic-link.js pattern for consistency + single source of
// truth on outbound email infrastructure.

const RATE_LIMIT_MAX = 3;          // max contact submissions per window per IP
const RATE_LIMIT_WINDOW_S = 600;   // 10-minute window
const MAX_MESSAGE_LEN = 5000;

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
    const { name, email, category, message, _honeypot } = body;

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

    if (name.length > 200 || email.length > 254 || message.length > MAX_MESSAGE_LEN) {
      return new Response(
        JSON.stringify({ error: "input too long" }),
        { status: 400, headers: jsonHeaders }
      );
    }

    const validCategories = ["General Inquiry", "Bug Report", "Feature Request", "Billing", "Enterprise"];
    const safeCategory = validCategories.includes(category) ? category : "General Inquiry";

    const WEBHOOK_URL = context.env.WEBHOOK_BASE_URL || "https://webhook.tinyzkp.com";
    const resp = await fetch(`${WEBHOOK_URL}/send-contact`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": context.env.INTERNAL_SECRET || "",
      },
      body: JSON.stringify({ name, email, category: safeCategory, message }),
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
