// Cloudflare Pages Function — contact form email delivery.
//
// Sends submissions to logan@galenhealth.org via MailChannels API.
// DNS setup: add TXT record `_mailchannels.tinyzkp.com` with value
// `v=mc1 cfid=tinyzkp.pages.dev` to authorize sending.

const RECIPIENT = "logan@galenhealth.org";
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

    // Input length limits.
    if (name.length > 200 || email.length > 254 || message.length > MAX_MESSAGE_LEN) {
      return new Response(
        JSON.stringify({ error: "input too long" }),
        { status: 400, headers: jsonHeaders }
      );
    }

    const validCategories = ["General Inquiry", "Bug Report", "Feature Request", "Billing"];
    const safeCategory = validCategories.includes(category) ? category : "General Inquiry";

    const subject = `[TinyZKP ${safeCategory}] from ${name.slice(0, 100)}`;
    const text = [
      `Name: ${name}`,
      `Email: ${email}`,
      `Category: ${safeCategory}`,
      "",
      message,
    ].join("\n");

    const mailResp = await fetch("https://api.mailchannels.net/tx/v1/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        personalizations: [
          { to: [{ email: RECIPIENT, name: "TinyZKP Support" }] },
        ],
        from: { email: "noreply@tinyzkp.com", name: "TinyZKP Contact Form" },
        reply_to: { email: email.slice(0, 254), name: name.slice(0, 100) },
        subject,
        content: [{ type: "text/plain", value: text }],
      }),
    });

    if (!mailResp.ok) {
      const errText = await mailResp.text();
      console.error("MailChannels error:", errText);
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
