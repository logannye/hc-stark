// Cloudflare Pages Function — contact form intake.
//
// Persists submissions in the owner-only evaluation ledger on Hetzner.
// No outbound email is sent by this recovery-period intake path.

const RATE_LIMIT_MAX = 3;          // max contact submissions per window per IP
const RATE_LIMIT_WINDOW_S = 600;   // 10-minute window
const MAX_MESSAGE_LEN = 5000;
const MAX_QUAL_FIELD_LEN = 160;

const NO_EMAIL_CONTACT_METHODS = new Set([
  "github",
  "linkedin",
  "signal",
  "discord",
  "telegram",
  "matrix",
  "phone",
]);

const VALID_CATEGORIES = new Set([
  "General Inquiry",
  "Bug Report",
  "Feature Request",
  "Design Partner",
  "Security Report",
  "Privacy Request",
  "Billing",
  "Enterprise",
]);

const QUALIFICATION_FIELDS = [
  "source",
  "platform",
  "intent",
  "referrer",
  "company",
  "repository",
  "stack",
  "workload",
  "logical_rows",
  "current_memory",
  "target_ram",
  "scratch",
  "verifier_target",
  "data_sensitivity",
  "technical_owner",
  "budget_owner",
  "timeline",
  "contact_method",
  "contact_handle",
  "consent",
];

const DESIGN_PARTNER_REQUIRED_FIELDS = [
  "company",
  "stack",
  "workload",
  "logical_rows",
  "current_memory",
  "target_ram",
  "scratch",
  "verifier_target",
  "data_sensitivity",
  "technical_owner",
  "budget_owner",
  "timeline",
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
  const originAllowed = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com";
  const allowedOrigin = originAllowed ? origin : "https://tinyzkp.com";
  const corsHeaders = {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

  try {
    if (!originAllowed) {
      return new Response(JSON.stringify({ error: "origin not allowed" }), {
        status: 403,
        headers: jsonHeaders,
      });
    }
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

    if (!name || !message) {
      return new Response(
        JSON.stringify({ error: "name and message are required" }),
        { status: 400, headers: jsonHeaders }
      );
    }

    if (email && !email.includes("@")) {
      return new Response(JSON.stringify({ error: "invalid email" }), {
        status: 400,
        headers: jsonHeaders,
      });
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
    const contactMethod = (safeQualification.contact_method || "").toLowerCase();
    if (safeCategory === "Design Partner") {
      const missing = DESIGN_PARTNER_REQUIRED_FIELDS.filter((field) => !safeQualification[field]);
      if (missing.length) {
        return new Response(JSON.stringify({ error: `missing evaluation fields: ${missing.join(", ")}` }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
    }
    if (
      !NO_EMAIL_CONTACT_METHODS.has(contactMethod) || !safeQualification.contact_handle
    ) {
      return new Response(
        JSON.stringify({ error: "a supported no-email contact method and handle are required" }),
        { status: 400, headers: jsonHeaders }
      );
    }
    if (safeQualification.consent !== "twelve_month_retention") {
      return new Response(JSON.stringify({ error: "retention acknowledgement is required" }), {
        status: 400,
        headers: jsonHeaders,
      });
    }

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
      return new Response(JSON.stringify({ error: errBody.error || "Failed to store application. Please try again in a few minutes." }), {
        status: 502,
        headers: jsonHeaders,
      });
    }

    const stored = await resp.json().catch(() => ({}));
    return new Response(JSON.stringify({
      ok: true,
      application_id: stored.application_id,
      benchmark_url: stored.benchmark_url,
      benchmark_command: stored.benchmark_command,
      next_action: stored.next_action,
    }), {
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
  const originAllowed = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com";
  if (!originAllowed) return new Response(null, { status: 403 });
  const allowedOrigin = origin;
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
