// Cloudflare Pages Function — privacy-bounded product analytics.
//
// Events are written to Worker logs only. The endpoint accepts a small
// allowlist of funnel events and a small allowlist of low-cardinality fields.
// Do not send proof bytes, API keys, emails, or arbitrary form contents here.

const RATE_LIMIT_MAX = 60;
const RATE_LIMIT_WINDOW_S = 60;
const MAX_BODY_BYTES = 2048;
const MAX_FIELD_CHARS = 160;

const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const API_SECRET_RE = /\b(?:tzk_[A-Za-z0-9._-]{8,}|sk_(?:live|test)_[A-Za-z0-9._-]+|pk_(?:live|test)_[A-Za-z0-9._-]+|whsec_[A-Za-z0-9._-]+)\b/g;
const LONG_HEX_RE = /\b(?:0x)?[a-f0-9]{64,}\b/gi;
const LONG_TOKEN_RE = /\b[A-Za-z0-9+/_=-]{120,}\b/g;

const ALLOWED_EVENTS = new Set([
  "page_view",
  "directory_referral",
  "docs_copy",
  "mcp_install_click",
  "playground_started",
  "playground_example_prefilled",
  "playground_prove_succeeded",
  "playground_prove_failed",
  "playground_verify_succeeded",
  "playground_verify_failed",
  "playground_share_copied",
  "playground_proof_copied",
  "playground_curl_copied",
  "verifier_opened",
  "verifier_cta_clicked",
  "signup_started",
  "signup_plan_selected",
  "signup_free_succeeded",
  "signup_free_failed",
  "checkout_started",
  "checkout_failed",
  "checkout_returned_success",
  "account_first_proof_panel_seen",
  "account_first_proof_reveal_click",
  "account_first_proof_curl_copied",
  "account_first_proof_curl_copy_blocked",
  "account_first_proof_quickstart_click",
  "first_api_proof_succeeded",
  "first_mcp_proof_succeeded",
  "first_verify_share_created",
  "quota_80_percent_reached",
  "upgrade_clicked",
  "paid_proof_succeeded",
  "client_verify_succeeded",
  "client_verify_failed",
  "client_verify_share_copied",
  "hosted_verify_succeeded",
  "fit_finder_start_click",
  "fit_finder_result",
  "fit_primary_click",
  "fit_secondary_click",
  "fit_contact_click",
  "trust_security_review_click",
  "agents_mcp_click",
  "openai_agents_signup_click",
  "paid_pilot_signup_click",
  "pilot_checkout_started",
  "pilot_checkout_failed",
  "pilot_contact_fallback_click",
  "platform_rollout_signup_click",
  "research_outbound_click",
  "compute_signup_click",
  "calculator_updated",
  "calculator_recommendation_click",
  "contact_submitted",
  "contact_failed",
]);

const ALLOWED_PROPS = new Set([
  "page",
  "path",
  "plan",
  "cadence",
  "category",
  "template",
  "elapsed_ms",
  "duration_ms",
  "status",
  "target",
  "source",
  "medium",
  "campaign",
  "platform",
  "use_case",
  "reason",
  "workflow",
  "intent",
  "landing_path",
  "referrer_host",
  "first_seen_at",
  "volume_bucket",
  "band",
  "external_visible",
  "recommendation",
  "route",
  "verifier",
  "fallback_from",
  "example",
  "index",
]);

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/events/${ip}`);
  const cached = await cache.match(key);

  let count = 0;
  if (cached) count = parseInt(await cached.text(), 10) || 0;
  if (count >= RATE_LIMIT_MAX) return false;

  await cache.put(key, new Response(String(count + 1), {
    headers: { "Cache-Control": `s-maxage=${RATE_LIMIT_WINDOW_S}` },
  }));
  return true;
}

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

function redactSensitiveText(value) {
  return String(value)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(EMAIL_RE, "[redacted-email]")
    .replace(API_SECRET_RE, "[redacted-secret]")
    .replace(LONG_HEX_RE, "[redacted-blob]")
    .replace(LONG_TOKEN_RE, "[redacted-blob]");
}

function sanitizeUrlish(value) {
  const text = redactSensitiveText(value).trim();
  if (!text) return "";

  try {
    const url = new URL(text, "https://tinyzkp.com");
    if (url.protocol !== "http:" && url.protocol !== "https:") return "";
    if (text.startsWith("/") && url.origin === "https://tinyzkp.com") {
      return url.pathname.slice(0, MAX_FIELD_CHARS);
    }
    return `${url.origin}${url.pathname}`.slice(0, MAX_FIELD_CHARS);
  } catch (_) {
    return text.split(/[?#]/, 1)[0].slice(0, MAX_FIELD_CHARS);
  }
}

function sanitizeStringField(key, value) {
  if (key === "path" || key === "target" || key === "landing_path") return sanitizeUrlish(value);
  return redactSensitiveText(value).slice(0, MAX_FIELD_CHARS);
}

function sanitizeProps(raw) {
  const clean = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return clean;
  for (const [key, value] of Object.entries(raw)) {
    if (!ALLOWED_PROPS.has(key)) continue;
    if (typeof value === "number" && Number.isFinite(value)) {
      clean[key] = Math.round(value);
    } else if (typeof value === "string") {
      clean[key] = sanitizeStringField(key, value);
    } else if (typeof value === "boolean") {
      clean[key] = value;
    }
  }
  return clean;
}

export async function onRequestPost(context) {
  const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
  if (!(await checkRateLimit(ip))) {
    // Analytics must never create user-visible console noise or block product
    // flows. When the privacy/rate budget is exhausted, drop the event
    // quietly instead of returning a browser-visible 429.
    return new Response(null, {
      status: 204,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const length = Number(context.request.headers.get("content-length") || 0);
  if (length > MAX_BODY_BYTES) {
    return json(413, { error: "event too large" });
  }

  let body;
  try {
    body = await context.request.json();
  } catch (_) {
    return json(400, { error: "invalid json" });
  }

  const event = typeof body.event === "string" ? body.event : "";
  if (!ALLOWED_EVENTS.has(event)) {
    return json(400, { error: "unknown event" });
  }

  const url = new URL(context.request.url);
  const record = {
    kind: "tinyzkp_product_event",
    event,
    props: sanitizeProps(body.props),
    path: typeof body.path === "string" ? sanitizeUrlish(body.path) : "",
    referrer_host: "",
    cf_ray: context.request.headers.get("cf-ray") || "",
    country: context.request.cf && context.request.cf.country ? context.request.cf.country : "",
    host: url.hostname,
    ts: new Date().toISOString(),
  };

  try {
    const ref = context.request.headers.get("referer") || "";
    if (ref) record.referrer_host = new URL(ref).hostname.slice(0, 160);
  } catch (_) {
    record.referrer_host = "";
  }

  console.log(JSON.stringify(record));
  return json(200, { ok: true });
}

export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "https://tinyzkp.com",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
