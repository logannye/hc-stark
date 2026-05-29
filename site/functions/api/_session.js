// Shared session helpers for Cloudflare Pages Functions.
// Exports: readSessionCookie, webhookSession, corsHeaders, SESSION_COOKIE, CLEAR_COOKIE.

/**
 * Parse the tz_session cookie from the Cookie header.
 * Returns the 64-hex-char token, or null if absent/malformed.
 */
export function readSessionCookie(request) {
  const c = request.headers.get("Cookie") || "";
  const m = c.match(/(?:^|;\s*)tz_session=([a-f0-9]{64})(?:;|$)/i);
  return m ? m[1] : null;
}

/**
 * POST {session_token} to the webhook at the given path.
 * Returns {ok, status, body}.
 */
export async function webhookSession(env, path, token) {
  const base = env.WEBHOOK_BASE_URL || "https://webhook.tinyzkp.com";
  const resp = await fetch(`${base}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Internal-Secret": env.INTERNAL_SECRET || "",
    },
    body: JSON.stringify({ session_token: token }),
  });
  const body = await resp.json().catch(() => ({}));
  return { ok: resp.ok, status: resp.status, body };
}

/**
 * Return CORS headers locked to the tinyzkp.com allowlist.
 * Mirrors the pattern in the existing functions.
 */
export function corsHeaders(origin) {
  const allowedOrigin =
    origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com"
      ? origin
      : "https://tinyzkp.com";
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

// Set-Cookie value that establishes a 24-hour httpOnly session.
// Replace % with the actual token before use.
export const SESSION_COOKIE =
  "tz_session=%; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400";

// Set-Cookie value that clears the session cookie.
export const CLEAR_COOKIE =
  "tz_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
