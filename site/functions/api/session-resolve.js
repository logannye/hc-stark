// Cloudflare Pages Function — resolves the tz_session cookie to safe tenant metadata.
// Returns {email, plan, api_key_prefix, status}; does NOT forward stripe_customer_id
// (that is used server-side by create-portal-session only).

import { readSessionCookie, webhookSession, corsHeaders, CLEAR_COOKIE } from "./_session.js";

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin") || "";
  const cors = corsHeaders(origin);
  const jsonHeaders = { "Content-Type": "application/json", ...cors };

  try {
    const token = readSessionCookie(context.request);
    if (!token) {
      return new Response(JSON.stringify({ error: "no session" }), {
        status: 401, headers: jsonHeaders,
      });
    }

    const { ok, status, body } = await webhookSession(context.env, "/session/resolve", token);

    if (!ok) {
      // Clear the cookie — the session is invalid or expired.
      return new Response(JSON.stringify({ error: body.error || "invalid session" }), {
        status,
        headers: { ...jsonHeaders, "Set-Cookie": CLEAR_COOKIE },
      });
    }

    // Return only the fields safe for the browser; omit stripe_customer_id.
    const { email, plan, api_key_prefix, status: accountStatus } = body;
    return new Response(JSON.stringify({ email, plan, api_key_prefix, status: accountStatus }), {
      status: 200, headers: jsonHeaders,
    });
  } catch (err) {
    console.error("session-resolve error:", err);
    return new Response(JSON.stringify({ error: "Internal error." }), {
      status: 500, headers: jsonHeaders,
    });
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("Origin") || "";
  return new Response(null, { headers: corsHeaders(origin) });
}
