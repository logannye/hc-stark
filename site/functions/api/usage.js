// Cloudflare Pages Function — passes through usage data for a session-authenticated user.
// Requires a valid tz_session cookie.

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

    const { ok, status, body } = await webhookSession(context.env, "/session/usage", token);

    if (!ok) {
      const headers = status === 401
        ? { ...jsonHeaders, "Set-Cookie": CLEAR_COOKIE }
        : jsonHeaders;
      return new Response(JSON.stringify({ error: body.error || "Usage unavailable." }), {
        status, headers,
      });
    }

    // Pass through the full usage JSON as-is.
    return new Response(JSON.stringify(body), {
      status: 200, headers: jsonHeaders,
    });
  } catch (err) {
    console.error("usage error:", err);
    return new Response(JSON.stringify({ error: "Internal error." }), {
      status: 500, headers: jsonHeaders,
    });
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("Origin") || "";
  return new Response(null, { headers: corsHeaders(origin) });
}
