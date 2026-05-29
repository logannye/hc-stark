// Cloudflare Pages Function — invalidates the server-side session and clears the cookie.
// Always responds 200 (idempotent); the cookie is cleared regardless of server outcome.

import { readSessionCookie, webhookSession, corsHeaders, CLEAR_COOKIE } from "./_session.js";

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin") || "";
  const cors = corsHeaders(origin);
  const jsonHeaders = { "Content-Type": "application/json", ...cors };

  try {
    const token = readSessionCookie(context.request);
    if (token) {
      // Best-effort server-side session deletion; ignore errors so the client
      // always gets the cleared cookie.
      await webhookSession(context.env, "/logout", token).catch(() => {});
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { ...jsonHeaders, "Set-Cookie": CLEAR_COOKIE },
    });
  } catch (err) {
    console.error("logout error:", err);
    // Still clear the cookie on error.
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { ...jsonHeaders, "Set-Cookie": CLEAR_COOKIE },
    });
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("Origin") || "";
  return new Response(null, { headers: corsHeaders(origin) });
}
