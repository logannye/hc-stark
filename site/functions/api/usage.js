// Cloudflare Pages Function — passes through usage data for a session-authenticated user.
// Requires a valid tz_session cookie.

import { readSessionCookie, corsHeaders, CLEAR_COOKIE } from "./_session.js";

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

    // Read optional since/until from the request body.
    let since, until;
    try {
      const reqBody = await context.request.json().catch(() => ({}));
      since = reqBody.since;
      until = reqBody.until;
    } catch (_) {
      // body absent or not JSON — fine, proceed without range params
    }

    const payload = { session_token: token };
    if (since != null) payload.since = since;
    if (until != null) payload.until = until;

    const base = context.env.WEBHOOK_BASE_URL || "https://webhook.tinyzkp.com";
    const resp = await fetch(`${base}/session/usage`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": context.env.INTERNAL_SECRET || "",
      },
      body: JSON.stringify(payload),
    });
    const body = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      const headers = resp.status === 401
        ? { ...jsonHeaders, "Set-Cookie": CLEAR_COOKIE }
        : jsonHeaders;
      return new Response(JSON.stringify({ error: body.error || "Usage unavailable." }), {
        status: resp.status, headers,
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
