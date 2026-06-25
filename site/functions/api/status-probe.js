// Cloudflare Pages Function — same-origin status probes for the public status page.
//
// The browser should not call api.tinyzkp.com directly because some service
// health endpoints intentionally do not expose broad CORS headers. Keep this
// endpoint allowlisted and response-only; it is not a generic fetch proxy.

const TARGETS = {
  api: {
    url: "https://api.tinyzkp.com/healthz",
  },
  mcp: {
    url: "https://mcp.tinyzkp.com/.well-known/mcp/server-card.json",
    marker: "tinyzkp",
  },
  site: {
    url: "https://tinyzkp.com/favicon.svg",
  },
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  const targetName = url.searchParams.get("target") || "";
  const target = TARGETS[targetName];

  if (!target) {
    return json({ ok: false, error: "unknown target" }, 400);
  }

  const started = Date.now();
  try {
    const response = await fetch(target.url, {
      method: "GET",
      headers: { "User-Agent": "TinyZKP status probe" },
    });
    const latency_ms = Date.now() - started;
    let marker_ok = true;

    if (response.ok && target.marker) {
      const text = await response.text();
      marker_ok = text.indexOf(target.marker) !== -1;
    }

    return json({
      ok: response.ok && marker_ok,
      target: targetName,
      status: response.status,
      latency_ms,
      marker_ok,
    });
  } catch (_) {
    return json({
      ok: false,
      target: targetName,
      status: 0,
      latency_ms: Date.now() - started,
      marker_ok: false,
    });
  }
}
