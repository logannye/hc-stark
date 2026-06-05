/**
 * TinyZKP external uptime probe (audit OPS-2 / OPS-3).
 *
 * Runs on Cloudflare's edge — OFF the Hetzner box AND off Logan's laptop — so it
 * keeps watching even when the box (and the on-box Prometheus/Alertmanager, which
 * die with the host) is down. This closes the structural blind spot where the
 * only liveness check was a daily audit on a personal Mac.
 *
 * Each cron tick it probes the public health surfaces; on a CONFIRMED failure
 * (one retry, to filter transient edge blips) it posts to ALERT_WEBHOOK_URL
 * (Slack / Discord / any JSON webhook). Email is intentionally avoided — the
 * MailChannels path broke previously (see PR #9).
 *
 * Deploy:  cd deploy/uptime-probe && npx wrangler secret put ALERT_WEBHOOK_URL && npx wrangler deploy
 * Test:    GET the deployed worker URL — it runs the probe on demand and returns
 *          JSON (200 if all up, 503 if any target is down).
 */

const TARGETS = [
  { name: "api", url: "https://api.tinyzkp.com/healthz", expect: 200 },
  // The MCP host returns 404 at "/" (tools live under /mcp); ANY HTTP response
  // means the host is reachable, so only a network error/timeout counts as down.
  { name: "mcp", url: "https://mcp.tinyzkp.com/", expect: null },
];

const TIMEOUT_MS = 10_000;
const RETRY_DELAY_MS = 5_000;

async function probe(target) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(target.url, {
      method: "GET",
      signal: controller.signal,
      cf: { cacheTtl: 0 },
      headers: { "user-agent": "tinyzkp-uptime-probe" },
    });
    const ok = target.expect === null ? true : res.status === target.expect;
    return { name: target.name, ok, status: res.status };
  } catch (err) {
    return { name: target.name, ok: false, status: 0, error: String(err) };
  } finally {
    clearTimeout(timer);
  }
}

// One retry after a short delay so a single transient blip never pages.
async function probeWithRetry(target) {
  const first = await probe(target);
  if (first.ok) return first;
  await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
  return { ...(await probe(target)), retried: true };
}

async function alert(env, failures) {
  if (!env.ALERT_WEBHOOK_URL) {
    console.error(
      "ALERT_WEBHOOK_URL unset — cannot page. Failures:",
      JSON.stringify(failures),
    );
    return;
  }
  const text =
    "\u{1F534} TinyZKP DOWN — " +
    failures
      .map((f) => `${f.name} (status=${f.status}${f.error ? `, ${f.error}` : ""})`)
      .join(", ");
  // {text} suits Slack; {content} suits Discord; {failures} is the structured form.
  await fetch(env.ALERT_WEBHOOK_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text, content: text, failures }),
  }).catch((e) => console.error("alert webhook POST failed:", e));
}

async function runProbes(env) {
  const results = await Promise.all(TARGETS.map(probeWithRetry));
  const failures = results.filter((r) => !r.ok);
  if (failures.length) await alert(env, failures);
  return { ok: failures.length === 0, checked_at: new Date().toISOString(), results };
}

export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(runProbes(env));
  },
  async fetch(_req, env) {
    const summary = await runProbes(env);
    return new Response(JSON.stringify(summary, null, 2), {
      status: summary.ok ? 200 : 503,
      headers: { "content-type": "application/json" },
    });
  },
};
