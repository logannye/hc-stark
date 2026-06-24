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
  {
    name: "api-templates",
    url: "https://api.tinyzkp.com/templates",
    expect: 200,
    contains: '"lifecycle"',
  },
  {
    name: "mcp-server-card",
    url: "https://mcp.tinyzkp.com/.well-known/mcp/server-card.json",
    expect: 200,
    contains: "Live self-serve template: accumulator_step",
  },
  {
    name: "mcp-server-card-tools",
    url: "https://mcp.tinyzkp.com/.well-known/mcp/server-card.json",
    expect: 200,
    contains: "prove_template",
  },
  {
    name: "site-research",
    url: "https://tinyzkp.com/research",
    expect: 200,
    contains: "One company, one thesis: space-efficient proving.",
  },
  {
    name: "site-security",
    url: "https://tinyzkp.com/security",
    expect: 200,
    contains: "Responsible disclosure",
  },
  {
    name: "site-docs",
    url: "https://tinyzkp.com/docs",
    expect: 200,
    contains: "Template Lifecycle",
  },
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
    const statusOk = target.expect === null ? true : res.status === target.expect;
    if (!statusOk) return { name: target.name, ok: false, status: res.status };

    if (target.contains) {
      const body = await res.text();
      const containsOk = body.includes(target.contains);
      return {
        name: target.name,
        ok: containsOk,
        status: res.status,
        missing: containsOk ? undefined : target.contains,
      };
    }

    return { name: target.name, ok: true, status: res.status };
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
      .map((f) => `${f.name} (status=${f.status}${f.missing ? `, missing=${f.missing}` : ""}${f.error ? `, ${f.error}` : ""})`)
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
