/** External backend-recovery canary. It runs off-host and pages only after one retry. */

const TARGETS = [
  { name: "api-health", url: "https://api.tinyzkp.com/healthz", expect: 200 },
  {
    name: "api-capabilities",
    url: "https://api.tinyzkp.com/v1/capabilities",
    expect: 200,
    contains: '"proving_available":false',
  },
  { name: "mcp-version", url: "https://mcp.tinyzkp.com/version", expect: 200, contains: '"service":"mcp"' },
  { name: "site-status", url: "https://tinyzkp.com/status", expect: 200, contains: "Backend recovery in progress" },
  { name: "site-security", url: "https://tinyzkp.com/security", expect: 200, contains: "release gates" },
  { name: "site-docs", url: "https://tinyzkp.com/docs", expect: 200, contains: "Maintenance API" },
];

const TIMEOUT_MS = 10_000;
const RETRY_DELAY_MS = 5_000;

async function probe(target) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(target.url, {
      method: "GET",
      signal: controller.signal,
      cf: { cacheTtl: 0 },
      headers: { "user-agent": "tinyzkp-recovery-uptime-probe" },
    });
    if (response.status !== target.expect) return { name: target.name, ok: false, status: response.status };
    if (!target.contains) return { name: target.name, ok: true, status: response.status };
    const body = await response.text();
    const ok = body.includes(target.contains);
    return { name: target.name, ok, status: response.status, missing: ok ? undefined : target.contains };
  } catch (error) {
    return { name: target.name, ok: false, status: 0, error: String(error) };
  } finally {
    clearTimeout(timer);
  }
}

async function probeWithRetry(target) {
  const first = await probe(target);
  if (first.ok) return first;
  await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
  return { ...(await probe(target)), retried: true };
}

async function alert(env, failures) {
  if (!env.ALERT_WEBHOOK_URL) {
    console.error("ALERT_WEBHOOK_URL unset", JSON.stringify(failures));
    return;
  }
  const text = "🔴 TinyZKP recovery surface failed: " + failures
    .map((failure) => `${failure.name} (${failure.status})`)
    .join(", ");
  await fetch(env.ALERT_WEBHOOK_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text, content: text, failures }),
  }).catch((error) => console.error("alert webhook failed", error));
}

async function runProbes(env) {
  const results = await Promise.all(TARGETS.map(probeWithRetry));
  const failures = results.filter((result) => !result.ok);
  if (failures.length) await alert(env, failures);
  return { ok: failures.length === 0, checked_at: new Date().toISOString(), results };
}

export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(runProbes(env));
  },
  async fetch(_request, env) {
    const summary = await runProbes(env);
    return new Response(JSON.stringify(summary, null, 2), {
      status: summary.ok ? 200 : 503,
      headers: { "content-type": "application/json" },
    });
  },
};
