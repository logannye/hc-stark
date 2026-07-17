/** External backend-recovery canary. It runs off-host and pages only after one retry. */

const TARGETS = [
  { name: "api-health", url: "https://api.tinyzkp.com/healthz", expect: 200 },
  { name: "api-ready", url: "https://api.tinyzkp.com/readyz", expect: 200 },
  { name: "webhook-health", url: "https://webhook.tinyzkp.com/health", expect: 200 },
  {
    name: "api-capabilities",
    url: "https://api.tinyzkp.com/v1/capabilities",
    expect: 200,
    contains: '"proving_available":false',
  },
  {
    name: "published-recovery-status",
    url: "https://tinyzkp.com/discovery.json",
    expect: 200,
    jsonField: "service_status",
    jsonValue: "backend_recovery",
  },
  {
    name: "api-proving-contained",
    url: "https://api.tinyzkp.com/templates",
    expect: 503,
    contains: '"code":"protocol_upgrade"',
  },
  {
    name: "checkout-contained",
    url: "https://tinyzkp.com/api/create-checkout",
    method: "POST",
    body: "{}",
    expect: 503,
    contains: '"code":"protocol_upgrade"',
  },
  {
    name: "mcp-transport",
    url: "https://mcp.tinyzkp.com/mcp",
    method: "POST",
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "tinyzkp-uptime-probe", version: "1.0" } } }),
    expect: 200,
    contains: "protocolVersion",
  },
  {
    name: "site",
    url: "https://tinyzkp.com/",
    expect: 200,
  },
  {
    name: "site-status",
    url: "https://tinyzkp.com/status",
    expect: 200,
    contains: "Planned maintenance",
  },
  { name: "mcp-version", url: "https://mcp.tinyzkp.com/version", expect: 200, contains: '"service":"mcp"' },
  { name: "site-recovery-status", url: "https://tinyzkp.com/status", expect: 200, contains: "Backend recovery in progress" },
  { name: "site-security", url: "https://tinyzkp.com/security", expect: 200, contains: "release gates" },
  { name: "site-docs", url: "https://tinyzkp.com/docs", expect: 200, contains: "Maintenance API" },
];

const PUBLIC_BETA_TARGETS = [
  { name: "api-health", url: "https://api.tinyzkp.com/healthz", expect: 200 },
  { name: "api-ready", url: "https://api.tinyzkp.com/readyz", expect: 200 },
  { name: "webhook-health", url: "https://webhook.tinyzkp.com/health", expect: 200 },
  {
    name: "api-public-beta-status",
    url: "https://api.tinyzkp.com/v1/discovery",
    expect: 200,
    jsonField: "service_status",
    jsonValue: "public_beta",
  },
  {
    name: "site-public-beta-status",
    url: "https://tinyzkp.com/discovery.json",
    expect: 200,
    jsonField: "service_status",
    jsonValue: "public_beta",
  },
  { name: "site", url: "https://tinyzkp.com/", expect: 200, contains: "Paid public beta" },
  { name: "dashboard", url: "https://tinyzkp.com/dashboard", expect: 200, contains: "Sign in with GitHub" },
  { name: "pricing", url: "https://tinyzkp.com/pricing", expect: 200, contains: "no automatic overages" },
  {
    name: "legacy-template-route-contained",
    url: "https://api.tinyzkp.com/templates",
    expect: 503,
    contains: '"code":"protocol_upgrade"',
  },
  { name: "mcp-version", url: "https://mcp.tinyzkp.com/version", expect: 200, contains: '"service":"mcp"' },
];

function targetsForMode(mode) {
  if (!mode || mode === "containment") return TARGETS;
  if (mode === "public_beta") return PUBLIC_BETA_TARGETS;
  throw new Error(`invalid AUDIT_MODE: ${mode}`);
}

const TIMEOUT_MS = 10_000;
const RETRY_DELAY_MS = 5_000;
const CONTACT_READINESS_CRON = "17 * * * *";

async function probe(target) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(target.url, {
      method: target.method || "GET",
      body: target.body,
      signal: controller.signal,
      cf: { cacheTtl: 0 },
      headers: {
        "user-agent": "tinyzkp-uptime-probe",
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
      },
    });
    const statusOk = target.expect === null ? true : res.status === target.expect;
    if (!statusOk) return { name: target.name, ok: false, status: res.status };

    if (target.contains || target.jsonField) {
      const body = await res.text();
      if (target.jsonField) {
        let payload;
        try { payload = JSON.parse(body); } catch { return { name: target.name, ok: false, status: res.status, error: "invalid JSON" }; }
        const jsonOk = payload[target.jsonField] === target.jsonValue;
        return { name: target.name, ok: jsonOk, status: res.status, missing: jsonOk ? undefined : `${target.jsonField}=${target.jsonValue}` };
      }
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

async function probeWithRetry(target) {
  const first = await probe(target);
  if (first.ok) return first;
  await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
  return { ...(await probe(target)), retried: true };
}

async function alert(env, failures) {
  if (!env.ALERT_WEBHOOK_URL || !env.ALERT_WEBHOOK_TOKEN) {
    console.error("alert webhook configuration unset", JSON.stringify(failures));
    return;
  }
  const text = "🔴 TinyZKP recovery surface failed: " + failures
    .map((failure) => `${failure.name} (${failure.status})`)
    .join(", ");
  await fetch(env.ALERT_WEBHOOK_URL, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.ALERT_WEBHOOK_TOKEN}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ text, incident: "external_probe_failed" }),
  }).catch((error) => console.error("alert webhook failed", error));
}

async function runProbes(env) {
  let targets;
  try {
    targets = targetsForMode(env.AUDIT_MODE);
  } catch (error) {
    const failures = [{ name: "audit-mode", ok: false, status: 0, error: String(error) }];
    await alert(env, failures);
    return { ok: false, checked_at: new Date().toISOString(), mode: env.AUDIT_MODE, results: failures };
  }
  const results = await Promise.all(targets.map(probeWithRetry));
  const failures = results.filter((result) => !result.ok);
  if (failures.length) await alert(env, failures);
  return { ok: failures.length === 0, checked_at: new Date().toISOString(), mode: env.AUDIT_MODE || "containment", results };
}

async function runContactReadiness(env) {
  const secret = env.CONTACT_READINESS_SECRET;
  if (!secret) {
    const failures = [{
      name: "contact-readiness-config",
      ok: false,
      status: 0,
      error: "CONTACT_READINESS_SECRET is unset",
    }];
    await alert(env, failures);
    return { ok: false, checked_at: new Date().toISOString(), results: failures };
  }
  const nonce = `probe_${crypto.randomUUID().replaceAll("-", "")}`;
  const submitted = await fetch("https://tinyzkp.com/api/contact", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://tinyzkp.com",
      "user-agent": "tinyzkp-uptime-probe",
    },
    body: JSON.stringify({
      name: "TinyZKP readiness probe",
      category: "General Inquiry",
      message: `TinyZKP automated contact readiness probe ${nonce}`,
      qualification: {
        intent: "automated_readiness_probe",
        contact_method: "github",
        contact_handle: "https://tinyzkp.com/status",
        consent: "twelve_month_retention",
      },
      _honeypot: "",
    }),
  });
  const submission = await submitted.json().catch(() => ({}));
  const applicationId = submission.application_id;
  if (
    submitted.status !== 200
    || typeof applicationId !== "string"
    || !applicationId.startsWith("eval_")
  ) {
    const failures = [{
      name: "contact-readiness-submit",
      ok: false,
      status: submitted.status,
    }];
    await alert(env, failures);
    return { ok: false, checked_at: new Date().toISOString(), results: failures };
  }
  const reconciled = await fetch("https://webhook.tinyzkp.com/contact-readiness", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-internal-secret": secret,
      "user-agent": "tinyzkp-uptime-probe",
    },
    body: JSON.stringify({ application_id: applicationId, nonce }),
  });
  const cleanup = await reconciled.json().catch(() => ({}));
  const ok = (
    reconciled.status === 200
    && cleanup.stored === true
    && cleanup.cleaned === true
  );
  if (!ok) {
    await alert(env, [{
      name: "contact-readiness-cleanup",
      ok: false,
      status: reconciled.status,
    }]);
  }
  return {
    ok,
    checked_at: new Date().toISOString(),
    stored: ok,
    cleaned: ok,
    application_id: applicationId,
  };
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      event.cron === CONTACT_READINESS_CRON
        ? runContactReadiness(env)
        : runProbes(env),
    );
  },
  async fetch(_request, env) {
    const summary = await runProbes(env);
    return new Response(JSON.stringify(summary, null, 2), {
      status: summary.ok ? 200 : 503,
      headers: { "content-type": "application/json" },
    });
  },
};

export {
  TARGETS,
  PUBLIC_BETA_TARGETS,
  CONTACT_READINESS_CRON,
  targetsForMode,
  probe,
  alert,
  runContactReadiness,
};
