/** External production canary. It runs off-host and pages only after one retry. */

const LEGACY_RECOVERY_TARGETS = [
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
    name: "api-proving-contained",
    url: "https://api.tinyzkp.com/templates",
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
  { name: "mcp-version", url: "https://mcp.tinyzkp.com/version", expect: 200, contains: '"service":"mcp"' },
];

const BACKEND_RECOVERY_TARGETS = [
  ...LEGACY_RECOVERY_TARGETS,
  {
    name: "published-recovery-status",
    url: "https://tinyzkp.com/discovery.json",
    expect: 200,
    jsonField: "service_status",
    jsonValue: "backend_recovery",
  },
  {
    name: "checkout-contained",
    url: "https://tinyzkp.com/api/create-checkout",
    method: "POST",
    body: "{}",
    expect: 503,
    contains: '"code":"protocol_upgrade"',
  },
  { name: "site", url: "https://tinyzkp.com/", expect: 200 },
  { name: "site-status", url: "https://tinyzkp.com/status", expect: 200, contains: "Planned maintenance" },
  { name: "site-recovery-status", url: "https://tinyzkp.com/status", expect: 200, contains: "Backend recovery in progress" },
  { name: "site-security", url: "https://tinyzkp.com/security", expect: 200, contains: "release gates" },
  { name: "site-docs", url: "https://tinyzkp.com/docs", expect: 200, contains: "Maintenance API" },
];

const GUARD_PRELAUNCH_TARGETS = [
  ...LEGACY_RECOVERY_TARGETS,
  {
    name: "published-guard-status",
    url: "https://tinyzkp.com/discovery.json",
    expect: 200,
    jsonField: "service_status",
    jsonValue: "guard_prelaunch",
  },
  {
    name: "checkout-contained",
    url: "https://tinyzkp.com/api/create-checkout",
    method: "POST",
    body: "{}",
    expect: 410,
    contains: "This surface has been retired.",
  },
  { name: "site", url: "https://tinyzkp.com/", expect: 200 },
  {
    name: "site-commerce-contained",
    url: "https://tinyzkp.com/commerce.json",
    expect: 200,
    jsonField: "checkout_enabled",
    jsonValue: false,
  },
  {
    name: "site-release-blocked",
    url: "https://tinyzkp.com/release.json",
    expect: 200,
    jsonField: "status",
    jsonValue: "blocked",
  },
  {
    name: "site-pricing-contained",
    url: "https://tinyzkp.com/pricing.json",
    expect: 200,
    jsonField: "checkout_enabled",
    jsonValue: false,
  },
  {
    name: "site-security",
    url: "https://tinyzkp.com/security",
    expect: 200,
    contains: "Proof data stays out of TinyZKP infrastructure.",
  },
  {
    name: "site-docs",
    url: "https://tinyzkp.com/docs",
    expect: 200,
    contains: "Evaluate compatibility before you buy.",
  },
];

// Compatibility alias for tooling that still imports the original recovery set.
const TARGETS = BACKEND_RECOVERY_TARGETS;

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
  if (!mode || mode === "guard_prelaunch") return GUARD_PRELAUNCH_TARGETS;
  if (mode === "containment") return BACKEND_RECOVERY_TARGETS;
  if (mode === "public_beta") return PUBLIC_BETA_TARGETS;
  throw new Error(`invalid AUDIT_MODE: ${mode}`);
}

const TIMEOUT_MS = 10_000;
const RETRY_DELAY_MS = 5_000;
const INCIDENT_KEY = "incident:external_probe_failed";
const DEFAULT_ALERT_REMINDER_SECONDS = 6 * 60 * 60;
const MIN_ALERT_REMINDER_SECONDS = 5 * 60;
const MAX_ALERT_REMINDER_SECONDS = 24 * 60 * 60;

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

function modeLabel(mode) {
  if (mode === "containment") return "backend recovery";
  if (mode === "public_beta") return "public beta";
  if (mode === "guard_prelaunch") return "Guard prelaunch";
  return mode || "production";
}

function failureFingerprint(failures) {
  return JSON.stringify(
    [...failures]
      .sort((left, right) => left.name.localeCompare(right.name))
      .map(({ name, status, missing, error }) => ({
        name,
        status,
        missing: missing || null,
        error: error || null,
      })),
  );
}

function alertReminderSeconds(env) {
  const configured = Number.parseInt(env.ALERT_REMINDER_SECONDS || "", 10);
  if (
    Number.isInteger(configured) &&
    configured >= MIN_ALERT_REMINDER_SECONDS &&
    configured <= MAX_ALERT_REMINDER_SECONDS
  ) {
    return configured;
  }
  return DEFAULT_ALERT_REMINDER_SECONDS;
}

async function postAlert(env, payload) {
  if (!env.ALERT_WEBHOOK_URL || !env.ALERT_WEBHOOK_TOKEN) {
    console.error("alert webhook configuration unset");
    return false;
  }
  try {
    const response = await fetch(env.ALERT_WEBHOOK_URL, {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.ALERT_WEBHOOK_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      console.error("alert webhook rejected delivery", response.status);
      return false;
    }
    return true;
  } catch (error) {
    console.error("alert webhook failed", error);
    return false;
  }
}

async function alert(env, failures, mode = "guard_prelaunch") {
  const text = `🔴 TinyZKP ${modeLabel(mode)} surface failed: ` + failures
    .map((failure) => `${failure.name} (${failure.status})`)
    .join(", ");
  return postAlert(env, { text, incident: "external_probe_failed" });
}

async function reconcileAlertState(env, failures, mode, now = Date.now()) {
  if (!env.ALERT_STATE) {
    if (failures.length) await alert(env, failures, mode);
    return;
  }

  let previous = null;
  try {
    previous = await env.ALERT_STATE.get(INCIDENT_KEY, "json");
  } catch (error) {
    console.error("cannot read alert incident state", error);
    if (failures.length) await alert(env, failures, mode);
    return;
  }

  if (!failures.length) {
    if (!previous) return;
    const delivered = await postAlert(env, {
      text: `🟢 TinyZKP ${modeLabel(mode)} surface recovered.`,
      incident: "external_probe_recovered",
    });
    if (delivered) await env.ALERT_STATE.delete(INCIDENT_KEY);
    return;
  }

  const fingerprint = failureFingerprint(failures);
  const reminderSeconds = alertReminderSeconds(env);
  const previousAt = Number(previous?.last_alert_at_ms);
  if (
    previous?.fingerprint === fingerprint &&
    Number.isFinite(previousAt) &&
    now - previousAt < reminderSeconds * 1000
  ) {
    return;
  }

  const delivered = await alert(env, failures, mode);
  if (!delivered) return;
  await env.ALERT_STATE.put(
    INCIDENT_KEY,
    JSON.stringify({ fingerprint, last_alert_at_ms: now }),
    { expirationTtl: Math.max(reminderSeconds * 4, 24 * 60 * 60) },
  );
}

async function runProbes(env) {
  let targets;
  try {
    targets = targetsForMode(env.AUDIT_MODE);
  } catch (error) {
    const failures = [{ name: "audit-mode", ok: false, status: 0, error: String(error) }];
    await reconcileAlertState(env, failures, env.AUDIT_MODE || "invalid");
    return { ok: false, checked_at: new Date().toISOString(), mode: env.AUDIT_MODE, results: failures };
  }
  const results = await Promise.all(targets.map(probeWithRetry));
  const failures = results.filter((result) => !result.ok);
  const mode = env.AUDIT_MODE || "guard_prelaunch";
  await reconcileAlertState(env, failures, mode);
  return { ok: failures.length === 0, checked_at: new Date().toISOString(), mode, results };
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

export {
  TARGETS,
  BACKEND_RECOVERY_TARGETS,
  GUARD_PRELAUNCH_TARGETS,
  PUBLIC_BETA_TARGETS,
  targetsForMode,
  probe,
  alert,
  failureFingerprint,
  reconcileAlertState,
};
