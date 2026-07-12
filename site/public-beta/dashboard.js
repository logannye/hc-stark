const API = "https://api.tinyzkp.com";
const $ = (id) => document.getElementById(id);
const operation = (prefix) => `${prefix}-${crypto.randomUUID()}`;

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, { credentials: "include", ...options, headers: { Accept: "application/json", ...(options.headers || {}) } });
  const body = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.error?.code || body?.code || `HTTP ${response.status}`);
  return body;
}

function jsonRequest(body, prefix) {
  return { method: "POST", headers: { "Content-Type": "application/json", "Idempotency-Key": operation(prefix) }, body: JSON.stringify(body) };
}

async function refresh() {
  try {
    const [me, keys, jobs] = await Promise.all([api("/v1/me"), api("/v1/api-keys"), api("/v1/proof-jobs")]);
    $("session-status").textContent = `Signed in · ${me.plan} plan`;
    $("sign-in").hidden = true;
    for (const id of ["account", "keys", "jobs", "danger"]) $(id).hidden = false;
    $("balances").innerHTML = [
      ["Subscription credits", me.subscription_millicredits], ["Purchased credits", me.purchased_millicredits], ["Reserved", me.reserved_millicredits],
    ].map(([label, value]) => `<article class="card"><h3>${label}</h3><p>${(value / 1000).toFixed(3)}</p></article>`).join("");
    $("key-list").innerHTML = keys.api_keys.map((key) => `<p><code>${key.prefix}…</code> ${key.label} ${key.revoked_at ? "(revoked)" : `<button data-revoke="${key.id}">Revoke</button>`}</p>`).join("") || "<p>No API keys.</p>";
    $("job-list").innerHTML = jobs.jobs.map((job) => `<p><code>${job.job_id}</code> · ${job.status} · ${job.settled_millicredits == null ? "pending" : `${(job.settled_millicredits / 1000).toFixed(3)} credits`}</p>`).join("") || "<p>No proof jobs.</p>";
  } catch (error) {
    $("session-status").textContent = `Not signed in (${error.message}).`;
    $("sign-in").hidden = false;
  }
}

$("refresh").addEventListener("click", refresh);
$("key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/v1/api-keys", jsonRequest({ label: new FormData(event.target).get("label") }, "api-key"));
  $("one-time-key").hidden = false;
  $("one-time-key").textContent = `Copy this key now; it will not be shown again: ${result.key}`;
  await refresh();
});
$("key-list").addEventListener("click", async (event) => {
  const id = event.target.dataset.revoke;
  if (!id) return;
  await api(`/v1/api-keys/${id}`, { method: "DELETE" });
  await refresh();
});
for (const [sku, label] of [["builder_monthly","Builder $49"],["pro_monthly","Pro $199"],["scale_beta_monthly","Scale $499"],["topup_25","+$25"],["topup_100","+$100"],["topup_500","+$500"]]) {
  const button = document.createElement("button");
  button.className = "cta secondary"; button.textContent = label;
  button.addEventListener("click", async () => {
    const result = await api("/v1/billing/checkout-sessions", jsonRequest({ sku, success_url: "https://tinyzkp.com/dashboard?checkout=success", cancel_url: "https://tinyzkp.com/pricing?checkout=cancelled", synthetic_canary: false }, "checkout"));
    location.assign(result.url);
  });
  $("checkout-actions").append(button);
}
$("portal").addEventListener("click", async () => {
  const result = await api("/v1/billing/portal-sessions", jsonRequest({ return_url: "https://tinyzkp.com/dashboard" }, "portal"));
  location.assign(result.url);
});
$("delete-account").addEventListener("click", async () => {
  if (!confirm("Delete this account and queue retained artifacts for deletion? Billing records required for reconciliation remain pseudonymized.")) return;
  await api("/v1/account", { method: "DELETE" });
  location.assign("/status");
});
refresh();
