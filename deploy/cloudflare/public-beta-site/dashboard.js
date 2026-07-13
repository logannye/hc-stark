const API = "https://api.tinyzkp.com";
const $ = (id) => document.getElementById(id);
const operation = (prefix) => `${prefix}-${crypto.randomUUID()}`;

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, { credentials: "include", ...options, headers: { Accept: "application/json", ...(options.headers || {}) } });
  const body = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.error?.code || `HTTP ${response.status}`);
  return body;
}

function jsonRequest(body, prefix) {
  return { method: "POST", headers: { "Content-Type": "application/json", "Idempotency-Key": operation(prefix) }, body: JSON.stringify(body) };
}

function textElement(tag, text, className) {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}

function balanceCard(label, value) {
  const article = document.createElement("article"); article.className = "card";
  article.append(textElement("h3", label), textElement("p", (value / 1000).toFixed(3)));
  return article;
}

function checkoutButton(sku, label) {
  const button = textElement("button", label, "cta secondary"); button.type = "button";
  button.addEventListener("click", async () => {
    const result = await api("/v1/billing/checkout-sessions", jsonRequest({
      sku, success_url: "https://tinyzkp.com/dashboard?checkout=success",
      cancel_url: "https://tinyzkp.com/pricing?checkout=cancelled", synthetic_canary: false,
    }, "checkout"));
    location.assign(result.url);
  });
  return button;
}

function renderPlan(me) {
  const actions = $("checkout-actions"); actions.replaceChildren();
  const description = $("plan-description");
  const subscribed = ["builder", "pro", "scale_beta"].includes(me.plan);
  if (me.plan === "sandbox") {
    description.textContent = `Sandbox sample: ${me.sandbox_entitlement || "unavailable"}. One signed fixture job, one concurrency slot, maximum 2^16 rows.`;
    actions.append(checkoutButton("topup_25", "Start PAYG · $25"), checkoutButton("builder_monthly", "Builder · $49/month"));
  } else if (me.plan === "payg") {
    description.textContent = "PAYG · full supported AIR profile · one concurrent job · seven-day proof retention.";
    actions.append(checkoutButton("topup_25", "+$25"), checkoutButton("topup_100", "+$100"), checkoutButton("topup_500", "+$500"), checkoutButton("builder_monthly", "Add Builder subscription"));
  } else if (subscribed) {
    description.textContent = `${me.plan.replace("_", " ")} subscription active. Top-ups supplement monthly credits without changing the plan.`;
    actions.append(checkoutButton("topup_25", "+$25"), checkoutButton("topup_100", "+$100"), checkoutButton("topup_500", "+$500"));
  } else {
    description.textContent = "This account is not eligible for new paid work. Check Status or open the billing Portal.";
  }
  $("portal").hidden = me.plan === "sandbox";
}

function renderKeys(keys) {
  const list = $("key-list"); list.replaceChildren();
  if (!keys.api_keys.length) { list.append(textElement("p", "No API keys.")); return; }
  for (const key of keys.api_keys) {
    const row = document.createElement("p");
    row.append(textElement("code", `${String(key.prefix)}…`), document.createTextNode(` ${String(key.label)} `));
    if (key.revoked_at) row.append(document.createTextNode("(revoked)"));
    else {
      const button = textElement("button", "Revoke"); button.type = "button"; button.dataset.revoke = String(key.id); row.append(button);
    }
    list.append(row);
  }
}

function renderJobs(jobs) {
  const list = $("job-list"); list.replaceChildren();
  if (!jobs.jobs.length) { list.append(textElement("p", "No proof jobs.")); return; }
  for (const job of jobs.jobs) {
    const charge = job.settled_millicredits == null ? "pending" : `${(Number(job.settled_millicredits) / 1000).toFixed(3)} credits`;
    const row = document.createElement("p");
    row.append(textElement("code", String(job.job_id)), document.createTextNode(` · ${String(job.status)} · ${charge}`));
    list.append(row);
  }
}

async function refresh() {
  try {
    const [me, keys, jobs] = await Promise.all([api("/v1/me"), api("/v1/api-keys"), api("/v1/proof-jobs")]);
    $("session-status").textContent = `Signed in · ${me.plan} plan`;
    $("sign-in").hidden = true;
    for (const id of ["account", "keys", "jobs", "danger"]) $(id).hidden = false;
    $("balances").replaceChildren(balanceCard("Subscription credits", me.subscription_millicredits), balanceCard("Purchased credits", me.purchased_millicredits), balanceCard("Reserved", me.reserved_millicredits));
    renderPlan(me); renderKeys(keys); renderJobs(jobs);
  } catch (error) {
    $("session-status").textContent = `Not signed in (${String(error.message)}).`;
    $("sign-in").hidden = false;
  }
}

$("refresh").addEventListener("click", refresh);
$("key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/v1/api-keys", jsonRequest({ label: String(new FormData(event.target).get("label")) }, "api-key"));
  $("one-time-key").hidden = false;
  $("one-time-key").textContent = result.key
    ? `Copy this key now; it will not be shown again: ${String(result.key)}`
    : "This idempotent request was already completed; the API key secret cannot be shown again. Create a new key if it was not saved.";
  await refresh();
});
$("key-list").addEventListener("click", async (event) => {
  const id = event.target instanceof HTMLElement ? event.target.dataset.revoke : null;
  if (!id) return; await api(`/v1/api-keys/${encodeURIComponent(id)}`, { method: "DELETE", headers: { "Idempotency-Key": operation("revoke-key") } }); await refresh();
});
$("portal").addEventListener("click", async () => {
  const result = await api("/v1/billing/portal-sessions", jsonRequest({ return_url: "https://tinyzkp.com/dashboard" }, "portal")); location.assign(result.url);
});
$("delete-account").addEventListener("click", async () => {
  if (!confirm("Delete this account and queue retained artifacts for deletion? Required billing records remain pseudonymized.")) return;
  await api("/v1/account", { method: "DELETE", headers: { "Idempotency-Key": operation("delete-account") } }); location.assign("/status");
});
refresh();
