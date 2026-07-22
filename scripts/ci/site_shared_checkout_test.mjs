import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const sharedSource = fs.readFileSync(new URL("../../site/shared.js", import.meta.url), "utf8");
const POLICY = "owner_only_ga_v1";
const BASIS = "owner_attested";
const TERMS = "2026-07-18";
const VERSION = "0.1.0";
const HOST = "lnholdings.lemonsqueezy.com";

function checkoutUrl(token) {
  return (
    `https://${HOST}/checkout/buy/${token}?` +
    `checkout%5Bcustom%5D%5Bterms_version%5D=${TERMS}&` +
    `checkout%5Bcustom%5D%5Bguard_version%5D=${VERSION}`
  );
}

function contracts() {
  return {
    commerce: {
      schema_version: 2,
      authorization_policy: POLICY,
      qualification_basis: BASIS,
      provider: "lemon_squeezy",
      launch_state: "qualified",
      sales_state: "live",
      commerce_state: "public_live",
      mode: "live",
      portal_state: "live",
      checkout_enabled: true,
      store_id: "101",
      product_id: "201",
      store_hostname: HOST,
      customer_portal_url: `https://${HOST}/billing`,
      checkout_custom_data: {
        terms_version: TERMS,
        guard_version: VERSION,
      },
      variants: {
        annual: {
          variant_id: "301",
          reviewed: true,
          checkout_url: checkoutUrl("annual-live"),
        },
        monthly: {
          variant_id: "302",
          reviewed: true,
          checkout_url: checkoutUrl("monthly-live"),
        },
      },
      reason_anchors: { sales: "/pricing#sales-status" },
    },
    release: {
      schema_version: 2,
      authorization_policy: POLICY,
      qualification_basis: BASIS,
      launch_state: "qualified",
      sales_state: "live",
      commerce_state: "public_live",
      portal_state: "live",
      checkout_enabled: true,
      guard_artifact_available: true,
      blocking_gates: [],
      release_identity: { guard_version: VERSION },
    },
  };
}

class Control {
  constructor(attributes) {
    this.attributes = new Map(Object.entries(attributes));
    this.textContent = "closed";
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  removeAttribute(name) {
    this.attributes.delete(name);
    if (name === "href") delete this.href;
  }
}

async function render(values, { failFetch = false } = {}) {
  const annual = new Control({
    "data-checkout": "annual",
    "data-closed-label": "Not yet for sale",
    "data-live-label": "Buy Guard",
  });
  const monthly = new Control({
    "data-checkout": "monthly",
    "data-closed-label": "Monthly not yet for sale",
    "data-live-label": "Buy Guard monthly",
  });
  const portal = new Control({
    "data-portal": "",
    "data-closed-label": "Billing portal unavailable",
    "data-live-label": "Manage billing",
  });
  const document = {
    readyState: "complete",
    documentElement: { classList: { add() {} } },
    querySelector() {
      return null;
    },
    querySelectorAll(selector) {
      if (selector === "[data-checkout]") return [annual, monthly];
      if (selector === "[data-portal]") return [portal];
      return [];
    },
    addEventListener() {},
  };
  const context = vm.createContext({
    Array,
    Promise,
    URL,
    console,
    document,
    window: {
      location: { origin: "https://tinyzkp.com", pathname: "/pricing" },
    },
    fetch: async (path) => {
      if (failFetch) throw new Error("offline");
      return {
        ok: true,
        async json() {
          return path === "/commerce.json" ? values.commerce : values.release;
        },
      };
    },
  });
  vm.runInContext(sharedSource, context, { filename: "site/shared.js" });
  await new Promise((resolve) => setImmediate(resolve));
  return { annual, monthly, portal };
}

function assertClosed(control) {
  assert.equal(control.href, undefined);
  assert.equal(control.getAttribute("aria-disabled"), "true");
  assert.equal(control.getAttribute("tabindex"), "-1");
}

{
  const values = contracts();
  const rendered = await render(values);
  assert.equal(rendered.annual.href, checkoutUrl("annual-live"));
  assert.equal(rendered.monthly.href, checkoutUrl("monthly-live"));
  assert.equal(rendered.portal.href, `https://${HOST}/billing`);
  assert.equal(rendered.portal.textContent, "Manage billing");
}

for (const mutate of [
  (value) => { value.commerce.authorization_policy = "outside_review_v1"; },
  (value) => { value.commerce.variants.annual.checkout_url = `https://${HOST}/cart`; },
  (value) => { value.commerce.variants.annual.checkout_url = value.commerce.variants.monthly.checkout_url; },
  (value) => { value.commerce.variants.annual.checkout_url = checkoutUrl("annual-live").replace(VERSION, "9.9.9"); },
  (value) => { value.commerce.variants.annual.checkout_url += "#"; },
  (value) => { value.commerce.customer_portal_url += "?signed=customer-token"; },
  (value) => { value.commerce.customer_portal_url = "https://app.lemonsqueezy.com/my-orders/customer"; },
  (value) => { value.commerce.store_hostname = "other-store.lemonsqueezy.com"; },
]) {
  const values = contracts();
  mutate(values);
  const rendered = await render(values);
  assertClosed(rendered.annual);
  assertClosed(rendered.monthly);
}

for (const portalUrl of [
  `https://${HOST}/billing?`,
  `https://${HOST}/billing#`,
  `https://${HOST}/billing/`,
  `https://${HOST}/billing?signed=customer-token`,
]) {
  const values = contracts();
  values.commerce.customer_portal_url = portalUrl;
  const rendered = await render(values);
  assertClosed(rendered.annual);
  assertClosed(rendered.monthly);
  assertClosed(rendered.portal);
}

{
  const values = contracts();
  values.commerce.launch_state = "blocked";
  values.commerce.sales_state = "closed";
  values.commerce.commerce_state = "live_hidden";
  values.commerce.checkout_enabled = false;
  values.release.launch_state = "blocked";
  values.release.sales_state = "closed";
  values.release.commerce_state = "live_hidden";
  values.release.checkout_enabled = false;
  values.release.guard_artifact_available = false;
  values.release.blocking_gates = ["guard_artifact_published"];
  const rendered = await render(values);
  assertClosed(rendered.annual);
  assert.equal(rendered.portal.href, `https://${HOST}/billing`);
}

{
  const rendered = await render(contracts(), { failFetch: true });
  assertClosed(rendered.annual);
  assertClosed(rendered.monthly);
  assertClosed(rendered.portal);
}

console.log("PASS site/shared.js checkout and portal fail-closed tests");
