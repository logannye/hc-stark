import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  BACKEND_RECOVERY_TARGETS,
  GUARD_PRELAUNCH_TARGETS,
  GUARD_TRANSITION_TARGETS,
  GUARD_LIVE_TARGETS,
  GUARD_FROZEN_TARGETS,
  PUBLIC_BETA_TARGETS,
  targetsForMode,
  loadCanonicalMode,
  probe,
  alert,
  failureFingerprint,
  reconcileAlertState,
  validateContract,
  liveMerchantTargets,
  frozenPortalTargets,
  liveReleaseTargets,
  probeOci,
} from "./worker.js";

const originalFetch = globalThis.fetch;

const terms = "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-21";
const guard = "checkout%5Bcustom%5D%5Bguard_version%5D=0.1.0";

function contractPayload(contract) {
  const owner = {
    schema_version: 2,
    authorization_policy: "owner_only_ga_v1",
    qualification_basis: "owner_attested",
  };
  if (contract === "guard_transition_commerce") return {
    ...owner,
    checkout_enabled: false,
    launch_state: "blocked",
    sales_state: "closed",
    commerce_state: "live_hidden",
  };
  if (contract === "guard_transition_release") return {
    ...owner,
    checkout_enabled: false,
    launch_state: "blocked",
    sales_state: "closed",
    blocking_gates: ["guard_artifact_published"],
  };
  if (contract === "guard_live_commerce") return {
    ...owner,
    checkout_enabled: true,
    launch_state: "qualified",
    sales_state: "live",
    commerce_state: "public_live",
    mode: "live",
    portal_state: "live",
    customer_portal_url: "https://lnholdings.lemonsqueezy.com/billing",
    store_hostname: "lnholdings.lemonsqueezy.com",
    support: {
      state: "verified",
      intake: "private_email",
      contact: "support@tinyzkp.com",
      delivery_verified: true,
      owner_access_verified: true,
      retention_configured: true,
    },
    checkout_custom_data: { terms_version: "2026-07-21", guard_version: "0.1.0" },
    price_policy: { monthly_usd: 499, annual_usd: 4990, annual_default: true },
    variants: {
      monthly: { reviewed: true, variant_id: "101", checkout_url: `https://lnholdings.lemonsqueezy.com/checkout/buy/monthly01?${terms}&${guard}` },
      annual: { reviewed: true, variant_id: "102", checkout_url: `https://lnholdings.lemonsqueezy.com/checkout/buy/annual001?${terms}&${guard}` },
    },
  };
  if (contract === "guard_live_release") return {
    ...owner,
    checkout_enabled: true,
    launch_state: "qualified",
    sales_state: "live",
    commerce_state: "public_live",
    guard_artifact_available: true,
    release_identity: { guard_version: "0.1.0" },
    guard_artifact_url: "https://github.com/logannye/hc-stark/releases/download/guard-v0.1.0/tinyzkp-guard.tar.gz",
    guard_artifact_sha256: "a".repeat(64),
    guard_oci_digest: `sha256:${"b".repeat(64)}`,
    channel_manifest: {
      url: "https://github.com/logannye/hc-stark/releases/download/guard-v0.1.0/guard-channel-v1.json",
      sha256: "c".repeat(64),
      release_identity: { guard_version: "0.1.0" },
    },
    latest_release_index: {
      url: "https://tinyzkp.com/guard-release-index-v1.json",
      signature_url: "https://tinyzkp.com/guard-release-index-v1.json.sig",
      sha256: "d".repeat(64),
      signature_sha256: "e".repeat(64),
    },
    blocking_gates: [],
  };
  if (contract === "guard_live_discovery") return {
    launch_state: "qualified",
    sales_state: "live",
    service_status: "guard_live",
    availability: { guard_checkout: true, guard_artifact: true },
  };
  if (contract === "guard_frozen_commerce") return {
    ...contractPayload("guard_live_commerce"),
    checkout_enabled: false,
    sales_state: "frozen",
    commerce_state: "sales_frozen",
    variants: {
      monthly: { reviewed: false, variant_id: "101", checkout_url: null },
      annual: { reviewed: false, variant_id: "102", checkout_url: null },
    },
  };
  if (contract === "guard_frozen_release") return {
    ...contractPayload("guard_live_release"),
    checkout_enabled: false,
    sales_state: "frozen",
    commerce_state: "sales_frozen",
  };
  if (contract === "guard_frozen_discovery") return {
    launch_state: "qualified",
    sales_state: "frozen",
    service_status: "guard_frozen",
    availability: { guard_checkout: false, guard_artifact: true },
  };
  throw new Error(`unknown contract fixture: ${contract}`);
}

function responseFor(target, override = {}) {
  const body = override.body ?? (target.contract ? JSON.stringify(contractPayload(target.contract)) : target.jsonField ? JSON.stringify({ [target.jsonField]: target.jsonValue }) : target.contains) ?? "ok";
  const status = override.status ?? target.expect;
  const headers = new Headers(override.headers || {});
  if (target.headerName && !override.omitExpectedHeader) {
    headers.set(target.headerName, target.headerContains);
  }
  return new Response(body, { status, headers });
}

class FakeKv {
  constructor() {
    this.values = new Map();
  }

  async get(key, type) {
    const value = this.values.get(key);
    if (value === undefined) return null;
    return type === "json" ? JSON.parse(value) : value;
  }

  async put(key, value) {
    this.values.set(key, value);
  }

  async delete(key) {
    this.values.delete(key);
  }
}

try {
  for (const targets of [
    BACKEND_RECOVERY_TARGETS,
    GUARD_PRELAUNCH_TARGETS,
    GUARD_TRANSITION_TARGETS,
    GUARD_LIVE_TARGETS,
    GUARD_FROZEN_TARGETS,
    PUBLIC_BETA_TARGETS,
  ]) {
    for (const target of targets) {
      globalThis.fetch = async (_url, options) => {
        assert.equal(options.method, target.method || "GET");
        return responseFor(target);
      };
      const result = await probe(target);
      assert.equal(result.ok, true, target.name);
    }
  }
  assert.equal(targetsForMode(), GUARD_PRELAUNCH_TARGETS);
  assert.equal(targetsForMode("guard_prelaunch"), GUARD_PRELAUNCH_TARGETS);
  assert.equal(targetsForMode("guard_transition"), GUARD_TRANSITION_TARGETS);
  assert.equal(targetsForMode("guard_live"), GUARD_LIVE_TARGETS);
  assert.equal(targetsForMode("guard_frozen"), GUARD_FROZEN_TARGETS);
  assert.equal(targetsForMode("containment"), BACKEND_RECOVERY_TARGETS);
  assert.equal(targetsForMode("public_beta"), PUBLIC_BETA_TARGETS);
  assert.throws(() => targetsForMode("production"), /invalid AUDIT_MODE/);

  const canonicalChannels = {
    schema_version: 1,
    authorization_policy: "owner_only_ga_v1",
    qualification_basis: "owner_attested",
    current_channel: "guard_transition",
    source_sha256: "a".repeat(64),
    channels: {
      guard_transition: {
        authorization_policy: "owner_only_ga_v1",
        qualification_basis: "owner_attested",
      },
    },
  };
  globalThis.fetch = async () => new Response(JSON.stringify(canonicalChannels), { status: 200 });
  assert.equal(await loadCanonicalMode("canonical"), "guard_transition");
  assert.equal(await loadCanonicalMode("guard_transition"), "guard_transition");
  await assert.rejects(loadCanonicalMode("guard_prelaunch"), /differs from canonical/);
  canonicalChannels.authorization_policy = "review_bypassed";
  await assert.rejects(loadCanonicalMode("canonical"), /contract is invalid/);

  const checkedInContracts = {
    "https://tinyzkp.com/discovery.json": await readFile(new URL("../../site/discovery.json", import.meta.url), "utf8"),
    "https://tinyzkp.com/commerce.json": await readFile(new URL("../../site/commerce.json", import.meta.url), "utf8"),
    "https://tinyzkp.com/release.json": await readFile(new URL("../../site/release.json", import.meta.url), "utf8"),
    "https://tinyzkp.com/pricing.json": await readFile(new URL("../../site/pricing.json", import.meta.url), "utf8"),
  };
  for (const target of GUARD_PRELAUNCH_TARGETS.filter((item) => item.jsonField)) {
    globalThis.fetch = async () => new Response(checkedInContracts[target.url], { status: 200 });
    assert.equal((await probe(target)).ok, true, `checked-in contract drift: ${target.name}`);
  }

  const retired = GUARD_TRANSITION_TARGETS.find((target) => target.name === "api-retired");
  globalThis.fetch = async () => responseFor(retired, { omitExpectedHeader: true });
  const indexableRetiredHost = await probe(retired);
  assert.equal(indexableRetiredHost.ok, false);
  assert.equal(indexableRetiredHost.missing, "x-robots-tag=noindex");
  globalThis.fetch = async (_url, options) => {
    assert.equal(options.redirect, "manual");
    return new Response(null, { status: 302, headers: { location: "https://tinyzkp.com/gone" } });
  };
  assert.equal((await probe(retired)).ok, false, "302 to a later 410 cannot mask a live legacy origin");

  const liveCommerceTarget = GUARD_LIVE_TARGETS.find((target) => target.contract === "guard_live_commerce");
  const invalidCommerce = contractPayload("guard_live_commerce");
  invalidCommerce.variants.annual.checkout_url = invalidCommerce.variants.monthly.checkout_url;
  assert.equal(validateContract("guard_live_commerce", invalidCommerce), false);
  globalThis.fetch = async () => responseFor(liveCommerceTarget, { body: JSON.stringify(invalidCommerce) });
  assert.equal((await probe(liveCommerceTarget)).ok, false);

  const frozenCommerce = contractPayload("guard_frozen_commerce");
  assert.equal(validateContract("guard_frozen_commerce", frozenCommerce), true);
  assert.deepEqual(frozenPortalTargets(frozenCommerce).map((target) => target.name), [
    "billing-portal-reachable",
  ]);
  for (const invalidPortal of [
    "https://lnholdings.lemonsqueezy.com/billing/",
    "https://lnholdings.lemonsqueezy.com/billing?",
    "https://lnholdings.lemonsqueezy.com/billing#",
  ]) {
    const invalidFrozen = structuredClone(frozenCommerce);
    invalidFrozen.customer_portal_url = invalidPortal;
    assert.equal(validateContract("guard_frozen_commerce", invalidFrozen), false);
  }

  const merchantTargets = liveMerchantTargets(contractPayload("guard_live_commerce"));
  assert.deepEqual(merchantTargets.map((target) => target.name), [
    "monthly-checkout-reachable",
    "annual-checkout-reachable",
    "billing-portal-reachable",
  ]);
  for (const target of merchantTargets) {
    globalThis.fetch = async () => new Response(
      target.name.startsWith("monthly") ? "$499" : target.name.startsWith("annual") ? "$4,990" : "billing",
      { status: 200 },
    );
    assert.equal((await probe(target)).ok, true, target.name);
  }
  globalThis.fetch = async () => new Response(null, {
    status: 302,
    headers: { location: "https://evil.example/checkout" },
  });
  assert.equal((await probe(merchantTargets[0])).ok, false);

  const releasePayload = contractPayload("guard_live_release");
  const exactBodies = {
    "guard-channel-exact": "channel bytes",
    "guard-index-exact": "index bytes",
    "guard-index-signature-exact": "signature bytes",
  };
  releasePayload.channel_manifest.sha256 = createHash("sha256").update(exactBodies["guard-channel-exact"]).digest("hex");
  releasePayload.latest_release_index.sha256 = createHash("sha256").update(exactBodies["guard-index-exact"]).digest("hex");
  releasePayload.latest_release_index.signature_sha256 = createHash("sha256").update(exactBodies["guard-index-signature-exact"]).digest("hex");
  const releaseTargets = liveReleaseTargets(releasePayload);
  assert.deepEqual(releaseTargets.map((target) => target.name), [
    "guard-artifact-anonymous",
    "guard-channel-exact",
    "guard-index-exact",
    "guard-index-signature-exact",
  ]);
  for (const target of releaseTargets) {
    globalThis.fetch = async () => new Response(exactBodies[target.name] || "artifact", { status: 200 });
    assert.equal((await probe(target)).ok, true, target.name);
  }
  globalThis.fetch = async () => new Response("tampered", { status: 200 });
  assert.equal((await probe(releaseTargets[1])).ok, false);

  const nextRelease = structuredClone(releasePayload);
  nextRelease.release_identity.guard_version = "0.1.1";
  nextRelease.channel_manifest.release_identity.guard_version = "0.1.1";
  nextRelease.guard_artifact_url = nextRelease.guard_artifact_url.replaceAll("0.1.0", "0.1.1");
  nextRelease.channel_manifest.url = nextRelease.channel_manifest.url.replaceAll("0.1.0", "0.1.1");
  assert.equal(liveReleaseTargets(nextRelease).length, 4);
  assert.equal(
    liveReleaseTargets(
      contractPayload("guard_frozen_release"),
      null,
      "guard_frozen",
    ).length,
    4,
  );

  const ociBody = '{"schemaVersion":2}';
  const ociDigest = `sha256:${createHash("sha256").update(ociBody).digest("hex")}`;
  globalThis.fetch = async (url, options) => {
    const rawUrl = String(url);
    if (rawUrl.startsWith("https://ghcr.io/token?")) {
      assert.equal(options.headers.authorization, undefined);
      return new Response(JSON.stringify({ token: "anonymous" }), { status: 200 });
    }
    if (options.headers.authorization === "Bearer anonymous") {
      return new Response(ociBody, { status: 200 });
    }
    return new Response(null, {
      status: 401,
      headers: { "www-authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:logannye/tinyzkp-guard:pull"' },
    });
  };
  assert.equal((await probeOci({ name: "guard-oci", ociRepository: "logannye/tinyzkp-guard", ociDigest })).ok, true);
  globalThis.fetch = async (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
  });
  const timedOut = await probeOci(
    { name: "guard-oci-timeout", ociRepository: "logannye/tinyzkp-guard", ociDigest },
    5,
  );
  assert.equal(timedOut.ok, false);
  assert.match(timedOut.error, /aborted/);

  const containment = GUARD_PRELAUNCH_TARGETS.find(
    (target) => target.name === "checkout-contained",
  );
  globalThis.fetch = async () => responseFor(containment, { status: 200, body: '{"ok":true}' });
  const reenabled = await probe(containment);
  assert.equal(reenabled.ok, false);
  assert.equal(reenabled.status, 200);

  globalThis.fetch = async () => responseFor(containment, { body: '{"code":"wrong"}' });
  const wrongCode = await probe(containment);
  assert.equal(wrongCode.ok, false);
  assert.equal(wrongCode.missing, containment.contains);

  let alertRequest;
  globalThis.fetch = async (url, options) => {
    alertRequest = { url, options };
    return new Response(null, { status: 204 });
  };
  const delivered = await alert(
    { ALERT_WEBHOOK_URL: "https://relay.example/alert", ALERT_WEBHOOK_TOKEN: "x".repeat(64) },
    [{ name: "api-ready", status: 503 }],
    "guard_prelaunch",
  );
  assert.equal(delivered, true);
  assert.equal(alertRequest.options.headers.authorization, `Bearer ${"x".repeat(64)}`);
  assert.deepEqual(JSON.parse(alertRequest.options.body), {
    text: "🔴 TinyZKP Guard prelaunch surface failed: api-ready (503)",
    incident: "external_probe_failed",
  });

  const fingerprint = failureFingerprint([
    { name: "z", status: 503 },
    { name: "a", status: 200, missing: "expected" },
  ]);
  assert.equal(
    fingerprint,
    '[{"name":"a","status":200,"missing":"expected","error":null},{"name":"z","status":503,"missing":null,"error":null}]',
  );

  const kv = new FakeKv();
  const payloads = [];
  const env = {
    ALERT_WEBHOOK_URL: "https://relay.example/alert",
    ALERT_WEBHOOK_TOKEN: "x".repeat(64),
    ALERT_REMINDER_SECONDS: "300",
    ALERT_STATE: kv,
  };
  globalThis.fetch = async (_url, options) => {
    payloads.push(JSON.parse(options.body));
    return new Response(null, { status: 204 });
  };
  const firstFailure = [{ name: "site-commerce-contained", status: 500 }];
  await reconcileAlertState(env, firstFailure, "guard_prelaunch", 0);
  await reconcileAlertState(env, firstFailure, "guard_prelaunch", 1_000);
  assert.equal(payloads.length, 1, "unchanged incidents are suppressed");

  const changedFailure = [{ name: "site-commerce-contained", status: 200, missing: "checkout_enabled=false" }];
  await reconcileAlertState(env, changedFailure, "guard_prelaunch", 2_000);
  assert.equal(payloads.length, 2, "a changed incident pages immediately");

  await reconcileAlertState(env, changedFailure, "guard_prelaunch", 303_000);
  assert.equal(payloads.length, 3, "an unchanged incident sends one bounded reminder");

  await reconcileAlertState(env, [], "guard_prelaunch", 304_000);
  await reconcileAlertState(env, [], "guard_prelaunch", 305_000);
  assert.equal(payloads.length, 4, "recovery is sent once");
  assert.equal(payloads[3].incident, "external_probe_recovered");
  assert.equal(kv.values.size, 0);
} finally {
  globalThis.fetch = originalFetch;
}
