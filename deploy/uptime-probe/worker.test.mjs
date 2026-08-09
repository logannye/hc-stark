import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  BACKEND_RECOVERY_TARGETS,
  GUARD_PRELAUNCH_TARGETS,
  GUARD_WITHDRAWN_TARGETS,
  GUARD_TRANSITION_TARGETS,
  GUARD_LIVE_TARGETS,
  GUARD_FROZEN_TARGETS,
  ESTIMATOR_TARGETS,
  ESTIMATOR_LIVENESS_FIXTURE,
  PUBLIC_BETA_TARGETS,
  targetsForMode,
  dueTargets,
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

// The exact body https://tinyzkp.com/v1/estimate returned for
// ESTIMATOR_LIVENESS_FIXTURE on 2026-08-09, copied verbatim. Keeping the real
// answer here means the validator is tested against production's actual
// output rather than against a hand-written idea of it.
const LIVE_ESTIMATE_RESPONSE = {
  schema_version: 1,
  request_digest: "7b47655339a060af69c77888e7333f90f9995b43b723ac1c40c1b84df9d21ad9",
  provable_today: true,
  blocking_reasons: [],
  estimates: {
    conventional: {
      peak_resident_bytes: 2181038080,
      scratch_high_water_bytes: 1,
      total_read_bytes: 0,
      total_write_bytes: 0,
    },
    bounded: {
      peak_resident_bytes: 1082130432,
      scratch_high_water_bytes: 3758292128,
      total_read_bytes: 11106517104,
      total_write_bytes: 7282433200,
    },
  },
};

function contractPayload(contract) {
  if (contract === "estimator_live") return structuredClone(LIVE_ESTIMATE_RESPONSE);
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
  if (contract === "guard_withdrawn_commerce") return {
    ...owner,
    checkout_enabled: false,
    launch_state: "blocked",
    sales_state: "withdrawn",
    commerce_state: "unconfigured",
    portal_state: "unconfigured",
    customer_portal_url: null,
    store_hostname: null,
    support: null,
    variants: {
      monthly: { reviewed: false, variant_id: null, checkout_url: null },
      annual: { reviewed: false, variant_id: null, checkout_url: null },
    },
  };
  if (contract === "guard_withdrawn_release") return {
    ...owner,
    checkout_enabled: false,
    launch_state: "blocked",
    sales_state: "withdrawn",
    guard_artifact_available: false,
    blocking_gates: ["guard_artifact_published"],
  };
  if (contract === "guard_withdrawn_discovery") return {
    sales_state: "withdrawn",
    service_status: "guard_withdrawn",
    availability: {
      guard_checkout: false,
      guard_artifact: false,
      hosted_proving: false,
      hosted_verification: false,
    },
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
    GUARD_WITHDRAWN_TARGETS,
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
  assert.equal(targetsForMode("guard_withdrawn"), GUARD_WITHDRAWN_TARGETS);
  assert.equal(targetsForMode("guard_transition"), GUARD_TRANSITION_TARGETS);
  assert.equal(targetsForMode("guard_live"), GUARD_LIVE_TARGETS);
  assert.equal(targetsForMode("guard_frozen"), GUARD_FROZEN_TARGETS);
  assert.equal(targetsForMode("containment"), BACKEND_RECOVERY_TARGETS);
  assert.equal(targetsForMode("public_beta"), PUBLIC_BETA_TARGETS);
  assert.throws(() => targetsForMode("production"), /invalid AUDIT_MODE/);

  // --- The live product is watched (the defect this file exists to keep fixed)
  //
  // Every post-retirement contract must probe the estimator. Before this
  // gate, `guard_withdrawn` — the canonical mode in production — checked six
  // retired hosts, the homepage, and three JSON files, and NOTHING that a
  // customer can use. This assertion fails if the estimator targets are ever
  // dropped from a mode, which is the exact way that regression happens.
  const estimatorNames = ["estimator-route-mounted", "keys-route-mounted", "estimator-answers"];
  assert.deepEqual(ESTIMATOR_TARGETS.map((target) => target.name), estimatorNames);
  for (const [mode, targets] of [
    ["guard_withdrawn", GUARD_WITHDRAWN_TARGETS],
    ["guard_transition", GUARD_TRANSITION_TARGETS],
    ["guard_live", GUARD_LIVE_TARGETS],
    ["guard_frozen", GUARD_FROZEN_TARGETS],
  ]) {
    for (const name of estimatorNames) {
      assert.ok(targets.some((target) => target.name === name), `${mode} does not watch ${name}`);
    }
  }
  // Rollback-only contracts describe eras where this endpoint did not exist.
  for (const targets of [BACKEND_RECOVERY_TARGETS, GUARD_PRELAUNCH_TARGETS, PUBLIC_BETA_TARGETS]) {
    assert.equal(targets.some((target) => estimatorNames.includes(target.name)), false);
  }

  // The probe must send the exact manifest whose live answer is asserted
  // below, by POST, to the real path — a GET or a drifted body would make the
  // whole check meaningless while still reporting green.
  const estimatorAnswers = ESTIMATOR_TARGETS.find((target) => target.name === "estimator-answers");
  assert.equal(estimatorAnswers.method, "POST");
  assert.equal(estimatorAnswers.url, "https://tinyzkp.com/v1/estimate");
  assert.deepEqual(JSON.parse(estimatorAnswers.body), ESTIMATOR_LIVENESS_FIXTURE);
  assert.equal(ESTIMATOR_LIVENESS_FIXTURE.ram_budget_bytes, 2147483648);
  const routeMounted = ESTIMATOR_TARGETS.find((target) => target.name === "estimator-route-mounted");
  assert.equal(routeMounted.expect, 405);

  // The recorded production answer satisfies the contract, and each way the
  // surface can break fails it.
  assert.equal(validateContract("estimator_live", contractPayload("estimator_live")), true);
  const brokenEstimates = {
    "error envelope": { schema_version: 1, error: { code: "malformed_manifest" } },
    "unprovable answer": { ...contractPayload("estimator_live"), provable_today: false },
    "blocked answer": {
      ...contractPayload("estimator_live"),
      blocking_reasons: [{ code: "ram_budget_exceeded" }],
    },
    "zeroed cost model": {
      ...contractPayload("estimator_live"),
      estimates: { conventional: { peak_resident_bytes: 0 }, bounded: { peak_resident_bytes: 0 } },
    },
    "memory cliff returned": {
      ...contractPayload("estimator_live"),
      estimates: {
        conventional: { peak_resident_bytes: 1082130432 },
        bounded: { peak_resident_bytes: 2181038080 },
      },
    },
    "budget overrun": {
      ...contractPayload("estimator_live"),
      estimates: {
        conventional: { peak_resident_bytes: 8589934592 },
        bounded: { peak_resident_bytes: 4294967296 },
      },
    },
    "digest dropped": { ...contractPayload("estimator_live"), request_digest: null },
  };
  for (const [label, payload] of Object.entries(brokenEstimates)) {
    assert.equal(validateContract("estimator_live", payload), false, label);
  }

  // An HTML fallback page and a rate-limited reply are both failures, not
  // "the endpoint answered".
  globalThis.fetch = async () => new Response("<!doctype html><title>TinyZKP</title>", { status: 200 });
  assert.equal((await probe(estimatorAnswers)).error, "invalid JSON");
  globalThis.fetch = async () => new Response('{"ok":false,"error":"rate_limited"}', { status: 429 });
  const rateLimited = await probe(estimatorAnswers);
  assert.equal(rateLimited.ok, false);
  assert.equal(rateLimited.status, 429);
  // A removed method guard means the route is no longer the estimator.
  globalThis.fetch = async () => new Response("ok", { status: 200 });
  assert.equal((await probe(routeMounted)).ok, false);

  // Cadence: the paid-for POST runs on the hour, the free route checks run on
  // every tick, and an on-demand run (no scheduled tick) runs everything.
  const onTheHour = dueTargets(GUARD_WITHDRAWN_TARGETS, new Date("2026-08-09T15:00:00Z"));
  const offTheHour = dueTargets(GUARD_WITHDRAWN_TARGETS, new Date("2026-08-09T15:02:00Z"));
  assert.equal(onTheHour.length, GUARD_WITHDRAWN_TARGETS.length);
  assert.equal(offTheHour.length, GUARD_WITHDRAWN_TARGETS.length - 1);
  assert.equal(offTheHour.some((target) => target.name === "estimator-answers"), false);
  assert.ok(offTheHour.some((target) => target.name === "estimator-route-mounted"));
  assert.ok(offTheHour.some((target) => target.name === "keys-route-mounted"));
  assert.equal(dueTargets(GUARD_WITHDRAWN_TARGETS, null), GUARD_WITHDRAWN_TARGETS);

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
  // Only the contracts published as static files in site/ can be replayed
  // from the working tree; `estimator-answers` is a live computation, covered
  // separately below. The count is asserted so a renamed or mistyped URL
  // cannot silently empty this loop.
  const publishedContractTargets = GUARD_WITHDRAWN_TARGETS.filter(
    (item) => item.contract && checkedInContracts[item.url],
  );
  assert.equal(publishedContractTargets.length, 3, "every published contract target is replayed");
  for (const target of publishedContractTargets) {
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

  const withdrawnCommerce = contractPayload("guard_withdrawn_commerce");
  assert.equal(validateContract("guard_withdrawn_commerce", withdrawnCommerce), true);
  withdrawnCommerce.variants.monthly.checkout_url = "https://store.example/checkout";
  assert.equal(validateContract("guard_withdrawn_commerce", withdrawnCommerce), false);

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
    [{ name: "api-ready", status: 503, missing: "HTTP 200" }],
    "guard_prelaunch",
  );
  assert.equal(delivered, true);
  assert.equal(alertRequest.options.headers.authorization, `Bearer ${"x".repeat(64)}`);
  assert.deepEqual(JSON.parse(alertRequest.options.body), {
    text: "🔴 TinyZKP Guard prelaunch surface failed: api-ready (503; HTTP 200)",
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

  // A cadence-throttled target is skipped by most runs. Those runs report no
  // failures, and without the checked-set guard that would read as recovery —
  // closing an open estimator incident two minutes after it was raised.
  const estimatorIncident = [{ name: "estimator-answers", status: 500 }];
  await reconcileAlertState(env, estimatorIncident, "guard_withdrawn", 400_000, new Set(["estimator-answers"]));
  assert.equal(payloads.length, 5, "a dead estimator pages");
  await reconcileAlertState(env, [], "guard_withdrawn", 401_000, new Set(["estimator-route-mounted"]));
  assert.equal(payloads.length, 5, "a target that was not probed is not evidence of recovery");
  assert.equal(kv.values.size, 1, "the open incident survives a run that skipped it");
  await reconcileAlertState(env, [], "guard_withdrawn", 402_000, new Set(["estimator-answers"]));
  assert.equal(payloads.length, 6, "recovery lands once the target is actually probed green");
  assert.equal(payloads[5].incident, "external_probe_recovered");
  assert.equal(kv.values.size, 0);
} finally {
  globalThis.fetch = originalFetch;
}
