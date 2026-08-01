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
    jsonField: "launch_state",
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

const RETIRED_LEGACY_TARGETS = [
  { name: "api-retired", url: "https://api.tinyzkp.com/healthz", expect: 410, direct: true, headerName: "x-robots-tag", headerContains: "noindex", contains: "This surface has been retired." },
  { name: "api-ready-retired", url: "https://api.tinyzkp.com/readyz", expect: 410, direct: true, headerName: "x-robots-tag", headerContains: "noindex", contains: "This surface has been retired." },
  { name: "api-routes-retired", url: "https://api.tinyzkp.com/templates", expect: 410, direct: true, headerName: "x-robots-tag", headerContains: "noindex", contains: "This surface has been retired." },
  { name: "webhook-retired", url: "https://webhook.tinyzkp.com/health", expect: 410, direct: true, headerName: "x-robots-tag", headerContains: "noindex", contains: "This surface has been retired." },
  { name: "mcp-retired", url: "https://mcp.tinyzkp.com/mcp", method: "POST", body: "{}", expect: 410, direct: true, headerName: "x-robots-tag", headerContains: "noindex", contains: "This surface has been retired." },
  { name: "mcp-version-retired", url: "https://mcp.tinyzkp.com/version", expect: 410, direct: true, headerName: "x-robots-tag", headerContains: "noindex", contains: "This surface has been retired." },
];

const GUARD_WITHDRAWN_TARGETS = [
  ...RETIRED_LEGACY_TARGETS,
  { name: "site", url: "https://tinyzkp.com/", expect: 200 },
  { name: "guard-withdrawn-commerce", url: "https://tinyzkp.com/commerce.json", expect: 200, contract: "guard_withdrawn_commerce" },
  { name: "guard-withdrawn-release", url: "https://tinyzkp.com/release.json", expect: 200, contract: "guard_withdrawn_release" },
  { name: "guard-withdrawn-discovery", url: "https://tinyzkp.com/discovery.json", expect: 200, contract: "guard_withdrawn_discovery" },
];

const GUARD_TRANSITION_TARGETS = [
  ...RETIRED_LEGACY_TARGETS,
  { name: "site", url: "https://tinyzkp.com/", expect: 200 },
  { name: "guard-transition-commerce", url: "https://tinyzkp.com/commerce.json", expect: 200, contract: "guard_transition_commerce" },
  { name: "guard-transition-release", url: "https://tinyzkp.com/release.json", expect: 200, contract: "guard_transition_release" },
];

const GUARD_LIVE_TARGETS = [
  ...RETIRED_LEGACY_TARGETS,
  { name: "site", url: "https://tinyzkp.com/", expect: 200 },
  { name: "guard-live-commerce", url: "https://tinyzkp.com/commerce.json", expect: 200, contract: "guard_live_commerce" },
  { name: "guard-live-release", url: "https://tinyzkp.com/release.json", expect: 200, contract: "guard_live_release" },
  { name: "guard-live-discovery", url: "https://tinyzkp.com/discovery.json", expect: 200, contract: "guard_live_discovery" },
];

const GUARD_FROZEN_TARGETS = [
  ...RETIRED_LEGACY_TARGETS,
  { name: "site", url: "https://tinyzkp.com/", expect: 200 },
  { name: "guard-frozen-commerce", url: "https://tinyzkp.com/commerce.json", expect: 200, contract: "guard_frozen_commerce" },
  { name: "guard-frozen-release", url: "https://tinyzkp.com/release.json", expect: 200, contract: "guard_frozen_release" },
  { name: "guard-frozen-discovery", url: "https://tinyzkp.com/discovery.json", expect: 200, contract: "guard_frozen_discovery" },
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
  if (mode === "guard_withdrawn") return GUARD_WITHDRAWN_TARGETS;
  if (mode === "guard_transition") return GUARD_TRANSITION_TARGETS;
  if (mode === "guard_live") return GUARD_LIVE_TARGETS;
  if (mode === "guard_frozen") return GUARD_FROZEN_TARGETS;
  if (mode === "containment") return BACKEND_RECOVERY_TARGETS;
  if (mode === "public_beta") return PUBLIC_BETA_TARGETS;
  throw new Error(`invalid AUDIT_MODE: ${mode}`);
}

async function loadCanonicalMode(requestedMode = "canonical") {
  const response = await fetch("https://tinyzkp.com/release-channels-v1.json", {
    method: "GET",
    redirect: "error",
    cf: { cacheTtl: 0 },
    headers: { "user-agent": "tinyzkp-uptime-probe", "accept": "application/json" },
  });
  if (!response.ok) throw new Error(`release-channels-v1.json returned ${response.status}`);
  const payload = await response.json();
  const mode = payload?.current_channel;
  const channel = payload?.channels?.[mode];
  if (
    payload?.schema_version !== 1
    || payload?.authorization_policy !== AUTHORIZATION_POLICY
    || payload?.qualification_basis !== QUALIFICATION_BASIS
    || !/^[0-9a-f]{64}$/.test(payload?.source_sha256 || "")
    || !["guard_prelaunch", "guard_withdrawn", "guard_transition", "guard_live", "guard_frozen"].includes(mode)
    || channel?.authorization_policy !== AUTHORIZATION_POLICY
    || channel?.qualification_basis !== QUALIFICATION_BASIS
  ) {
    throw new Error("canonical release channel contract is invalid");
  }
  if (requestedMode !== "canonical" && requestedMode !== mode) {
    throw new Error(`configured AUDIT_MODE ${requestedMode} differs from canonical ${mode}`);
  }
  return mode;
}

const TIMEOUT_MS = 10_000;
const RETRY_DELAY_MS = 5_000;
const INCIDENT_KEY = "incident:external_probe_failed";
const DEFAULT_ALERT_REMINDER_SECONDS = 6 * 60 * 60;
const MIN_ALERT_REMINDER_SECONDS = 5 * 60;
const MAX_ALERT_REMINDER_SECONDS = 24 * 60 * 60;
const AUTHORIZATION_POLICY = "owner_only_ga_v1";
const QUALIFICATION_BASIS = "owner_attested";
const CHECKOUT_PATH = /^\/checkout\/buy\/[A-Za-z0-9_-]{8,128}\/?$/;
const STORE_HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.lemonsqueezy\.com$/i;

function ownerContract(payload) {
  return payload?.authorization_policy === AUTHORIZATION_POLICY
    && payload?.qualification_basis === QUALIFICATION_BASIS;
}

function verifiedPrivateSupport(value) {
  return value
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === [
      "contact",
      "delivery_verified",
      "intake",
      "owner_access_verified",
      "retention_configured",
      "state",
    ].join(",")
    && value.state === "verified"
    && value.intake === "private_email"
    && /^[a-z0-9][a-z0-9.!#$%&'*+/=?^_`{|}~-]{0,62}@tinyzkp\.com$/.test(value.contact || "")
    && value.delivery_verified === true
    && value.owner_access_verified === true
    && value.retention_configured === true;
}

function storeUrl(raw) {
  if (typeof raw !== "string" || raw.includes("#")) return null;
  try {
    const url = new URL(raw);
    if (
      url.protocol !== "https:"
      || !STORE_HOST.test(url.hostname)
      || /^(?:api|app|www)\.lemonsqueezy\.com$/i.test(url.hostname)
      || url.username
      || url.password
      || (url.port && url.port !== "443")
      || url.hash
    ) return null;
    return url;
  } catch {
    return null;
  }
}

function checkoutUrl(raw, customData) {
  const url = storeUrl(raw);
  if (!url || !CHECKOUT_PATH.test(url.pathname)) return null;
  const termsKey = "checkout[custom][terms_version]";
  const guardKey = "checkout[custom][guard_version]";
  const pairs = Array.from(url.searchParams.entries());
  if (
    pairs.length !== 2
    || url.searchParams.getAll(termsKey).length !== 1
    || url.searchParams.getAll(guardKey).length !== 1
    || url.searchParams.get(termsKey) !== customData?.terms_version
    || url.searchParams.get(guardKey) !== customData?.guard_version
  ) return null;
  return url;
}

function portalUrl(raw) {
  const url = storeUrl(raw);
  if (!url || raw.includes("?") || raw.includes("#") || url.pathname !== "/billing" || url.search) return null;
  return url;
}

function validateContract(name, payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return false;
  if (name === "guard_transition_commerce") {
    return ownerContract(payload)
      && payload.schema_version === 2
      && payload.checkout_enabled === false
      && payload.launch_state === "blocked"
      && payload.sales_state === "closed"
      && payload.commerce_state === "live_hidden";
  }
  if (name === "guard_transition_release") {
    return ownerContract(payload)
      && payload.schema_version === 2
      && payload.checkout_enabled === false
      && payload.launch_state === "blocked"
      && payload.sales_state === "closed"
      && Array.isArray(payload.blocking_gates)
      && payload.blocking_gates.length === 1
      && payload.blocking_gates[0] === "guard_artifact_published";
  }
  if (name === "guard_live_commerce") {
    const monthly = payload.variants?.monthly;
    const annual = payload.variants?.annual;
    const monthlyUrl = checkoutUrl(monthly?.checkout_url, payload.checkout_custom_data);
    const annualUrl = checkoutUrl(annual?.checkout_url, payload.checkout_custom_data);
    const portal = portalUrl(payload.customer_portal_url);
    return ownerContract(payload)
      && payload.schema_version === 2
      && payload.checkout_enabled === true
      && payload.launch_state === "qualified"
      && payload.sales_state === "live"
      && payload.commerce_state === "public_live"
      && payload.mode === "live"
      && payload.portal_state === "live"
      && payload.price_policy?.monthly_usd === 499
      && payload.price_policy?.annual_usd === 4990
      && payload.price_policy?.annual_default === true
      && verifiedPrivateSupport(payload.support)
      && /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(payload.checkout_custom_data?.guard_version || "")
      && monthly?.reviewed === true
      && annual?.reviewed === true
      && /^[1-9][0-9]*$/.test(monthly?.variant_id || "")
      && /^[1-9][0-9]*$/.test(annual?.variant_id || "")
      && monthly.variant_id !== annual.variant_id
      && monthly.checkout_url !== annual.checkout_url
      && monthlyUrl !== null
      && annualUrl !== null
      && portal !== null
      && monthlyUrl.hostname === annualUrl.hostname
      && monthlyUrl.hostname === portal.hostname
      && monthlyUrl.hostname === payload.store_hostname;
  }
  if (name === "guard_live_release") {
    return ownerContract(payload)
      && payload.schema_version === 2
      && payload.checkout_enabled === true
      && payload.launch_state === "qualified"
      && payload.sales_state === "live"
      && payload.commerce_state === "public_live"
      && payload.guard_artifact_available === true
      && /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(payload.release_identity?.guard_version || "")
      && Array.isArray(payload.blocking_gates)
      && payload.blocking_gates.length === 0;
  }
  if (name === "guard_live_discovery") {
    return payload.launch_state === "qualified"
      && payload.sales_state === "live"
      && payload.service_status === "guard_live"
      && payload.availability?.guard_checkout === true
      && payload.availability?.guard_artifact === true;
  }
  if (name === "guard_withdrawn_commerce") {
    const variants = payload.variants;
    const noCheckoutUrls = variants
      && Object.keys(variants).sort().join(",") === "annual,monthly"
      && variants.monthly?.checkout_url === null
      && variants.annual?.checkout_url === null
      && variants.monthly?.reviewed === false
      && variants.annual?.reviewed === false;
    const portalAbsent = payload.portal_state === "unconfigured"
      && payload.customer_portal_url === null
      && payload.store_hostname === null
      && payload.support === null;
    const portalRetained = payload.portal_state === "live"
      && portalUrl(payload.customer_portal_url) !== null
      && new URL(payload.customer_portal_url).hostname === payload.store_hostname
      && verifiedPrivateSupport(payload.support);
    return ownerContract(payload)
      && payload.schema_version === 2
      && payload.checkout_enabled === false
      && payload.sales_state === "withdrawn"
      && noCheckoutUrls
      && (portalAbsent || portalRetained);
  }
  if (name === "guard_withdrawn_release") {
    const blocked = payload.launch_state === "blocked"
      && payload.guard_artifact_available === false
      && Array.isArray(payload.blocking_gates)
      && payload.blocking_gates.length > 0;
    const fulfilled = payload.launch_state === "qualified"
      && payload.guard_artifact_available === true
      && Array.isArray(payload.blocking_gates)
      && payload.blocking_gates.length === 0;
    return ownerContract(payload)
      && payload.schema_version === 2
      && payload.checkout_enabled === false
      && payload.sales_state === "withdrawn"
      && (blocked || fulfilled);
  }
  if (name === "guard_withdrawn_discovery") {
    return payload.sales_state === "withdrawn"
      && payload.service_status === "guard_withdrawn"
      && payload.availability?.guard_checkout === false
      && payload.availability?.hosted_proving === false
      && payload.availability?.hosted_verification === false;
  }
  if (name === "guard_frozen_commerce") {
    return ownerContract(payload)
      && payload.schema_version === 2
      && payload.checkout_enabled === false
      && payload.launch_state === "qualified"
      && payload.sales_state === "frozen"
      && payload.commerce_state === "sales_frozen"
      && payload.portal_state === "live"
      && payload.mode === "live"
      && verifiedPrivateSupport(payload.support)
      && payload.variants?.monthly?.checkout_url === null
      && payload.variants?.annual?.checkout_url === null
      && portalUrl(payload.customer_portal_url) !== null
      && new URL(payload.customer_portal_url).hostname === payload.store_hostname;
  }
  if (name === "guard_frozen_release") {
    return ownerContract(payload)
      && payload.schema_version === 2
      && payload.checkout_enabled === false
      && payload.launch_state === "qualified"
      && payload.sales_state === "frozen"
      && payload.commerce_state === "sales_frozen"
      && payload.guard_artifact_available === true
      && Array.isArray(payload.blocking_gates)
      && payload.blocking_gates.length === 0
      && /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(payload.release_identity?.guard_version || "");
  }
  if (name === "guard_frozen_discovery") {
    return payload.launch_state === "qualified"
      && payload.sales_state === "frozen"
      && payload.service_status === "guard_frozen"
      && payload.availability?.guard_checkout === false
      && payload.availability?.guard_artifact === true;
  }
  return false;
}

function liveMerchantTargets(payload) {
  if (!validateContract("guard_live_commerce", payload)) {
    throw new Error("live commerce contract is invalid");
  }
  const host = new URL(payload.customer_portal_url).hostname;
  return [
    {
      name: "monthly-checkout-reachable",
      url: payload.variants.monthly.checkout_url,
      expectAny: [200, 301, 302, 303, 307, 308],
      merchantDestination: { kind: "checkout", storeHost: host },
      containsAny: ["499", "$499"],
    },
    {
      name: "annual-checkout-reachable",
      url: payload.variants.annual.checkout_url,
      expectAny: [200, 301, 302, 303, 307, 308],
      merchantDestination: { kind: "checkout", storeHost: host },
      containsAny: ["4,990", "4990"],
    },
    {
      name: "billing-portal-reachable",
      url: payload.customer_portal_url,
      expectAny: [200, 301, 302, 303, 307, 308],
      merchantDestination: { kind: "portal", storeHost: host },
    },
  ];
}

function frozenPortalTargets(payload) {
  if (!validateContract("guard_frozen_commerce", payload)) {
    throw new Error("frozen commerce contract is invalid");
  }
  const host = new URL(payload.customer_portal_url).hostname;
  return [{
    name: "billing-portal-reachable",
    url: payload.customer_portal_url,
    expectAny: [200, 301, 302, 303, 307, 308],
    merchantDestination: { kind: "portal", storeHost: host },
  }];
}

function publicReleaseUrl(raw, kind) {
  if (typeof raw !== "string") return null;
  try {
    const url = new URL(raw);
    if (
      url.protocol !== "https:"
      || url.username
      || url.password
      || url.port
      || url.search
      || url.hash
    ) return null;
    if (kind === "github") {
      return url.hostname === "github.com"
        && /^\/logannye\/hc-stark\/releases\/download\/guard-v[^/]+\/[^/]+$/.test(url.pathname)
        ? url : null;
    }
    return ["tinyzkp.com", "www.tinyzkp.com"].includes(url.hostname)
      && /^\/(?:release-index-revisions\/[0-9a-f]{64}\/)?guard-release-index-v1\.json(?:\.sig)?$/.test(url.pathname)
      ? url : null;
  } catch {
    return null;
  }
}

function liveReleaseTargets(payload, compatibility = null, mode = "guard_live") {
  const contract = mode === "guard_frozen" ? "guard_frozen_release" : "guard_live_release";
  if (!validateContract(contract, payload)) {
    throw new Error("live release contract is invalid");
  }
  const channel = payload.channel_manifest;
  const latest = payload.latest_release_index;
  const artifact = publicReleaseUrl(payload.guard_artifact_url, "github");
  const channelUrl = publicReleaseUrl(channel?.url, "github");
  const stableIndex = publicReleaseUrl(latest?.url, "site");
  const stableSignature = publicReleaseUrl(latest?.signature_url, "site");
  if (
    !artifact || !channelUrl || !stableIndex || !stableSignature
    || !/^[0-9a-f]{64}$/.test(payload.guard_artifact_sha256 || "")
    || !/^[0-9a-f]{64}$/.test(channel?.sha256 || "")
    || !/^[0-9a-f]{64}$/.test(latest?.sha256 || "")
    || !/^[0-9a-f]{64}$/.test(latest?.signature_sha256 || "")
    || channel.release_identity !== undefined && channel.release_identity.guard_version !== payload.release_identity.guard_version
  ) throw new Error("live release download identity is invalid");
  const targets = [
    {
      name: "guard-artifact-anonymous",
      url: artifact.href,
      expectAny: [200, 301, 302, 303, 307, 308],
      publicReleaseDestination: "github",
    },
    {
      name: "guard-channel-exact",
      url: channelUrl.href,
      expectAny: [200, 301, 302, 303, 307, 308],
      publicReleaseDestination: "github",
      sha256: channel.sha256,
    },
    {
      name: "guard-index-exact",
      url: stableIndex.href,
      expect: 200,
      publicReleaseDestination: "site",
      sha256: latest.sha256,
    },
    {
      name: "guard-index-signature-exact",
      url: stableSignature.href,
      expect: 200,
      publicReleaseDestination: "site",
      sha256: latest.signature_sha256,
    },
  ];
  if (compatibility !== null) {
    const engineDigest = compatibility?.release_binding?.engine_oci_digest;
    if (
      !/^sha256:[0-9a-f]{64}$/.test(payload.guard_oci_digest || "")
      || !/^sha256:[0-9a-f]{64}$/.test(engineDigest || "")
    ) throw new Error("live OCI release identity is invalid");
    targets.push(
      { name: "guard-oci-anonymous", ociRepository: "logannye/tinyzkp-guard", ociDigest: payload.guard_oci_digest },
      { name: "engine-oci-anonymous", ociRepository: "logannye/tinyzkp-engine", ociDigest: engineDigest },
    );
  }
  return targets;
}

async function loadLiveReleaseTargets(mode = "guard_live") {
  const options = {
    method: "GET",
    redirect: "error",
    cf: { cacheTtl: 0 },
    headers: { "user-agent": "tinyzkp-uptime-probe", "accept": "application/json" },
  };
  const [response, compatibilityResponse] = await Promise.all([
    fetch("https://tinyzkp.com/release.json", options),
    fetch("https://tinyzkp.com/compatibility.json", options),
  ]);
  if (!response.ok) throw new Error(`release.json returned ${response.status}`);
  if (!compatibilityResponse.ok) throw new Error(`compatibility.json returned ${compatibilityResponse.status}`);
  return liveReleaseTargets(await response.json(), await compatibilityResponse.json(), mode);
}

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function probeOci(target, timeoutMs = TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const url = `https://ghcr.io/v2/${target.ociRepository}/manifests/${target.ociDigest}`;
  const options = (authorization = null) => ({
    method: "GET",
    redirect: "error",
    signal: controller.signal,
    cf: { cacheTtl: 0 },
    headers: {
      "user-agent": "tinyzkp-uptime-probe",
      "accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
      ...(authorization ? { authorization } : {}),
    },
  });
  try {
    let response = await fetch(url, options());
    if (response.status === 401) {
      const challenge = response.headers.get("www-authenticate") || "";
      const match = challenge.match(/^Bearer realm="(https:\/\/ghcr\.io\/token)",service="([^"]+)",scope="([^"]+)"$/);
      const scope = `repository:${target.ociRepository}:pull`;
      if (!match || match[2] !== "ghcr.io" || match[3] !== scope) {
        return { name: target.name, ok: false, status: 401, missing: "anonymous GHCR pull challenge" };
      }
      const tokenUrl = new URL(match[1]);
      tokenUrl.searchParams.set("service", match[2]);
      tokenUrl.searchParams.set("scope", match[3]);
      const tokenResponse = await fetch(tokenUrl, { method: "GET", redirect: "error", signal: controller.signal, headers: { "user-agent": "tinyzkp-uptime-probe", "accept": "application/json" } });
      if (!tokenResponse.ok) return { name: target.name, ok: false, status: tokenResponse.status };
      const token = (await tokenResponse.json())?.token;
      if (typeof token !== "string" || !token) return { name: target.name, ok: false, status: tokenResponse.status, missing: "anonymous GHCR token" };
      response = await fetch(url, options(`Bearer ${token}`));
    }
    if (response.status !== 200) return { name: target.name, ok: false, status: response.status };
    const observed = `sha256:${await sha256Hex(await response.arrayBuffer())}`;
    return { name: target.name, ok: observed === target.ociDigest, status: response.status, missing: observed === target.ociDigest ? undefined : target.ociDigest };
  } catch (error) {
    return { name: target.name, ok: false, status: 0, error: String(error) };
  } finally {
    clearTimeout(timer);
  }
}

async function loadLiveMerchantTargets() {
  const response = await fetch("https://tinyzkp.com/commerce.json", {
    method: "GET",
    redirect: "error",
    cf: { cacheTtl: 0 },
    headers: { "user-agent": "tinyzkp-uptime-probe", "accept": "application/json" },
  });
  if (!response.ok) throw new Error(`commerce.json returned ${response.status}`);
  return liveMerchantTargets(await response.json());
}

async function probe(target) {
  if (target.ociRepository) return probeOci(target);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(target.url, {
      method: target.method || "GET",
      body: target.body,
      redirect: (target.merchantDestination || target.direct) ? "manual" : "follow",
      signal: controller.signal,
      cf: { cacheTtl: 0 },
      headers: {
        "user-agent": "tinyzkp-uptime-probe",
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
      },
    });
    const statusOk = Array.isArray(target.expectAny)
      ? target.expectAny.includes(res.status)
      : target.expect === null ? true : res.status === target.expect;
    if (!statusOk) return { name: target.name, ok: false, status: res.status };

    if (target.merchantDestination) {
      const location = res.headers.get("location");
      const destination = location ? new URL(location, target.url) : new URL(res.url || target.url);
      const source = new URL(target.url);
      const merchant = target.merchantDestination;
      const checkoutDestination = merchant.kind === "checkout"
        && destination.hostname === merchant.storeHost
        && destination.pathname === source.pathname;
      const portalDestination = merchant.kind === "portal"
        && (
          (destination.hostname === merchant.storeHost && destination.pathname === "/billing")
          || (destination.hostname === "app.lemonsqueezy.com"
            && /^\/(?:login|billing|my-orders)(?:\/|$)/.test(destination.pathname)
            && !destination.search)
        );
      if (
        destination.protocol !== "https:"
        || destination.username
        || destination.password
        || destination.hash
        || !(checkoutDestination || portalDestination)
      ) {
        return { name: target.name, ok: false, status: res.status, missing: "approved merchant redirect host" };
      }
      if (res.status >= 300 && res.status < 400 && !location) {
        return { name: target.name, ok: false, status: res.status, missing: "merchant redirect location" };
      }
    }

    if (target.publicReleaseDestination) {
      const location = res.headers.get("location");
      const destination = location ? new URL(location, target.url) : new URL(res.url || target.url);
      const allowed = target.publicReleaseDestination === "github"
        ? ["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"]
        : ["tinyzkp.com", "www.tinyzkp.com"];
      if (
        destination.protocol !== "https:"
        || destination.username
        || destination.password
        || destination.hash
        || !allowed.includes(destination.hostname)
        || (res.status >= 300 && res.status < 400 && !location)
      ) return { name: target.name, ok: false, status: res.status, missing: "approved anonymous release destination" };
    }

    const headerOk = !target.headerName
      || (res.headers.get(target.headerName) || "").toLowerCase().includes(target.headerContains.toLowerCase());
    if (!headerOk) {
      return { name: target.name, ok: false, status: res.status, missing: `${target.headerName}=${target.headerContains}` };
    }

    if (target.sha256) {
      if (res.status !== 200) {
        return { name: target.name, ok: false, status: res.status, missing: "direct exact-byte response" };
      }
      const observed = await sha256Hex(await res.arrayBuffer());
      return { name: target.name, ok: observed === target.sha256, status: res.status, missing: observed === target.sha256 ? undefined : `sha256=${target.sha256}` };
    }

    if (target.contains || target.containsAny || target.jsonField || target.contract) {
      const body = await res.text();
      if (target.contract) {
        let payload;
        try { payload = JSON.parse(body); } catch { return { name: target.name, ok: false, status: res.status, error: "invalid JSON" }; }
        const contractOk = validateContract(target.contract, payload);
        return { name: target.name, ok: contractOk, status: res.status, missing: contractOk ? undefined : target.contract };
      }
      if (target.containsAny && res.status === 200) {
        const containsOk = target.containsAny.some((marker) => body.includes(marker));
        return { name: target.name, ok: containsOk, status: res.status, missing: containsOk ? undefined : target.containsAny.join(" or ") };
      }
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
  if (mode === "guard_withdrawn") return "Guard withdrawn";
  if (mode === "guard_transition") return "Guard transition";
  if (mode === "guard_live") return "Guard live";
  if (mode === "guard_frozen") return "Guard frozen";
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
    .map((failure) => {
      const reason = failure.missing || failure.error;
      return `${failure.name} (${failure.status}${reason ? `; ${reason}` : ""})`;
    })
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
  let mode;
  try {
    mode = await loadCanonicalMode(env.AUDIT_MODE || "canonical");
    targets = targetsForMode(mode);
  } catch (error) {
    const failures = [{ name: "audit-mode", ok: false, status: 0, error: String(error) }];
    await reconcileAlertState(env, failures, env.AUDIT_MODE || "invalid");
    return { ok: false, checked_at: new Date().toISOString(), mode: env.AUDIT_MODE, results: failures };
  }
  const results = await Promise.all(targets.map(probeWithRetry));
  if (mode === "guard_live" || mode === "guard_frozen") {
    try {
      const merchantTargets = mode === "guard_live"
        ? await loadLiveMerchantTargets()
        : frozenPortalTargets(
          await (await fetch("https://tinyzkp.com/commerce.json", {
            method: "GET",
            redirect: "error",
            cf: { cacheTtl: 0 },
            headers: { "user-agent": "tinyzkp-uptime-probe", "accept": "application/json" },
          })).json(),
        );
      results.push(...await Promise.all(merchantTargets.map(probeWithRetry)));
      const releaseTargets = await loadLiveReleaseTargets(mode);
      results.push(...await Promise.all(releaseTargets.map(probeWithRetry)));
    } catch (error) {
      results.push({ name: "live-merchant-targets", ok: false, status: 0, error: String(error) });
    }
  }
  const failures = results.filter((result) => !result.ok);
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
  GUARD_WITHDRAWN_TARGETS,
  GUARD_TRANSITION_TARGETS,
  GUARD_LIVE_TARGETS,
  GUARD_FROZEN_TARGETS,
  RETIRED_LEGACY_TARGETS,
  PUBLIC_BETA_TARGETS,
  targetsForMode,
  loadCanonicalMode,
  probe,
  validateContract,
  liveMerchantTargets,
  frozenPortalTargets,
  loadLiveMerchantTargets,
  liveReleaseTargets,
  loadLiveReleaseTargets,
  probeOci,
  alert,
  failureFingerprint,
  reconcileAlertState,
};
