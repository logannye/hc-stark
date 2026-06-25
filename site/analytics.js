(function () {
  var ENDPOINT = "/api/events";
  var ATTRIBUTION_KEY = "tinyzkp_attribution";
  var ATTRIBUTION_FIELDS = [
    "source",
    "medium",
    "campaign",
    "platform",
    "use_case",
    "workflow",
    "intent",
    "landing_path",
    "referrer_host",
    "first_seen_at",
  ];
  var FIELD_ALIASES = {
    source: ["source", "utm_source"],
    medium: ["medium", "utm_medium"],
    campaign: ["campaign", "utm_campaign"],
    platform: ["platform"],
    use_case: ["use_case"],
    workflow: ["workflow"],
    intent: ["intent"],
  };
  var CONVERSION_INTENTS = {
    "/signup": "api_key",
    "/try": "try_receipt",
    "/verify": "verify_receipt",
    "/mcp": "mcp_install",
    "/pilot": "paid_pilot",
    "/platform-rollout": "platform_rollout",
    "/contact": "contact",
  };

  function currentPageSource() {
    var slug = cleanText(window.location.pathname, 120)
      .replace(/^\/+|\/+$/g, "")
      .replace(/[^a-zA-Z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .toLowerCase();
    return "site_" + (slug || "homepage");
  }

  function cleanText(value, max) {
    return String(value || "")
      .replace(/[^\w .:/-]/g, "")
      .trim()
      .slice(0, max || 160);
  }

  function referrerHost() {
    try {
      if (!document.referrer) return "";
      var ref = new URL(document.referrer);
      if (ref.hostname === window.location.hostname) return "";
      return cleanText(ref.hostname, 160);
    } catch (_) {
      return "";
    }
  }

  function readStoredAttribution() {
    try {
      return JSON.parse(localStorage.getItem(ATTRIBUTION_KEY) || "{}") || {};
    } catch (_) {
      return {};
    }
  }

  function writeStoredAttribution(value) {
    try {
      localStorage.setItem(ATTRIBUTION_KEY, JSON.stringify(value));
    } catch (_) {}
  }

  function queryValue(params, field) {
    var aliases = FIELD_ALIASES[field] || [field];
    for (var i = 0; i < aliases.length; i += 1) {
      var value = cleanText(params.get(aliases[i]), 160);
      if (value) return value;
    }
    return "";
  }

  function collectAttribution() {
    var params = new URLSearchParams(window.location.search);
    var stored = readStoredAttribution();
    var next = {};

    ATTRIBUTION_FIELDS.forEach(function (field) {
      if (stored[field]) next[field] = cleanText(stored[field], 160);
    });

    ["source", "medium", "campaign", "platform", "use_case", "workflow", "intent"].forEach(function (field) {
      var value = queryValue(params, field);
      if (value && !next[field]) next[field] = value;
    });

    if (!next.landing_path) next.landing_path = cleanText(window.location.pathname, 160);
    if (!next.referrer_host) next.referrer_host = referrerHost();
    if (!next.first_seen_at) next.first_seen_at = new Date().toISOString();

    writeStoredAttribution(next);
    return next;
  }

  function hasFreshAttributionSignal() {
    var params = new URLSearchParams(window.location.search);
    return Boolean(
      queryValue(params, "source") ||
        queryValue(params, "medium") ||
        queryValue(params, "campaign") ||
        referrerHost()
    );
  }

  var attribution = collectAttribution();
  var shouldTrackDirectoryReferral = hasFreshAttributionSignal() && attribution.medium !== "site";
  window.tinyzkpAttribution = attribution;
  window.tinyzkpGetAttribution = function tinyzkpGetAttribution() {
    return Object.assign({}, attribution);
  };

  function cleanProps(props) {
    var out = {};
    props = props || {};
    Object.keys(props).forEach(function (key) {
      var value = props[key];
      if (value == null) return;
      if (typeof value === "number" && isFinite(value)) out[key] = Math.round(value);
      else if (typeof value === "boolean") out[key] = value;
      else out[key] = String(value).slice(0, 160);
    });
    return out;
  }

  function withAttribution(props) {
    var merged = {};
    Object.keys(attribution).forEach(function (key) {
      if (attribution[key]) merged[key] = attribution[key];
    });
    Object.keys(props || {}).forEach(function (key) {
      if (props[key] != null && props[key] !== "") merged[key] = props[key];
    });
    return merged;
  }

  function conversionIntentForPath(pathname) {
    return CONVERSION_INTENTS[pathname.replace(/\/$/, "") || "/"] || "";
  }

  function canDecorateConversionUrl(url) {
    if (url.origin !== window.location.origin) return false;
    return Boolean(conversionIntentForPath(url.pathname));
  }

  function writeClickAttribution(clickSource, intent) {
    var selectedSource = clickSource || currentPageSource();
    if (!selectedSource || attribution.source || attribution.referrer_host) return;
    attribution.source = selectedSource;
    if (!attribution.medium) attribution.medium = "site";
    if (!attribution.platform) attribution.platform = "website";
    if (!attribution.intent && intent) attribution.intent = intent;
    writeStoredAttribution(attribution);
  }

  function decorateConversionLink(el, persistClick) {
    if (!el || !el.getAttribute) return;
    var href = el.getAttribute("href") || "";
    if (!href || href.charAt(0) === "#") return;

    var url;
    try {
      url = new URL(href, window.location.origin);
    } catch (_) {
      return;
    }
    if (!canDecorateConversionUrl(url)) return;

    var clickSource = cleanText(el.getAttribute("data-source"), 160);
    var defaultSource = currentPageSource();
    var intent = attribution.intent || conversionIntentForPath(url.pathname);
    var selectedSource = attribution.source || (!attribution.referrer_host ? (clickSource || defaultSource) : "");

    if (selectedSource && !url.searchParams.has("source") && !url.searchParams.has("utm_source")) {
      url.searchParams.set("source", selectedSource);
    }
    if (!url.searchParams.has("medium") && !url.searchParams.has("utm_medium")) {
      var medium = attribution.medium || (!attribution.referrer_host && (clickSource || selectedSource === defaultSource) ? "site" : "");
      if (medium) url.searchParams.set("medium", medium);
    }
    var selectedCampaign = clickSource || attribution.campaign || (!attribution.referrer_host ? defaultSource : "");
    if (selectedCampaign && !url.searchParams.has("campaign") && !url.searchParams.has("utm_campaign")) {
      url.searchParams.set("campaign", selectedCampaign);
    }
    if (!url.searchParams.has("platform")) {
      var platform = attribution.platform || ((clickSource || selectedSource) ? "website" : "");
      if (platform) url.searchParams.set("platform", platform);
    }
    if (intent && !url.searchParams.has("intent")) url.searchParams.set("intent", intent);
    if (attribution.use_case && !url.searchParams.has("use_case")) {
      url.searchParams.set("use_case", attribution.use_case);
    }
    if (attribution.workflow && !url.searchParams.has("workflow")) {
      url.searchParams.set("workflow", attribution.workflow);
    }

    if (persistClick) writeClickAttribution(clickSource, intent);
    el.setAttribute("href", url.pathname + url.search + url.hash);
  }

  window.tinyzkpTrack = function tinyzkpTrack(event, props) {
    try {
      var payload = JSON.stringify({
        event: event,
        path: window.location.pathname,
        props: cleanProps(withAttribution(props)),
      });
      if (navigator.sendBeacon) {
        var blob = new Blob([payload], { type: "application/json" });
        if (navigator.sendBeacon(ENDPOINT, blob)) return;
      }
      fetch(ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
        keepalive: true,
      }).catch(function () {});
    } catch (_) {}
  };

  document.addEventListener("DOMContentLoaded", function () {
    window.tinyzkpTrack("page_view", { page: document.title || "", path: window.location.pathname });

    if (shouldTrackDirectoryReferral && (attribution.source || attribution.referrer_host)) {
      window.tinyzkpTrack("directory_referral", {
        source: attribution.source || "",
        referrer_host: attribution.referrer_host || "",
      });
    }

    document.querySelectorAll("[data-track]").forEach(function (el) {
      el.addEventListener("click", function () {
        decorateConversionLink(el, true);
        window.tinyzkpTrack(el.getAttribute("data-track"), {
          target: el.getAttribute("href") || "",
          plan: el.getAttribute("data-plan") || "",
          source: el.getAttribute("data-source") || "",
        });
      });
    });

    document.querySelectorAll("a[href]").forEach(function (el) {
      decorateConversionLink(el, false);
    });

    if (new URLSearchParams(window.location.search).get("checkout") === "success") {
      window.tinyzkpTrack("checkout_returned_success", { source: "stripe_return" });
    }
  });
})();
