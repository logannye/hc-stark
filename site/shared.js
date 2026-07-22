(function () {
  "use strict";

  var CHECKOUT_CONFIG = "/commerce.json";
  var RELEASE_CONFIG = "/release.json";
  var AUTHORIZATION_POLICY = "owner_only_ga_v1";
  var QUALIFICATION_BASIS = "owner_attested";
  var STORE_HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.lemonsqueezy\.com$/i;
  var CHECKOUT_PATH = /^\/checkout\/buy\/[A-Za-z0-9_-]{8,128}\/?$/;
  var CUSTOM_TERMS = "checkout[custom][terms_version]";
  var CUSTOM_GUARD = "checkout[custom][guard_version]";

  function trustedOwnerContract(value) {
    return (
      value &&
      value.authorization_policy === AUTHORIZATION_POLICY &&
      value.qualification_basis === QUALIFICATION_BASIS
    );
  }

  function storeUrl(value) {
    if (typeof value !== "string" || value.includes("#")) return null;
    try {
      var url = new URL(value);
      if (
        url.protocol !== "https:" ||
        !STORE_HOST.test(url.hostname) ||
        /^(?:api|app|www)\.lemonsqueezy\.com$/i.test(url.hostname) ||
        url.username ||
        url.password ||
        (url.port && url.port !== "443") ||
        url.hash
      ) return null;
      return url;
    } catch (_) {
      return null;
    }
  }

  function reviewedPortal(config, release) {
    if (!config || config.schema_version !== 2 || !trustedOwnerContract(config)) return null;
    if (config.provider !== "lemon_squeezy" || config.portal_state !== "live") return null;
    if (!["live_hidden", "public_live", "sales_frozen"].includes(config.commerce_state)) return null;
    if (!release || release.schema_version !== 2 || !trustedOwnerContract(release)) return null;
    if (release.portal_state !== "live" || release.commerce_state !== config.commerce_state) return null;
    var url = storeUrl(config.customer_portal_url);
    if (!url || url.pathname !== "/billing") return null;
    if (config.customer_portal_url.includes("?") || config.customer_portal_url.includes("#")) return null;
    if (url.hostname !== config.store_hostname || !STORE_HOST.test(config.store_hostname || "")) return null;
    if (url.search || url.hash) return null;
    return url.toString();
  }

  function reviewedCheckoutUrl(value, customData) {
    var url = storeUrl(value);
    if (!url || !CHECKOUT_PATH.test(url.pathname)) return null;
    var pairs = Array.from(url.searchParams.entries());
    if (pairs.length !== 2) return null;
    if (
      url.searchParams.getAll(CUSTOM_TERMS).length !== 1 ||
      url.searchParams.getAll(CUSTOM_GUARD).length !== 1 ||
      url.searchParams.get(CUSTOM_TERMS) !== customData.terms_version ||
      url.searchParams.get(CUSTOM_GUARD) !== customData.guard_version
    ) return null;
    return url;
  }

  function setNavigation() {
    var nav = document.querySelector("[data-site-nav]");
    var button = document.querySelector("[data-nav-toggle]");
    if (!nav || !button) return;

    var current = window.location.pathname.replace(/\/$/, "") || "/";
    nav.querySelectorAll("a[href^='/']").forEach(function (link) {
      var target = new URL(link.href, window.location.origin).pathname.replace(/\/$/, "") || "/";
      if (target === current) link.setAttribute("aria-current", "page");
    });

    button.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      button.setAttribute("aria-expanded", open ? "true" : "false");
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        nav.classList.remove("open");
        button.setAttribute("aria-expanded", "false");
      }
    });
  }

  function reviewedCheckout(config, release, cadence) {
    if (!config || config.schema_version !== 2 || !trustedOwnerContract(config)) return null;
    if (config.checkout_enabled !== true) return null;
    if (config.launch_state !== "qualified" || config.sales_state !== "live") return null;
    if (config.commerce_state !== "public_live" || config.mode !== "live") return null;
    if (config.portal_state !== "live" || config.provider !== "lemon_squeezy") return null;
    if (!/^[1-9][0-9]*$/.test(config.store_id) || !/^[1-9][0-9]*$/.test(config.product_id)) return null;
    if (!STORE_HOST.test(config.store_hostname || "")) return null;
    if (!release || release.schema_version !== 2 || !trustedOwnerContract(release)) return null;
    if (release.launch_state !== "qualified") return null;
    if (release.sales_state !== "live" || release.commerce_state !== "public_live") return null;
    if (release.portal_state !== "live") return null;
    if (release.checkout_enabled !== true || release.guard_artifact_available !== true) return null;
    if (!Array.isArray(release.blocking_gates) || release.blocking_gates.length !== 0) return null;
    if (!reviewedPortal(config, release)) return null;
    var customData = config.checkout_custom_data;
    if (
      !customData ||
      !/^\d{4}-\d{2}-\d{2}$/.test(customData.terms_version) ||
      !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(customData.guard_version) ||
      !release.release_identity ||
      release.release_identity.guard_version !== customData.guard_version
    ) return null;
    var variants = config.variants;
    var variant = variants && variants[cadence];
    if (!variant || variant.reviewed !== true || typeof variant.checkout_url !== "string") return null;
    if (!/^[1-9][0-9]*$/.test(variant.variant_id)) return null;
    if (
      !variants.annual ||
      !variants.monthly ||
      variants.annual.variant_id === variants.monthly.variant_id ||
      variants.annual.checkout_url === variants.monthly.checkout_url
    ) return null;
    var url = reviewedCheckoutUrl(variant.checkout_url, customData);
    var otherCadence = cadence === "annual" ? "monthly" : "annual";
    var other = reviewedCheckoutUrl(variants[otherCadence].checkout_url, customData);
    var portal = storeUrl(config.customer_portal_url);
    if (!url || !other || !portal) return null;
    if (
      url.hostname !== config.store_hostname ||
      other.hostname !== config.store_hostname ||
      portal.hostname !== config.store_hostname
    ) return null;
    return url.toString();
  }

  function keepCheckoutClosed(reasonAnchor) {
    document.querySelectorAll("[data-checkout]").forEach(function (control) {
      control.removeAttribute("href");
      control.setAttribute("aria-disabled", "true");
      control.setAttribute("tabindex", "-1");
      if (typeof reasonAnchor === "string" && reasonAnchor.startsWith("/")) {
        control.setAttribute("data-reason-anchor", reasonAnchor);
        control.setAttribute("title", "Sales are closed. Review the published reason.");
      } else {
        control.removeAttribute("data-reason-anchor");
        control.removeAttribute("title");
      }
      control.textContent = control.getAttribute("data-closed-label") || "Not yet for sale";
    });
  }

  function keepPortalClosed() {
    document.querySelectorAll("[data-portal]").forEach(function (control) {
      control.removeAttribute("href");
      control.setAttribute("aria-disabled", "true");
      control.setAttribute("tabindex", "-1");
      control.textContent = control.getAttribute("data-closed-label") || "Billing portal unavailable";
    });
  }

  function configureCheckout() {
    keepCheckoutClosed();
    keepPortalClosed();
    Promise.all([
      fetch(CHECKOUT_CONFIG, { cache: "no-store", credentials: "same-origin" }),
      fetch(RELEASE_CONFIG, { cache: "no-store", credentials: "same-origin" }),
    ])
      .then(function (responses) {
        if (!responses[0].ok || !responses[1].ok) throw new Error("release configuration unavailable");
        return Promise.all([responses[0].json(), responses[1].json()]);
      })
      .then(function (configs) {
        var config = configs[0];
        var release = configs[1];
        var reasonAnchor =
          config &&
          config.reason_anchors &&
          typeof config.reason_anchors.sales === "string"
            ? config.reason_anchors.sales
            : null;
        keepCheckoutClosed(reasonAnchor);
        keepPortalClosed();
        document.querySelectorAll("[data-checkout]").forEach(function (control) {
          var url = reviewedCheckout(config, release, control.getAttribute("data-checkout"));
          if (!url) return;
          control.href = url;
          control.removeAttribute("aria-disabled");
          control.removeAttribute("tabindex");
          control.textContent = control.getAttribute("data-live-label") || "Buy Guard";
          control.rel = "noopener noreferrer";
        });
        var portalUrl = reviewedPortal(config, release);
        if (portalUrl) {
          document.querySelectorAll("[data-portal]").forEach(function (control) {
            control.href = portalUrl;
            control.removeAttribute("aria-disabled");
            control.removeAttribute("tabindex");
            control.textContent = control.getAttribute("data-live-label") || "Manage billing";
            control.rel = "noopener noreferrer";
          });
        }
      })
      .catch(function () {
        keepCheckoutClosed();
        keepPortalClosed();
      });
  }

  document.documentElement.classList.add("js");
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      setNavigation();
      configureCheckout();
    });
  } else {
    setNavigation();
    configureCheckout();
  }
})();
