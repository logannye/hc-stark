(function () {
  "use strict";

  var CHECKOUT_CONFIG = "/commerce.json";
  var RELEASE_CONFIG = "/release.json";
  var VALID_CHECKOUT_HOST = /(^|\.)lemonsqueezy\.com$/i;

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
    if (!config || config.schema_version !== 2 || config.checkout_enabled !== true) return null;
    if (config.launch_state !== "qualified" || config.sales_state !== "live") return null;
    if (config.commerce_state !== "public_live" || config.mode !== "live") return null;
    if (config.portal_state !== "live" || config.provider !== "lemon_squeezy") return null;
    if (!/^[1-9][0-9]*$/.test(config.store_id) || !/^[1-9][0-9]*$/.test(config.product_id)) return null;
    if (!release || release.schema_version !== 2 || release.launch_state !== "qualified") return null;
    if (release.sales_state !== "live" || release.commerce_state !== "public_live") return null;
    if (release.portal_state !== "live") return null;
    if (release.checkout_enabled !== true || release.guard_artifact_available !== true) return null;
    if (!Array.isArray(release.blocking_gates) || release.blocking_gates.length !== 0) return null;
    var variant = config.variants && config.variants[cadence];
    if (!variant || variant.reviewed !== true || typeof variant.checkout_url !== "string") return null;
    if (!/^[1-9][0-9]*$/.test(variant.variant_id)) return null;
    if (
      config.variants.annual.variant_id === config.variants.monthly.variant_id
    ) return null;
    try {
      var url = new URL(variant.checkout_url);
      if (url.protocol !== "https:" || !VALID_CHECKOUT_HOST.test(url.hostname)) return null;
      return url.toString();
    } catch (_) {
      return null;
    }
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

  function configureCheckout() {
    keepCheckoutClosed();
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
        document.querySelectorAll("[data-checkout]").forEach(function (control) {
          var url = reviewedCheckout(config, release, control.getAttribute("data-checkout"));
          if (!url) return;
          control.href = url;
          control.removeAttribute("aria-disabled");
          control.removeAttribute("tabindex");
          control.textContent = control.getAttribute("data-live-label") || "Buy Guard";
          control.rel = "noopener noreferrer";
        });
      })
      .catch(function () {
        keepCheckoutClosed();
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
