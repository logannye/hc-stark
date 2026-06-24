(function () {
  var ENDPOINT = "/api/events";

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

  window.tinyzkpTrack = function tinyzkpTrack(event, props) {
    try {
      var payload = JSON.stringify({
        event: event,
        path: window.location.pathname,
        props: cleanProps(props),
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

    document.querySelectorAll("[data-track]").forEach(function (el) {
      el.addEventListener("click", function () {
        window.tinyzkpTrack(el.getAttribute("data-track"), {
          target: el.getAttribute("href") || "",
          plan: el.getAttribute("data-plan") || "",
          source: el.getAttribute("data-source") || "",
        });
      });
    });

    if (new URLSearchParams(window.location.search).get("checkout") === "success") {
      window.tinyzkpTrack("checkout_returned_success", { source: "stripe_return" });
    }
  });
})();
