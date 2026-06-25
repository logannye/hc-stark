#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync("site/analytics.js", "utf8");

class FakeAnchor {
  constructor(attrs) {
    this.attrs = new Map(Object.entries(attrs));
    this.listeners = new Map();
  }

  getAttribute(name) {
    return this.attrs.get(name) || "";
  }

  setAttribute(name, value) {
    this.attrs.set(name, value);
  }

  addEventListener(name, callback) {
    this.listeners.set(name, callback);
  }

  click() {
    const callback = this.listeners.get("click");
    if (callback) callback();
  }
}

function makeLocalStorage(initial = {}) {
  const store = new Map();
  if (Object.keys(initial).length) {
    store.set("tinyzkp_attribution", JSON.stringify(initial));
  }
  return {
    getItem(key) {
      return store.has(key) ? store.get(key) : null;
    },
    setItem(key, value) {
      store.set(key, String(value));
    },
    readAttribution() {
      return JSON.parse(store.get("tinyzkp_attribution") || "{}");
    },
  };
}

function runAnalytics({ url = "https://tinyzkp.com/", referrer = "", stored = {}, anchors = [] } = {}) {
  const parsed = new URL(url);
  const localStorage = makeLocalStorage(stored);
  let domReady;
  const document = {
    referrer,
    title: "TinyZKP",
    addEventListener(name, callback) {
      if (name === "DOMContentLoaded") domReady = callback;
    },
    querySelectorAll(selector) {
      if (selector === "[data-track]") return anchors.filter((anchor) => anchor.getAttribute("data-track"));
      if (selector === "a[data-source][href]") {
        return anchors.filter((anchor) => anchor.getAttribute("data-source") && anchor.getAttribute("href"));
      }
      if (selector === "a[href]") return anchors.filter((anchor) => anchor.getAttribute("href"));
      return [];
    },
  };
  const window = {
    location: {
      search: parsed.search,
      origin: parsed.origin,
      pathname: parsed.pathname,
      hostname: parsed.hostname,
    },
  };

  const context = {
    Blob,
    URL,
    URLSearchParams,
    document,
    window,
    localStorage,
    navigator: { sendBeacon: () => true },
    fetch: async () => ({ ok: true }),
  };
  vm.runInNewContext(source, context, { filename: "site/analytics.js" });
  assert.equal(typeof domReady, "function");
  domReady();
  return { anchors, localStorage, window };
}

{
  const signup = new FakeAnchor({
    href: "/signup?plan=pro",
    "data-source": "homepage_pricing",
    "data-track": "signup_plan_selected",
    "data-plan": "pro",
  });
  const { localStorage } = runAnalytics({ anchors: [signup] });

  assert.equal(
    signup.getAttribute("href"),
    "/signup?plan=pro&source=homepage_pricing&medium=site&campaign=homepage_pricing&platform=website&intent=api_key",
  );
  assert.equal(localStorage.readAttribution().source, undefined);

  signup.click();
  assert.equal(localStorage.readAttribution().source, "homepage_pricing");
  assert.equal(localStorage.readAttribution().medium, "site");
}

{
  const signup = new FakeAnchor({
    href: "/signup?plan=developer",
    "data-source": "homepage_pricing",
    "data-track": "signup_plan_selected",
    "data-plan": "developer",
  });
  runAnalytics({
    stored: {
      source: "smithery_mcp",
      medium: "mcp_directory",
      platform: "smithery",
      landing_path: "/mcp",
      first_seen_at: "2026-06-25T00:00:00.000Z",
    },
    anchors: [signup],
  });

  assert.equal(
    signup.getAttribute("href"),
    "/signup?plan=developer&source=smithery_mcp&medium=mcp_directory&campaign=homepage_pricing&platform=smithery&intent=api_key",
  );
  signup.click();
  assert.equal(signup.getAttribute("href"), "/signup?plan=developer&source=smithery_mcp&medium=mcp_directory&campaign=homepage_pricing&platform=smithery&intent=api_key");
}

{
  const signup = new FakeAnchor({
    href: "/signup",
    "data-source": "pricing_hero",
    "data-track": "signup_plan_selected",
  });
  const { localStorage } = runAnalytics({
    referrer: "https://news.ycombinator.com/item?id=1",
    anchors: [signup],
  });

  assert.equal(
    signup.getAttribute("href"),
    "/signup?campaign=pricing_hero&platform=website&intent=api_key",
  );
  assert.equal(localStorage.readAttribution().source, undefined);
  assert.equal(localStorage.readAttribution().referrer_host, "news.ycombinator.com");
}

{
  const pilot = new FakeAnchor({ href: "/pilot" });
  const { localStorage } = runAnalytics({
    url: "https://tinyzkp.com/agent-platforms",
    anchors: [pilot],
  });

  assert.equal(
    pilot.getAttribute("href"),
    "/pilot?source=site_agent_platforms&medium=site&campaign=site_agent_platforms&platform=website&intent=paid_pilot",
  );
  assert.equal(localStorage.readAttribution().source, undefined);
}

{
  const pilot = new FakeAnchor({ href: "/pilot" });
  const { localStorage } = runAnalytics({
    url: "https://tinyzkp.com/pricing",
    referrer: "https://news.ycombinator.com/item?id=2",
    anchors: [pilot],
  });

  assert.equal(pilot.getAttribute("href"), "/pilot?intent=paid_pilot");
  assert.equal(localStorage.readAttribution().source, undefined);
  assert.equal(localStorage.readAttribution().referrer_host, "news.ycombinator.com");
}

console.log("PASS analytics attribution handoff");
