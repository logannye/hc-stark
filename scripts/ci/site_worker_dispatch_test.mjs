#!/usr/bin/env node
import assert from "node:assert/strict";
import { mkdtemp, rm, cp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = process.cwd();
const siteDir = path.join(root, "site");

function makeCacheMock() {
  const store = new Map();
  return {
    async match(request) {
      return store.get(request.url) || null;
    },
    async put(request, response) {
      store.set(request.url, response.clone());
    },
  };
}

function makeAssetsMock(handler) {
  const calls = [];
  return {
    calls,
    async fetch(request) {
      calls.push(new URL(request.url).pathname);
      return handler(request);
    },
  };
}

async function importWorker() {
  const tmp = await mkdtemp(path.join(tmpdir(), "tinyzkp-site-worker-"));
  await cp(path.join(siteDir, "_worker.js"), path.join(tmp, "_worker.js"));
  await cp(path.join(siteDir, "functions"), path.join(tmp, "functions"), { recursive: true });
  await writeFile(path.join(tmp, "package.json"), '{"type":"module"}\n');
  const mod = await import(pathToFileURL(path.join(tmp, "_worker.js")).href);
  return { worker: mod.default, cleanup: () => rm(tmp, { recursive: true, force: true }) };
}

async function readJson(response) {
  return JSON.parse(await response.text());
}

async function withFetchMock(handler, fn) {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = input instanceof Request ? input.url : String(input);
    calls.push({ url, init });
    return handler(input, init, calls);
  };
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function checkoutEnv(overrides = {}) {
  return {
    ASSETS: makeAssetsMock(async () => new Response("missing", { status: 404 })),
    STRIPE_SECRET_KEY: "sk_test_checkout",
    STRIPE_PRICE_ID_METERED: "price_metered",
    STRIPE_PRICE_ID_TRACE_STEP_METERED: "price_trace",
    STRIPE_PRICE_ID_DEVELOPER: "price_developer",
    STRIPE_PRICE_ID_PRO: "price_pro",
    STRIPE_PRICE_ID_SCALE: "price_scale",
    STRIPE_PRICE_ID_PILOT: "price_pilot",
    ...overrides,
  };
}

function siteEnv(overrides = {}) {
  return {
    ASSETS: makeAssetsMock(async () => new Response("missing", { status: 404 })),
    INTERNAL_SECRET: "internal-secret",
    WEBHOOK_BASE_URL: "https://webhook.test",
    ...overrides,
  };
}

async function postCheckout(worker, body, envOverrides = {}, ip = "203.0.113.10") {
  const env = checkoutEnv(envOverrides);
  const response = await worker.fetch(
    new Request("https://tinyzkp.com/api/create-checkout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "https://tinyzkp.com",
        "cf-connecting-ip": ip,
      },
      body: JSON.stringify(body),
    }),
    env,
    { waitUntil() {} },
  );
  return { response, env };
}

async function postPilotCheckout(worker, body, envOverrides = {}, ip = "203.0.113.11") {
  const env = checkoutEnv(envOverrides);
  const response = await worker.fetch(
    new Request("https://tinyzkp.com/api/create-pilot-checkout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "https://tinyzkp.com",
        "cf-connecting-ip": ip,
      },
      body: JSON.stringify(body),
    }),
    env,
    { waitUntil() {} },
  );
  return { response, env };
}

async function getPilotCheckoutCapability(worker, envOverrides = {}) {
  const env = checkoutEnv(envOverrides);
  const response = await worker.fetch(
    new Request("https://tinyzkp.com/api/create-pilot-checkout", {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "Origin": "https://tinyzkp.com",
      },
    }),
    env,
    { waitUntil() {} },
  );
  return { response, env };
}

async function postFreeSignup(worker, body, envOverrides = {}, ip = "203.0.113.30") {
  const env = siteEnv(envOverrides);
  const response = await worker.fetch(
    new Request("https://tinyzkp.com/api/create-free-account", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "https://tinyzkp.com",
        "cf-connecting-ip": ip,
      },
      body: JSON.stringify(body),
    }),
    env,
    { waitUntil() {} },
  );
  return { response, env };
}

async function postContact(worker, body, envOverrides = {}, ip = "203.0.113.50") {
  const env = siteEnv(envOverrides);
  const response = await worker.fetch(
    new Request("https://tinyzkp.com/api/contact", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "https://tinyzkp.com",
        "cf-connecting-ip": ip,
      },
      body: JSON.stringify(body),
    }),
    env,
    { waitUntil() {} },
  );
  return { response, env };
}

function stripeParams(call) {
  assert.equal(call.url, "https://api.stripe.com/v1/checkout/sessions");
  assert.equal(call.init.method, "POST");
  assert.equal(call.init.headers.Authorization, "Bearer sk_test_checkout");
  assert.equal(call.init.headers["Content-Type"], "application/x-www-form-urlencoded");
  return new URLSearchParams(call.init.body);
}

function assertSecurityHeaders(response) {
  assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(response.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin");
  assert.equal(response.headers.get("X-Frame-Options"), "DENY");
  assert.equal(response.headers.get("Cross-Origin-Opener-Policy"), "same-origin");
  assert.equal(
    response.headers.get("Permissions-Policy"),
    "camera=(), microphone=(), geolocation=(), payment=()",
  );
}

async function main() {
  globalThis.caches = { default: makeCacheMock() };

  const { worker, cleanup } = await importWorker();
  try {
    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const typoHost = "tny" + "zkp.com";
      const response = await worker.fetch(
        new Request(`https://${typoHost}/research?utm_source=old-card`, { method: "GET" }),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 308);
      assertSecurityHeaders(response);
      assert.equal(response.headers.get("Location"), "https://tinyzkp.com/research?utm_source=old-card");
      assert.equal(response.headers.get("Cache-Control"), "public, max-age=3600");
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const response = await worker.fetch(
        new Request("https://www.tinyzkp.com/docs", { method: "GET" }),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 308);
      assertSecurityHeaders(response);
      assert.equal(response.headers.get("Location"), "https://tinyzkp.com/docs");
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const log = console.log;
      const logs = [];
      console.log = (line) => logs.push(line);
      let response;
      try {
        response = await worker.fetch(
          new Request("https://tinyzkp.com/api/events", {
            method: "POST",
            headers: { "Content-Type": "application/json", "cf-connecting-ip": "203.0.113.101" },
            body: JSON.stringify({
              event: "page_view",
              path: "/docs?email=buyer@example.com&token=tzk_should_not_log_123456",
              props: {
                page: "docs for buyer@example.com",
                path: "/account?api_key=tzk_should_not_log_abcdef",
                target: "https://github.com/logannye/hc-stark?email=buyer@example.com#token",
                reason: `proof ${"a".repeat(80)}`,
                api_key: "tzk_unknown_props_are_dropped",
              },
            }),
          }),
          { ASSETS: assets },
          { waitUntil() {} },
        );
      } finally {
        console.log = log;
      }
      assert.equal(response.status, 200);
      assertSecurityHeaders(response);
      assert.deepEqual(await readJson(response), { ok: true });
      assert.deepEqual(assets.calls, []);
      assert.equal(logs.length, 1);
      const event = JSON.parse(logs[0]);
      assert.equal(event.path, "/docs");
      assert.equal(event.props.path, "/account");
      assert.equal(event.props.target, "https://github.com/logannye/hc-stark");
      assert.equal(event.props.page, "docs for [redacted-email]");
      assert.equal(event.props.reason, "proof [redacted-blob]");
      assert.equal(event.props.api_key, undefined);
      const logged = JSON.stringify(event);
      assert(!logged.includes("buyer@example.com"));
      assert(!logged.includes("tzk_should_not_log"));
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/api/events", { method: "GET" }),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 405);
      assertSecurityHeaders(response);
      assert.equal(response.headers.get("Allow"), "POST, OPTIONS");
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/api/release", { method: "GET" }),
        {
          ASSETS: assets,
          CF_PAGES_COMMIT_SHA: "cf_sha",
          CF_PAGES_BRANCH: "main",
          CF_PAGES_URL: "https://tinyzkp.pages.dev",
        },
        { waitUntil() {} },
      );
      assert.equal(response.status, 200);
      assertSecurityHeaders(response);
      assert.deepEqual(await readJson(response), {
        service: "site",
        package_version: "0.1.0",
        release_sha: "cf_sha",
        release_ref: "main",
        build_url: "https://tinyzkp.pages.dev",
      });
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      await withFetchMock(async (input) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url === "https://api.tinyzkp.com/healthz") {
          return new Response("", { status: 200 });
        }
        throw new Error(`unexpected status probe fetch ${url}`);
      }, async () => {
        const response = await worker.fetch(
          new Request("https://tinyzkp.com/api/status-probe?target=api", { method: "GET" }),
          { ASSETS: assets },
          { waitUntil() {} },
        );
        assert.equal(response.status, 200);
        const data = await readJson(response);
        assert.equal(data.ok, true);
        assert.equal(data.target, "api");
        assert.equal(data.status, 200);
        assert.equal(typeof data.latency_ms, "number");
      });
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      await withFetchMock(async (input) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url === "https://mcp.tinyzkp.com/.well-known/mcp/server-card.json") {
          return new Response('{"name":"tinyzkp"}', { status: 200 });
        }
        throw new Error(`unexpected status probe fetch ${url}`);
      }, async () => {
        const response = await worker.fetch(
          new Request("https://tinyzkp.com/api/status-probe?target=mcp", { method: "GET" }),
          { ASSETS: assets },
          { waitUntil() {} },
        );
        assert.equal(response.status, 200);
        const data = await readJson(response);
        assert.equal(data.ok, true);
        assert.equal(data.marker_ok, true);
      });
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/api/status-probe?target=https://example.com", { method: "GET" }),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 400);
      assert.deepEqual(await readJson(response), { ok: false, error: "unknown target" });
      assert.deepEqual(assets.calls, []);
    }

    {
      // extensionless HTML fallback must serve static pages without hiding API dispatch bugs.
      const assets = makeAssetsMock(async (request) => {
        const pathname = new URL(request.url).pathname;
        if (pathname === "/verify.html") return new Response("verify page", { status: 200 });
        return new Response("missing", { status: 404 });
      });
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/verify", { method: "GET" }),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 200);
      assertSecurityHeaders(response);
      assert.equal(await response.text(), "verify page");
      assert.deepEqual(assets.calls, ["/verify", "/verify.html"]);
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/verify", { method: "POST" }),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 404);
      assertSecurityHeaders(response);
      assert.deepEqual(assets.calls, ["/verify"]);
    }

    {
      const assets = makeAssetsMock(async (request) => {
        const pathname = new URL(request.url).pathname;
        if (pathname === "/shared.css") return new Response("body{}", { status: 200 });
        return new Response("missing", { status: 404 });
      });
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/shared.css", { method: "GET" }),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 200);
      assertSecurityHeaders(response);
      assert.equal(await response.text(), "body{}");
      assert.deepEqual(assets.calls, ["/shared.css"]);
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/api/session-resolve", { method: "POST" }),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 200);
      assert.deepEqual(await readJson(response), { authenticated: false });
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const log = console.log;
      console.log = () => {};
      try {
        let response;
        for (let i = 0; i < 61; i += 1) {
          response = await worker.fetch(
            new Request("https://tinyzkp.com/api/events", {
              method: "POST",
              headers: { "Content-Type": "application/json", "cf-connecting-ip": "203.0.113.199" },
              body: JSON.stringify({ event: "page_view", path: "/docs", props: { page: "Docs" } }),
            }),
            { ASSETS: assets },
            { waitUntil() {} },
          );
        }
        assert.equal(response.status, 204);
        assert.equal(await response.text(), "");
      } finally {
        console.log = log;
      }
      assert.deepEqual(assets.calls, []);
    }

    {
      // Account/billing API routes must be registered in Advanced Mode and must
      // not fall through to static assets when called with the wrong method.
      const registeredPostRoutes = [
        "/api/contact",
        "/api/create-checkout",
        "/api/create-free-account",
        "/api/create-portal-session",
        "/api/events",
        "/api/jobs",
        "/api/logout",
        "/api/reveal-key",
        "/api/rotate-key",
        "/api/send-magic-link",
        "/api/session-resolve",
        "/api/usage",
        "/api/verify-magic-link",
      ];
      for (const route of registeredPostRoutes) {
        const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
        const response = await worker.fetch(
          new Request(`https://tinyzkp.com${route}`, { method: "GET" }),
          { ASSETS: assets },
          { waitUntil() {} },
        );
        assert.equal(response.status, 405, `${route} should be registered and reject GET`);
        assert.deepEqual(assets.calls, [], `${route} should not hit static assets`);
      }
    }

    {
      const sessionGatedRoutes = [
        "/api/create-portal-session",
        "/api/jobs",
        "/api/reveal-key",
        "/api/usage",
      ];
      for (const route of sessionGatedRoutes) {
        const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
        const response = await worker.fetch(
          new Request(`https://tinyzkp.com${route}`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Origin": "https://tinyzkp.com" },
            body: "{}",
          }),
          { ASSETS: assets },
          { waitUntil() {} },
        );
        assert.equal(response.status, 401, `${route} should require a tz_session cookie`);
        assert.deepEqual(await readJson(response), { error: "no session" });
        assert.deepEqual(assets.calls, []);
      }
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const sessionToken = "d".repeat(64);
      await withFetchMock(
        async (input, init, calls) => {
          if (calls.length === 1) {
            assert.equal(String(input), "https://webhook.test/session/resolve");
            assert.equal(init.method, "POST");
            assert.equal(init.headers["X-Internal-Secret"], "internal-secret");
            assert.deepEqual(JSON.parse(init.body), { session_token: sessionToken });
            return new Response(JSON.stringify({ stripe_customer_id: "cus_server_123" }), {
              status: 200,
              headers: { "Content-Type": "application/json" },
            });
          }
          assert.equal(String(input), "https://api.stripe.com/v1/billing_portal/sessions");
          assert.equal(init.method, "POST");
          assert.equal(init.headers.Authorization, "Bearer sk_test_portal");
          const params = new URLSearchParams(init.body);
          assert.equal(params.get("customer"), "cus_server_123");
          assert.equal(params.get("configuration"), "bpc_test");
          assert.equal(params.get("return_url"), "https://tinyzkp.com/account");
          assert.equal(params.has("email"), false);
          assert.notEqual(params.get("customer"), "cus_client_supplied");
          return new Response(JSON.stringify({ url: "https://billing.stripe.test/session" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        },
        async (calls) => {
          const response = await worker.fetch(
            new Request("https://tinyzkp.com/api/create-portal-session", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Origin": "https://tinyzkp.com",
                "Cookie": `tz_session=${sessionToken}`,
                "cf-connecting-ip": "203.0.113.40",
              },
              body: JSON.stringify({
                customer: "cus_client_supplied",
                email: "attacker@example.com",
              }),
            }),
            siteEnv({
              ASSETS: assets,
              STRIPE_SECRET_KEY: "sk_test_portal",
              STRIPE_PORTAL_CONFIG_ID: "bpc_test",
            }),
            { waitUntil() {} },
          );
          assert.equal(response.status, 200);
          assert.deepEqual(await readJson(response), { url: "https://billing.stripe.test/session" });
          assert.equal(calls.length, 2);
          assert.deepEqual(assets.calls, []);
        },
      );
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const sessionToken = "e".repeat(64);
      await withFetchMock(
        async (input, init) => {
          assert.equal(String(input), "https://webhook.test/session/resolve");
          assert.equal(init.method, "POST");
          assert.deepEqual(JSON.parse(init.body), { session_token: sessionToken });
          return new Response(JSON.stringify({ error: "invalid session" }), {
            status: 401,
            headers: { "Content-Type": "application/json" },
          });
        },
        async (calls) => {
          const response = await worker.fetch(
            new Request("https://tinyzkp.com/api/create-portal-session", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Origin": "https://tinyzkp.com",
                "Cookie": `tz_session=${sessionToken}`,
                "cf-connecting-ip": "203.0.113.41",
              },
              body: "{}",
            }),
            siteEnv({ ASSETS: assets, STRIPE_SECRET_KEY: "sk_test_portal" }),
            { waitUntil() {} },
          );
          assert.equal(response.status, 401);
          assert.deepEqual(await readJson(response), { error: "invalid session" });
          assert.match(response.headers.get("Set-Cookie") || "", /^tz_session=;/);
          assert.equal(calls.length, 1);
          assert.deepEqual(assets.calls, []);
        },
      );
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const sessionToken = "f".repeat(64);
      await withFetchMock(
        async (input, init) => {
          assert.equal(String(input), "https://webhook.test/session/reveal-key");
          assert.equal(init.method, "POST");
          assert.equal(init.headers["X-Internal-Secret"], "internal-secret");
          assert.deepEqual(JSON.parse(init.body), { session_token: sessionToken });
          return new Response(JSON.stringify({ api_key: "tzk_revealed" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        },
        async (calls) => {
          const response = await worker.fetch(
            new Request("https://tinyzkp.com/api/reveal-key", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Origin": "https://tinyzkp.com",
                "Cookie": `tz_session=${sessionToken}`,
                "cf-connecting-ip": "203.0.113.42",
              },
              body: "{}",
            }),
            siteEnv({ ASSETS: assets }),
            { waitUntil() {} },
          );
          assert.equal(response.status, 200);
          assert.deepEqual(await readJson(response), { api_key: "tzk_revealed" });
          assert.equal(calls.length, 1);
          assert.deepEqual(assets.calls, []);
        },
      );
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const sessionToken = "1".repeat(64);
      await withFetchMock(
        async (input, init) => {
          assert.equal(String(input), "https://webhook.test/rotate");
          assert.equal(init.method, "POST");
          assert.equal(init.headers["X-Internal-Secret"], "internal-secret");
          assert.deepEqual(JSON.parse(init.body), { session_token: sessionToken });
          return new Response(JSON.stringify({ api_key: "tzk_rotated_session" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        },
        async (calls) => {
          const response = await worker.fetch(
            new Request("https://tinyzkp.com/api/rotate-key", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Origin": "https://tinyzkp.com",
                "Cookie": `tz_session=${sessionToken}`,
                "Authorization": "Bearer tzk_client_should_not_win",
                "cf-connecting-ip": "203.0.113.43",
              },
              body: "{}",
            }),
            siteEnv({ ASSETS: assets }),
            { waitUntil() {} },
          );
          assert.equal(response.status, 200);
          assert.deepEqual(await readJson(response), { api_key: "tzk_rotated_session" });
          assert.equal(calls.length, 1);
          assert.deepEqual(assets.calls, []);
        },
      );
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      await withFetchMock(
        async (input, init) => {
          assert.equal(String(input), "https://webhook.test/rotate");
          assert.equal(init.method, "POST");
          assert.equal(init.headers["X-Internal-Secret"], "internal-secret");
          assert.deepEqual(JSON.parse(init.body), { current_key: "tzk_currentabcdef" });
          return new Response(JSON.stringify({ api_key: "tzk_rotated_bearer" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        },
        async (calls) => {
          const response = await worker.fetch(
            new Request("https://tinyzkp.com/api/rotate-key", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Origin": "https://tinyzkp.com",
                "Authorization": "Bearer tzk_currentabcdef",
                "cf-connecting-ip": "203.0.113.44",
              },
              body: "{}",
            }),
            siteEnv({ ASSETS: assets }),
            { waitUntil() {} },
          );
          assert.equal(response.status, 200);
          assert.deepEqual(await readJson(response), { api_key: "tzk_rotated_bearer" });
          assert.equal(calls.length, 1);
          assert.deepEqual(assets.calls, []);
        },
      );
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/api/logout", {
          method: "POST",
          headers: { "Content-Type": "application/json", "Origin": "https://tinyzkp.com" },
          body: "{}",
        }),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 200);
      assertSecurityHeaders(response);
      assert.deepEqual(await readJson(response), { ok: true });
      assert.match(response.headers.get("Set-Cookie") || "", /^tz_session=;/);
      assert.match(response.headers.get("Set-Cookie") || "", /HttpOnly/);
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = makeAssetsMock(async () => new Response("missing", { status: 404 }));
      const linkToken = "a".repeat(64);
      const sessionToken = "b".repeat(64);
      await withFetchMock(
        async (input, init) => {
          assert.equal(String(input), "https://webhook.test/verify-magic-link");
          assert.equal(init.method, "POST");
          assert.equal(init.headers["X-Internal-Secret"], "internal-secret");
          assert.deepEqual(JSON.parse(init.body), { token: linkToken });
          return new Response(JSON.stringify({
            session_token: sessionToken,
            tenant_id: "t_test",
            email: "user@example.com",
            plan: "free",
            api_key_prefix: "tzk_abcd",
            status: "active",
            api_key: "tzk_should_not_reach_browser",
            stripe_customer_id: "cus_should_not_reach_browser",
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        },
        async (calls) => {
          const response = await worker.fetch(
            new Request("https://tinyzkp.com/api/verify-magic-link", {
              method: "POST",
              headers: { "Content-Type": "application/json", "Origin": "https://tinyzkp.com" },
              body: JSON.stringify({ token: linkToken }),
            }),
            {
              ASSETS: assets,
              WEBHOOK_BASE_URL: "https://webhook.test",
              INTERNAL_SECRET: "internal-secret",
            },
            { waitUntil() {} },
          );
          assert.equal(response.status, 200);
          const body = await readJson(response);
          assert.deepEqual(body, {
            tenant_id: "t_test",
            email: "user@example.com",
            plan: "free",
            api_key_prefix: "tzk_abcd",
            status: "active",
          });
          const cookie = response.headers.get("Set-Cookie") || "";
          assert.match(cookie, new RegExp(`^tz_session=${sessionToken};`));
          assert.match(cookie, /HttpOnly/);
          assert.match(cookie, /Secure/);
          assert.match(cookie, /SameSite=Strict/);
          assert.equal(calls.length, 1);
          assert.deepEqual(assets.calls, []);
        },
      );
    }

    {
      await withFetchMock(
        async () => new Response(JSON.stringify({ url: "https://checkout.stripe.com/c/dev" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
        async (calls) => {
          const { response, env } = await postCheckout(
            worker,
            {
              email: " User@Example.com ",
              plan: " Developer ",
              source: "integration_cursor",
              medium: "mcp_directory",
              campaign: "q3_agent_distribution",
              platform: "cursor",
              use_case: "AI-agent state receipts",
              workflow: "Cursor MCP",
              intent: "developer_signup",
              landing_path: "/integrations/cursor",
              referrer_host: "smithery.ai",
              first_seen_at: "2026-06-25T12:00:00.000Z",
            },
            {},
            "203.0.113.20",
          );
          assert.equal(response.status, 200);
          assert.deepEqual(await readJson(response), { url: "https://checkout.stripe.com/c/dev" });
          const params = stripeParams(calls[0]);
          assert.equal(params.get("mode"), "subscription");
          assert.equal(params.get("customer_email"), "user@example.com");
          assert.equal(params.get("line_items[0][price]"), "price_metered");
          assert.equal(params.get("line_items[1][price]"), "price_developer");
          assert.equal(params.get("line_items[1][quantity]"), "1");
          assert.equal(params.get("line_items[2][price]"), "price_trace");
          assert.equal(params.get("line_items[3][price]"), null);
          assert.equal(params.get("metadata[plan]"), "developer");
          assert.equal(params.get("metadata[cadence]"), "monthly");
          assert.equal(params.get("metadata[source]"), "integration_cursor");
          assert.equal(params.get("metadata[medium]"), "mcp_directory");
          assert.equal(params.get("metadata[campaign]"), "q3_agent_distribution");
          assert.equal(params.get("metadata[platform]"), "cursor");
          assert.equal(params.get("metadata[use_case]"), "AI-agent state receipts");
          assert.equal(params.get("metadata[workflow]"), "Cursor MCP");
          assert.equal(params.get("metadata[intent]"), "developer_signup");
          assert.equal(params.get("metadata[landing_path]"), "/integrations/cursor");
          assert.equal(params.get("metadata[referrer_host]"), "smithery.ai");
          assert.equal(params.get("metadata[first_seen_at]"), "2026-06-25T12:00:00.000Z");
          assert.equal(params.get("subscription_data[metadata][plan]"), "developer");
          assert.equal(params.get("subscription_data[metadata][source]"), "integration_cursor");
          assert.equal(params.get("subscription_data[metadata][referrer_host]"), "smithery.ai");
          const successUrl = new URL(params.get("success_url"));
          assert.equal(successUrl.origin + successUrl.pathname, "https://tinyzkp.com/welcome");
          assert.equal(successUrl.searchParams.get("checkout"), "success");
          assert.equal(successUrl.searchParams.get("plan"), "developer");
          assert.equal(successUrl.searchParams.get("cadence"), "monthly");
          assert.equal(successUrl.searchParams.get("source"), "integration_cursor");
          assert.equal(successUrl.searchParams.get("medium"), "mcp_directory");
          assert.equal(successUrl.searchParams.get("campaign"), "q3_agent_distribution");
          assert.equal(successUrl.searchParams.get("platform"), "cursor");
          assert.equal(successUrl.searchParams.get("use_case"), "AI-agent state receipts");
          assert.equal(successUrl.searchParams.get("workflow"), "Cursor MCP");
          assert.equal(successUrl.searchParams.get("intent"), "developer_signup");
          assert.equal(successUrl.searchParams.get("landing_path"), "/integrations/cursor");
          assert.equal(successUrl.searchParams.get("referrer_host"), "smithery.ai");
          assert.equal(successUrl.searchParams.get("first_seen_at"), "2026-06-25T12:00:00.000Z");
          const cancelUrl = new URL(params.get("cancel_url"));
          assert.equal(cancelUrl.origin + cancelUrl.pathname, "https://tinyzkp.com/signup");
          assert.equal(cancelUrl.searchParams.get("cancelled"), "true");
          assert.equal(cancelUrl.searchParams.get("plan"), "developer");
          assert.equal(cancelUrl.searchParams.get("source"), "integration_cursor");
          assert.equal(cancelUrl.searchParams.get("referrer_host"), "smithery.ai");
          assert.deepEqual(env.ASSETS.calls, []);
          assert.equal(calls.length, 1);
        },
      );
    }

    {
      await withFetchMock(
        async () => new Response(JSON.stringify({ url: "https://checkout.stripe.com/c/compute" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
        async (calls) => {
          const { response } = await postCheckout(
            worker,
            { email: "compute@example.com", plan: "compute" },
            {},
            "203.0.113.21",
          );
          assert.equal(response.status, 200);
          const params = stripeParams(calls[0]);
          assert.equal(params.get("line_items[0][price]"), "price_trace");
          assert.equal(params.get("line_items[1][price]"), null);
          assert.equal(params.get("metadata[plan]"), "compute");
          assert.equal(params.get("subscription_data[metadata][plan]"), "compute");
          assert.equal(params.get("success_url"), "https://tinyzkp.com/welcome?checkout=success&plan=compute&cadence=monthly");
        },
      );
    }

    {
      await withFetchMock(
        async () => {
          throw new Error("Compute checkout should not create a partial session when its trace-step meter is missing");
        },
        async (calls) => {
          const { response } = await postCheckout(
            worker,
            { email: "compute-missing@example.com", plan: "compute" },
            { STRIPE_PRICE_ID_TRACE_STEP_METERED: "" },
            "203.0.113.24",
          );
          assert.equal(response.status, 503);
          assert.deepEqual(await readJson(response), { error: "compute tier not yet available" });
          assert.equal(calls.length, 0);
        },
      );
    }

    {
      await withFetchMock(
        async () => new Response(JSON.stringify({ url: "https://checkout.stripe.com/c/pro" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
        async (calls) => {
          const { response } = await postCheckout(
            worker,
            { email: "team@example.com", plan: "team" },
            {},
            "203.0.113.22",
          );
          assert.equal(response.status, 200);
          const params = stripeParams(calls[0]);
          assert.equal(params.get("line_items[1][price]"), "price_pro");
          assert.equal(params.get("metadata[plan]"), "pro");
          assert.equal(params.get("subscription_data[metadata][plan]"), "pro");
        },
      );
    }

    {
      await withFetchMock(
        async () => {
          throw new Error("Stripe should not be called when a paid plan price binding is missing");
        },
        async (calls) => {
          const { response } = await postCheckout(
            worker,
            { email: "scale@example.com", plan: "scale" },
            { STRIPE_PRICE_ID_SCALE: "" },
            "203.0.113.23",
          );
          assert.equal(response.status, 503);
          assert.deepEqual(await readJson(response), { error: "scale tier not yet available" });
          assert.equal(calls.length, 0);
        },
      );
    }

    {
      const { response } = await getPilotCheckoutCapability(worker);
      assert.equal(response.status, 200);
      assert.deepEqual(await readJson(response), {
        available: true,
        plan: "production_pilot",
        mode: "payment",
        amount: 5000,
        currency: "USD",
        pricing_source: "stripe_price",
        catalog_price_configured: true,
        fallback_url: "https://tinyzkp.com/contact?category=Paid%20Pilot",
      });
    }

    {
      const { response } = await getPilotCheckoutCapability(worker, { STRIPE_PRICE_ID_PILOT: "" });
      assert.equal(response.status, 200);
      assert.deepEqual(await readJson(response), {
        available: true,
        plan: "production_pilot",
        mode: "payment",
        amount: 5000,
        currency: "USD",
        pricing_source: "inline_price_data",
        catalog_price_configured: false,
        fallback_url: "https://tinyzkp.com/contact?category=Paid%20Pilot",
      });
    }

    {
      await withFetchMock(
        async () => new Response(JSON.stringify({ url: "https://checkout.stripe.com/c/pilot" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
        async (calls) => {
          const { response } = await postPilotCheckout(
            worker,
            {
              email: " Pilot@Example.com ",
              source: "agent_offer",
              medium: "llm",
              campaign: "paid_pilot",
              platform: "openai_agents",
              use_case: "AI-agent state receipts",
              workflow: "agent_policy_rollout",
              intent: "paid_pilot_checkout",
              landing_path: "/pilot",
              referrer_host: "chatgpt.com",
              first_seen_at: "2026-06-25T12:00:00.000Z",
              pilot_workflow: "Receipt every payout approval",
            },
            {},
            "203.0.113.25",
          );
          assert.equal(response.status, 200);
          assert.deepEqual(await readJson(response), { url: "https://checkout.stripe.com/c/pilot" });
          const params = stripeParams(calls[0]);
          assert.equal(params.get("mode"), "payment");
          assert.equal(params.get("customer_email"), "pilot@example.com");
          assert.equal(params.get("client_reference_id"), "pilot@example.com");
          assert.equal(params.get("line_items[0][price]"), "price_pilot");
          assert.equal(params.get("line_items[0][quantity]"), "1");
          assert.equal(params.get("line_items[1][price]"), null);
          assert.equal(params.get("metadata[plan]"), "production_pilot");
          assert.equal(params.get("metadata[package]"), "production_pilot");
          assert.equal(params.get("metadata[cadence]"), "one_time");
          assert.equal(params.get("metadata[source]"), "agent_offer");
          assert.equal(params.get("metadata[medium]"), "llm");
          assert.equal(params.get("metadata[campaign]"), "paid_pilot");
          assert.equal(params.get("metadata[platform]"), "openai_agents");
          assert.equal(params.get("metadata[workflow]"), "agent_policy_rollout");
          assert.equal(params.get("metadata[pilot_workflow]"), "Receipt every payout approval");
          assert.equal(params.get("payment_intent_data[metadata][plan]"), "production_pilot");
          assert.equal(params.get("payment_intent_data[metadata][source]"), "agent_offer");
          const successUrl = new URL(params.get("success_url"));
          assert.equal(successUrl.origin + successUrl.pathname, "https://tinyzkp.com/pilot");
          assert.equal(successUrl.searchParams.get("checkout"), "pilot_success");
          assert.equal(successUrl.searchParams.get("plan"), "production_pilot");
          assert.equal(successUrl.searchParams.get("session_id"), "{CHECKOUT_SESSION_ID}");
          assert.equal(successUrl.searchParams.get("source"), "agent_offer");
          assert.equal(successUrl.searchParams.get("pilot_workflow"), "Receipt every payout approval");
          const cancelUrl = new URL(params.get("cancel_url"));
          assert.equal(cancelUrl.origin + cancelUrl.pathname, "https://tinyzkp.com/pilot");
          assert.equal(cancelUrl.searchParams.get("checkout"), "pilot_cancelled");
          assert.equal(cancelUrl.searchParams.get("plan"), "production_pilot");
          assert.equal(calls.length, 1);
        },
      );
    }

    {
      await withFetchMock(
        async () => new Response(JSON.stringify({ url: "https://checkout.stripe.com/c/pilot-inline" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
        async (calls) => {
          const { response } = await postPilotCheckout(
            worker,
            {
              email: "pilot-inline@example.com",
              source: "gtm_execution_ledger",
              medium: "ops",
              intent: "paid_pilot_checkout",
            },
            { STRIPE_PRICE_ID_PILOT: "" },
            "203.0.113.26",
          );
          assert.equal(response.status, 200);
          assert.deepEqual(await readJson(response), { url: "https://checkout.stripe.com/c/pilot-inline" });
          const params = stripeParams(calls[0]);
          assert.equal(params.get("mode"), "payment");
          assert.equal(params.get("customer_email"), "pilot-inline@example.com");
          assert.equal(params.get("line_items[0][price]"), null);
          assert.equal(params.get("line_items[0][price_data][currency]"), "usd");
          assert.equal(params.get("line_items[0][price_data][unit_amount]"), "500000");
          assert.equal(params.get("line_items[0][price_data][product_data][name]"), "TinyZKP Production Pilot");
          assert.equal(
            params.get("line_items[0][price_data][product_data][description]"),
            "14-day scoped TinyZKP proof-receipt workflow pilot, creditable toward annual, platform, or reserved-capacity agreement if converted within 60 days",
          );
          assert.equal(params.get("line_items[0][price_data][product_data][metadata][package]"), "production_pilot");
          assert.equal(params.get("line_items[0][price_data][product_data][metadata][offer]"), "paid_pilot");
          assert.equal(params.get("line_items[0][quantity]"), "1");
          assert.equal(params.get("metadata[source]"), "gtm_execution_ledger");
          assert.equal(params.get("payment_intent_data[metadata][intent]"), "paid_pilot_checkout");
          assert.equal(calls.length, 1);
        },
      );
    }

    {
      await withFetchMock(
        async (input, init) => {
          assert.equal(String(input), "https://webhook.test/provision-free");
          assert.equal(init.method, "POST");
          assert.equal(init.headers["X-Internal-Secret"], "internal-secret");
          assert.deepEqual(JSON.parse(init.body), {
            email: "free@example.com",
            plan: "free",
            source: "templates",
            medium: "organic",
            campaign: "receipt_share_loop",
            workflow: "accumulator_step",
            landing_path: "/try",
            referrer_host: "glama.ai",
            first_seen_at: "2026-06-25T12:10:00.000Z",
          });
          return new Response(JSON.stringify({
            ok: true,
            dashboard_token: "c".repeat(64),
            api_key: "tzk_should_not_reach_browser",
            tenant_id: "t_free",
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        },
        async (calls) => {
          const { response, env } = await postFreeSignup(
            worker,
            {
              email: " Free@Example.com ",
              source: "templates",
              medium: "organic",
              campaign: "receipt_share_loop",
              workflow: "accumulator_step",
              landing_path: "/try",
              referrer_host: "glama.ai",
              first_seen_at: "2026-06-25T12:10:00.000Z",
            },
            {},
            "203.0.113.31",
          );
          assert.equal(response.status, 200);
          assert.deepEqual(await readJson(response), { ok: true, dashboard_token: "c".repeat(64) });
          assert.equal(calls.length, 1);
          assert.deepEqual(env.ASSETS.calls, []);
        },
      );
    }

    {
      await withFetchMock(
        async () => new Response("upstream unavailable", { status: 503 }),
        async () => {
          const errorLog = console.error;
          console.error = () => {};
          let response;
          try {
            ({ response } = await postFreeSignup(
              worker,
              { email: "free-fail@example.com" },
              {},
              "203.0.113.32",
            ));
          } finally {
            console.error = errorLog;
          }
          assert.equal(response.status, 502);
          assert.deepEqual(await readJson(response), {
            error: "Account creation failed.",
            upstream_status: 503,
          });
        },
      );
    }

    {
      await withFetchMock(
        async (input, init) => {
          assert.equal(String(input), "https://webhook.test/send-contact");
          assert.equal(init.method, "POST");
          assert.equal(init.headers["X-Internal-Secret"], "internal-secret");
          assert.deepEqual(JSON.parse(init.body), {
            name: "Agent Buyer",
            email: "agent@example.com",
            category: "Platform Rollout",
            message: "We want proof receipts in our agent platform.",
            qualification: {
              source: "integration_openai_agents",
              platform: "openai_agents",
              plan: "scale",
              workflow: "Backend tool receipt",
              intent: "platform_rollout",
              current_path: "/contact",
              referrer: "https://tinyzkp.com/integrations/openai-agents",
              use_case: "AI-agent state receipts",
              verification_environment: "AI agent / MCP",
            },
          });
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        },
        async (calls) => {
          const { response, env } = await postContact(
            worker,
            {
              name: "Agent Buyer",
              email: "Agent@Example.com",
              category: "Platform Rollout",
              message: "We want proof receipts in our agent platform.",
              context: {
                source: "integration_openai_agents",
                platform: "openai_agents",
                current_path: "/contact",
                referrer: "https://tinyzkp.com/integrations/openai-agents",
              },
              qualification: {
                plan: "scale",
                workflow: "Backend tool receipt",
                intent: "platform_rollout",
                use_case: "AI-agent state receipts",
                verification_environment: "AI agent / MCP",
                ignored: "drop me",
              },
            },
            {},
            "203.0.113.51",
          );
          assert.equal(response.status, 200);
          assert.deepEqual(await readJson(response), { ok: true });
          assert.equal(calls.length, 1);
          assert.deepEqual(env.ASSETS.calls, []);
        },
      );
    }
  } finally {
    await cleanup();
  }

  console.log("PASS site worker dispatch test");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
