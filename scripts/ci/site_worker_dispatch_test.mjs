#!/usr/bin/env node
import assert from "node:assert/strict";
import { cp, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = process.cwd();

function assetsMock(handler = async () => new Response("missing", { status: 404 })) {
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
  const temp = await mkdtemp(path.join(tmpdir(), "tinyzkp-worker-"));
  await cp(path.join(root, "site", "_worker.js"), path.join(temp, "_worker.js"));
  await cp(path.join(root, "site", "functions"), path.join(temp, "functions"), { recursive: true });
  await writeFile(path.join(temp, "package.json"), '{"type":"module"}\n');
  const module = await import(pathToFileURL(path.join(temp, "_worker.js")).href);
  return { worker: module.default, cleanup: () => rm(temp, { recursive: true, force: true }) };
}

async function json(response) {
  return JSON.parse(await response.text());
}

async function main() {
  globalThis.caches = { default: { async match() { return null; }, async put() {} } };
  const { worker, cleanup } = await importWorker();
  try {
    {
      const assets = assetsMock();
      const response = await worker.fetch(
        new Request("http://www.tinyzkp.com/docs?x=1"),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 308);
      assert.equal(response.headers.get("Location"), "https://tinyzkp.com/docs?x=1");
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = assetsMock();
      const response = await worker.fetch(
        new Request("https://preview-branch.tinyzkp.pages.dev/vendor/tinyzkp-verify/tinyzkp-verify.js"),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 308);
      assert.equal(
        response.headers.get("Location"),
        "https://tinyzkp.com/vendor/tinyzkp-verify/tinyzkp-verify.js",
      );
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = assetsMock(async (request) => {
        const pathname = new URL(request.url).pathname;
        return new Response(`asset:${pathname}`, { status: 200 });
      });
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/api/release"),
        {
          ASSETS: assets,
          TINYZKP_RELEASE_SHA: "abc123",
          TINYZKP_RELEASE_REF: "main",
        },
        { waitUntil() {} },
      );
      assert.equal(response.status, 200);
      const body = await json(response);
      assert.equal(body.service, "site");
      assert.equal(body.release_sha, "abc123");
      assert.equal(body.release_ref, "main");
      assert.equal(body.asset_manifest_complete, true);
      assert.match(body.asset_manifest_sha256, /^[0-9a-f]{64}$/);
      assert.equal(assets.calls.length, 10);
    }

    for (const [source, destination] of [
      ["/compute", "/engine"],
      ["/receipts", "/engine"],
      ["/try", "/benchmarks"],
      ["/signup", "/contact?intent=memory_bounded_evaluation"],
      ["/pilot", "/pricing"],
      ["/platform-rollout", "/pricing"],
    ]) {
      const assets = assetsMock();
      const response = await worker.fetch(
        new Request(`https://tinyzkp.com${source}`),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 308, `${source} must redirect`);
      assert.equal(response.headers.get("Location"), `https://tinyzkp.com${destination}`);
      assert.deepEqual(assets.calls, []);
    }

    for (const retired of [
      "/agents", "/agents.html", "/agent-policy", "/agent-policy.json", "/roi",
      "/roi.json", "/calculator", "/use-cases", "/compare/foo", "/integrations",
      "/mcp.json", "/.well-known/tinyzkp-offers.json",
      "/.well-known/mcp/server-card.json",
      "/vendor/tinyzkp-verify/tinyzkp-verify.js",
      "/vendor/tinyzkp-verify/tinyzkp-verify_bg.wasm",
    ]) {
      const assets = assetsMock();
      const response = await worker.fetch(
        new Request(`https://tinyzkp.com${retired}`),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 410, `${retired} must be gone`);
      assert.match(await response.text(), /resource-bounded Plonky3/);
      assert.equal(response.headers.get("X-Robots-Tag"), "noindex, nofollow");
      assert.deepEqual(assets.calls, []);
    }

    const disabled = [
      "/api/create-checkout",
      "/api/create-free-account",
      "/api/create-pilot-checkout",
      "/api/demo-poll",
      "/api/demo-prove",
      "/api/demo-verify",
    ];
    for (const route of disabled) {
      for (const method of ["GET", "POST"]) {
        const assets = assetsMock();
        const originalFetch = globalThis.fetch;
        let upstreamCalls = 0;
        globalThis.fetch = async () => { upstreamCalls += 1; throw new Error("disabled route called upstream"); };
        try {
          const request = new Request(`https://tinyzkp.com${route}`, {
            method,
            headers: method === "POST" ? { "Content-Type": "application/json" } : undefined,
            body: method === "POST" ? "{}" : undefined,
          });
          const response = await worker.fetch(request, { ASSETS: assets }, { waitUntil() {} });
          assert.equal(response.status, 503, `${route} must fail closed`);
          assert.equal((await json(response)).code, "protocol_upgrade");
          assert.equal(upstreamCalls, 0);
          assert.deepEqual(assets.calls, []);
        } finally {
          globalThis.fetch = originalFetch;
        }
      }
    }

    {
      const assets = assetsMock();
      const originalFetch = globalThis.fetch;
      let upstreamCalls = 0;
      globalThis.fetch = async () => { upstreamCalls += 1; throw new Error("unexpected upstream"); };
      try {
        const response = await worker.fetch(
          new Request("https://tinyzkp.com/api/contact", {
            method: "POST",
            headers: { "Content-Type": "application/json", Origin: "https://attacker.example" },
            body: JSON.stringify({ name: "Bot", email: "bot@example.com", message: "spam" }),
          }),
          { ASSETS: assets },
          { waitUntil() {} },
        );
        assert.equal(response.status, 403);
        assert.equal(upstreamCalls, 0);
      } finally {
        globalThis.fetch = originalFetch;
      }
    }

    {
      const assets = assetsMock();
      const originalFetch = globalThis.fetch;
      const calls = [];
      globalThis.fetch = async (input, init) => {
        calls.push({ url: String(input), init });
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      };
      try {
        const response = await worker.fetch(
          new Request("https://tinyzkp.com/api/contact", {
            method: "POST",
            headers: { "Content-Type": "application/json", Origin: "https://tinyzkp.com" },
            body: JSON.stringify({
              name: "Proving Lead",
              category: "Design Partner",
              message: "Reproducible public workload",
              qualification: {
                company: "Example",
                stack: "Plonky3 0.6.1",
                workload: "Poseidon2 AIR",
                logical_rows: "1048576",
                current_memory: "OOM at 16 GiB",
                target_ram: "2 GiB",
                scratch: "100 GiB local NVMe",
                verifier_target: "Unmodified Plonky3 verifier",
                data_sensitivity: "Public deterministic generator",
                technical_owner: "Proving Lead",
                budget_owner: "CTO",
                timeline: "This quarter",
                contact_method: "github",
                contact_handle: "https://github.com/example",
                consent: "twelve_month_retention",
                secret: "must-not-forward",
              },
            }),
          }),
          { ASSETS: assets, WEBHOOK_BASE_URL: "https://webhook.test", INTERNAL_SECRET: "internal" },
          { waitUntil() {} },
        );
        assert.equal(response.status, 200);
        assert.equal(calls.length, 1);
        assert.equal(calls[0].url, "https://webhook.test/send-contact");
        const forwarded = JSON.parse(calls[0].init.body);
        assert.equal(forwarded.qualification.stack, "Plonky3 0.6.1");
        assert.equal(forwarded.qualification.consent, "twelve_month_retention");
        assert.equal(forwarded.qualification.contact_method, "github");
        assert.equal(forwarded.qualification.contact_handle, "https://github.com/example");
        assert.equal(forwarded.qualification.secret, undefined);
        assert.equal(forwarded.email, undefined);
        assert.deepEqual(assets.calls, []);
      } finally {
        globalThis.fetch = originalFetch;
      }
    }

    {
      const assets = assetsMock();
      const originalFetch = globalThis.fetch;
      const calls = [];
      globalThis.fetch = async (input, init) => {
        calls.push({ url: String(input), init });
        return new Response(JSON.stringify({ ok: true, application_id: "eval_test" }), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        });
      };
      try {
        const response = await worker.fetch(
          new Request("https://tinyzkp.com/api/contact", {
            method: "POST",
            headers: { "Content-Type": "application/json", Origin: "https://tinyzkp.com" },
            body: JSON.stringify({
              name: "No Email Applicant",
              category: "Security Report",
              message: "Reproducible public workload",
              qualification: {
                contact_method: "github",
                contact_handle: "https://github.com/example",
                consent: "twelve_month_retention",
              },
            }),
          }),
          { ASSETS: assets, WEBHOOK_BASE_URL: "https://webhook.test", INTERNAL_SECRET: "internal" },
          { waitUntil() {} },
        );
        assert.equal(response.status, 200);
        assert.equal(calls.length, 1);
        const forwarded = JSON.parse(calls[0].init.body);
        assert.equal(forwarded.email, undefined);
        assert.equal(forwarded.qualification.contact_method, "github");
      } finally {
        globalThis.fetch = originalFetch;
      }
    }

    {
      const assets = assetsMock();
      const originalFetch = globalThis.fetch;
      let upstreamCalls = 0;
      globalThis.fetch = async () => {
        upstreamCalls += 1;
        throw new Error("email-bearing intake must not reach the webhook");
      };
      try {
        const response = await worker.fetch(
          new Request("https://tinyzkp.com/api/contact", {
            method: "POST",
            headers: { "Content-Type": "application/json", Origin: "https://tinyzkp.com" },
            body: JSON.stringify({
              name: "Email Applicant",
              email: "lead@example.com",
              category: "General Inquiry",
              message: "This payload must be rejected",
              qualification: {
                contact_method: "github",
                contact_handle: "https://github.com/example",
                consent: "twelve_month_retention",
              },
            }),
          }),
          { ASSETS: assets, WEBHOOK_BASE_URL: "https://webhook.test", INTERNAL_SECRET: "internal" },
          { waitUntil() {} },
        );
        assert.equal(response.status, 400);
        assert.equal((await json(response)).error, "email fields are not accepted");
        assert.equal(upstreamCalls, 0);
      } finally {
        globalThis.fetch = originalFetch;
      }
    }

    for (const route of ["/api/create-portal-session", "/api/jobs", "/api/reveal-key", "/api/usage"]) {
      const assets = assetsMock();
      const response = await worker.fetch(
        new Request(`https://tinyzkp.com${route}`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Origin: "https://tinyzkp.com" },
          body: "{}",
        }),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 404, `${route} must be absent from the recovery worker`);
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = assetsMock(async (request) => {
        const pathname = new URL(request.url).pathname;
        if (pathname === "/status.html") return new Response("backend recovery", { status: 200 });
        return new Response("missing", { status: 404 });
      });
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/status"),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 200);
      assert.equal(await response.text(), "backend recovery");
      assert.deepEqual(assets.calls, ["/status", "/status.html"]);
      assert.equal(response.headers.get("X-Frame-Options"), "DENY");
    }

    {
      const assets = assetsMock(async () => new Response("homepage fallback", { status: 200 }));
      const response = await worker.fetch(
        new Request("https://tinyzkp.com/totally-nonexistent-audit-path"),
        { ASSETS: assets },
        { waitUntil() {} },
      );
      assert.equal(response.status, 404);
      assert.equal(await response.text(), "not found");
      assert.deepEqual(assets.calls, []);
    }

    console.log("site worker maintenance dispatch: PASS");
  } finally {
    await cleanup();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
