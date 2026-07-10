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
      assert.deepEqual(assets.calls, []);
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
      "/vendor/tinyzkp-verify/tinyzkp-verify.js",
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
              email: "lead@example.com",
              category: "Design Partner",
              message: "Reproducible public workload",
              qualification: {
                company: "Example",
                stack: "Plonky3 0.6.1",
                logical_rows: "1048576",
                current_memory: "OOM at 16 GiB",
                target_ram: "2 GiB",
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
        assert.equal(forwarded.qualification.secret, undefined);
        assert.deepEqual(assets.calls, []);
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

    console.log("site worker maintenance dispatch: PASS");
  } finally {
    await cleanup();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
