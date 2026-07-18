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
  const temp = await mkdtemp(path.join(tmpdir(), "tinyzkp-static-worker-"));
  await cp(path.join(root, "site", "_worker.js"), path.join(temp, "_worker.js"));
  await writeFile(path.join(temp, "package.json"), '{"type":"module"}\n');
  const module = await import(pathToFileURL(path.join(temp, "_worker.js")).href);
  return { worker: module.default, cleanup: () => rm(temp, { recursive: true, force: true }) };
}

async function main() {
  const { worker, cleanup } = await importWorker();
  try {
    {
      const assets = assetsMock();
      const response = await worker.fetch(new Request("http://www.tinyzkp.com/docs?x=1"), { ASSETS: assets });
      assert.equal(response.status, 308);
      assert.equal(response.headers.get("Location"), "https://tinyzkp.com/docs?x=1");
      assert.deepEqual(assets.calls, []);
    }

    for (const hostname of [
      "api.tinyzkp.com",
      "mcp.tinyzkp.com",
      "webhook.tinyzkp.com",
    ]) {
      for (const method of ["GET", "POST", "PUT", "DELETE"]) {
        const assets = assetsMock();
        const response = await worker.fetch(new Request(`https://${hostname}/any/path?ignored=1`, {
          method,
          body: new Set(["POST", "PUT"]).has(method) ? "{}" : undefined,
        }), { ASSETS: assets });
        assert.equal(response.status, 410, `${method} ${hostname} must be gone`);
        assert.equal(response.headers.get("Location"), null);
        assert.equal(response.headers.get("X-Robots-Tag"), "noindex, nofollow");
        assert.deepEqual(assets.calls, []);
      }
    }

    {
      const assets = assetsMock(async (request) => new Response(`asset:${new URL(request.url).pathname}`, { status: 200 }));
      const response = await worker.fetch(new Request("https://preview-branch.tinyzkp.pages.dev/guard"), { ASSETS: assets });
      assert.equal(response.status, 200);
      assert.equal(await response.text(), "asset:/guard");
      assert.equal(response.headers.get("X-Robots-Tag"), "noindex, nofollow");
    }

    for (const [source, destination] of [
      ["/engine", "/guard"],
      ["/plonky3", "/compatibility"],
      ["/status", "/releases"],
      ["/contact", "/support"],
    ]) {
      const assets = assetsMock();
      const response = await worker.fetch(new Request(`https://tinyzkp.com${source}`), { ASSETS: assets });
      assert.equal(response.status, 308, `${source} must redirect`);
      assert.equal(response.headers.get("Location"), `https://tinyzkp.com${destination}`);
      assert.deepEqual(assets.calls, []);
    }

    for (const retired of [
      "/compute",
      "/receipts",
      "/mcp",
      "/mcp.json",
      "/requests",
      "/vendor/tinyzkp-verify/tinyzkp-verify.js",
      "/api/contact",
      "/api/create-checkout",
      "/api/release",
      "/functions/api/contact",
      "/.well-known/mcp/server-card.json",
    ]) {
      for (const method of ["GET", "POST"]) {
        const assets = assetsMock();
        const response = await worker.fetch(new Request(`https://tinyzkp.com${retired}`, {
          method,
          body: method === "POST" ? "{}" : undefined,
        }), { ASSETS: assets });
        assert.equal(response.status, 410, `${method} ${retired} must be gone`);
        assert.match(await response.text(), /no longer operates hosted proving/);
        assert.equal(response.headers.get("X-Robots-Tag"), "noindex, nofollow");
        assert.deepEqual(assets.calls, []);
      }
    }

    {
      const assets = assetsMock(async (request) => {
        const pathname = new URL(request.url).pathname;
        if (pathname === "/pricing") return new Response("missing", { status: 404 });
        if (pathname === "/pricing.html") return new Response("pricing", { status: 200 });
        return new Response("missing", { status: 404 });
      });
      const response = await worker.fetch(new Request("https://tinyzkp.com/pricing"), { ASSETS: assets });
      assert.equal(response.status, 200);
      assert.equal(await response.text(), "pricing");
      assert.deepEqual(assets.calls, ["/pricing", "/pricing.html"]);
      assert.match(response.headers.get("Content-Security-Policy"), /connect-src 'self' https:\/\/cloudflareinsights\.com/);
      assert.match(response.headers.get("Content-Security-Policy"), /script-src 'self' https:\/\/static\.cloudflareinsights\.com(?:;|$)/);
      assert.equal(response.headers.get("X-Frame-Options"), "DENY");
    }

    {
      const assets = assetsMock();
      const response = await worker.fetch(new Request("https://tinyzkp.com/not-a-route"), { ASSETS: assets });
      assert.equal(response.status, 404);
      assert.deepEqual(assets.calls, []);
    }

    {
      const assets = assetsMock();
      const response = await worker.fetch(new Request("https://tinyzkp.com/pricing", { method: "POST", body: "{}" }), { ASSETS: assets });
      assert.equal(response.status, 405);
      assert.equal(response.headers.get("Allow"), "GET, HEAD");
      assert.deepEqual(assets.calls, []);
    }

    console.log("PASS static site worker dispatch and retirement policy");
  } finally {
    await cleanup();
  }
}

await main();
