#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const source = await readFile(
  path.join(root, "deploy", "cloudflare", "public-beta-site", "_worker.js"),
  "utf8",
);
const workerUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const worker = (await import(workerUrl)).default;
const releaseSha = "a".repeat(40);

function assetsMock() {
  const calls = [];
  return {
    calls,
    async fetch(request) {
      const url = new URL(request.url);
      calls.push(url.toString());
      return new Response(`asset:${url.pathname}`, {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    },
  };
}

function environment(branch = "candidate-release") {
  return {
    ASSETS: assetsMock(),
    CF_PAGES_BRANCH: branch,
    CF_PAGES_COMMIT_SHA: releaseSha,
    TINYZKP_RELEASE_SHA: releaseSha,
  };
}

async function expectAsset(url, branch = "candidate-release") {
  const env = environment(branch);
  const response = await worker.fetch(new Request(url), env);
  assert.equal(response.status, 200, `${url} must serve the staged asset`);
  assert.equal(response.headers.get("Content-Security-Policy")?.includes("default-src 'self'"), true);
  assert.equal(env.ASSETS.calls.length, 1);
  assert.equal(new URL(env.ASSETS.calls[0]).hostname, "tinyzkp.com");
}

async function expectRedirect(url, branch, expected) {
  const env = environment(branch);
  const response = await worker.fetch(new Request(url), env);
  assert.equal(response.status, 308, `${url} must redirect`);
  assert.equal(response.headers.get("Location"), expected);
  assert.equal(env.ASSETS.calls.length, 0);
}

await expectAsset("https://candidate-release.tinyzkp.pages.dev/discovery.json");
await expectAsset("https://a6f5fc44.tinyzkp.pages.dev/status");
await expectAsset("https://tinyzkp.com/pricing", "main");

await expectRedirect(
  "https://candidate-release.tinyzkp.pages.dev/contact",
  "candidate-release",
  "https://candidate-release.tinyzkp.pages.dev/requests",
);
await expectRedirect(
  "https://a6f5fc44.tinyzkp.pages.dev/enterprise",
  "candidate-release",
  "https://a6f5fc44.tinyzkp.pages.dev/pricing",
);
await expectRedirect(
  "https://tinyzkp.pages.dev/status",
  "main",
  "https://tinyzkp.com/status",
);
await expectRedirect(
  "https://attacker.example/status",
  "candidate-release",
  "https://tinyzkp.com/status",
);
await expectRedirect(
  "http://candidate-release.tinyzkp.pages.dev/status",
  "candidate-release",
  "https://tinyzkp.com/status",
);

{
  const env = environment("candidate-release");
  const response = await worker.fetch(
    new Request("https://candidate-release.tinyzkp.pages.dev/research"),
    env,
  );
  assert.equal(response.status, 410);
  assert.equal(env.ASSETS.calls.length, 0);
}

console.log("public beta Pages worker preview policy passed");
