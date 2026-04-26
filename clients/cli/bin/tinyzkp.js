#!/usr/bin/env node
// @tinyzkp/cli — generate and verify TinyZKP zero-knowledge proofs.
//
// Usage examples:
//   npx tinyzkp templates
//   npx tinyzkp prove range_proof '{"min":0,"max":100,"witness_steps":[42,44]}'
//   npx tinyzkp poll prf_a1b2c3
//   npx tinyzkp verify proof.json
//   npx tinyzkp estimate range_proof '{"min":0,"max":100,"witness_steps":[42,44]}'
//   npx tinyzkp healthz
//
// API key resolution order:
//   1. --api-key flag
//   2. TINYZKP_API_KEY env var
//   3. ~/.tinyzkp/credentials (TINYZKP_API_KEY=tzk_... line)
//
// Base URL override:
//   --base-url=https://staging.tinyzkp.com  (or TINYZKP_API_URL env var)

import { promises as fs } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

// ── Color helpers (no chalk dep) ──────────────────────────────────────

const isTTY = process.stdout.isTTY;
const c = {
  reset: (s) => isTTY ? `\x1b[0m${s}\x1b[0m` : s,
  bold: (s) => isTTY ? `\x1b[1m${s}\x1b[22m` : s,
  dim: (s) => isTTY ? `\x1b[2m${s}\x1b[22m` : s,
  red: (s) => isTTY ? `\x1b[31m${s}\x1b[39m` : s,
  green: (s) => isTTY ? `\x1b[32m${s}\x1b[39m` : s,
  yellow: (s) => isTTY ? `\x1b[33m${s}\x1b[39m` : s,
  cyan: (s) => isTTY ? `\x1b[36m${s}\x1b[39m` : s,
  magenta: (s) => isTTY ? `\x1b[35m${s}\x1b[39m` : s,
};

// ── Argument parsing ──────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { _: [], flags: {} };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > -1) {
        args.flags[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next && !next.startsWith('--')) {
          args.flags[a.slice(2)] = next;
          i++;
        } else {
          args.flags[a.slice(2)] = true;
        }
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

// ── Config resolution ─────────────────────────────────────────────────

async function resolveApiKey(flags) {
  if (flags['api-key']) return flags['api-key'];
  if (process.env.TINYZKP_API_KEY) return process.env.TINYZKP_API_KEY;
  try {
    const credPath = join(homedir(), '.tinyzkp', 'credentials');
    const txt = await fs.readFile(credPath, 'utf8');
    const m = txt.match(/^TINYZKP_API_KEY=(.+)$/m);
    if (m) return m[1].trim();
  } catch {} // file missing is fine
  return null;
}

function resolveBaseUrl(flags) {
  return flags['base-url']
    || process.env.TINYZKP_API_URL
    || 'https://api.tinyzkp.com';
}

// ── HTTP helpers ──────────────────────────────────────────────────────

async function httpRequest(method, url, { headers = {}, body, apiKey } = {}) {
  const reqHeaders = { ...headers };
  if (apiKey) reqHeaders['Authorization'] = `Bearer ${apiKey}`;
  if (body) reqHeaders['Content-Type'] = 'application/json';
  reqHeaders['User-Agent'] = `tinyzkp-cli/0.1.0 (node ${process.version})`;
  const t0 = Date.now();
  let resp;
  try {
    resp = await fetch(url, {
      method,
      headers: reqHeaders,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    return { ok: false, status: 0, json: { error: `network: ${e.message}` }, elapsed: Date.now() - t0 };
  }
  const elapsed = Date.now() - t0;
  let json;
  try {
    json = await resp.json();
  } catch {
    json = { error: `non-JSON response (HTTP ${resp.status})` };
  }
  return { ok: resp.ok, status: resp.status, json, elapsed };
}

// ── Output helpers ────────────────────────────────────────────────────

function jsonOutput(flags) { return Boolean(flags.json); }

function emit(flags, prettyFn, jsonObj) {
  if (jsonOutput(flags)) {
    console.log(JSON.stringify(jsonObj, null, 2));
  } else {
    prettyFn();
  }
}

function die(msg, code = 1) {
  console.error(c.red('✘ ') + msg);
  process.exit(code);
}

// ── Subcommands ───────────────────────────────────────────────────────

async function cmdHealthz(args) {
  const base = resolveBaseUrl(args.flags);
  const r = await httpRequest('GET', `${base}/healthz`);
  emit(args.flags, () => {
    if (r.ok) console.log(c.green('✔ ') + `${base}/healthz: HTTP ${r.status} (${r.elapsed} ms)`);
    else console.log(c.red('✘ ') + `${base}/healthz: HTTP ${r.status} (${r.elapsed} ms)`);
  }, { ok: r.ok, status: r.status, elapsed_ms: r.elapsed, body: r.json });
  if (!r.ok) process.exit(1);
}

async function cmdTemplates(args) {
  const base = resolveBaseUrl(args.flags);
  const r = await httpRequest('GET', `${base}/templates`);
  if (!r.ok) die(`failed to list templates: HTTP ${r.status} ${JSON.stringify(r.json)}`);
  const templates = r.json.templates || [];
  emit(args.flags, () => {
    console.log(c.bold('Available proof templates:\n'));
    for (const t of templates) {
      const tag = t.backend ? c.dim(` [${t.backend}]`) : '';
      const cost = t.cost_category ? c.dim(` (${t.cost_category})`) : '';
      console.log(`  ${c.cyan(t.id)}${tag}${cost}`);
      if (t.summary) console.log(`    ${t.summary}`);
    }
    console.log();
    console.log(c.dim(`Total: ${templates.length} templates`));
    console.log(c.dim(`Describe one: tinyzkp describe <id>`));
  }, r.json);
}

async function cmdDescribe(args) {
  const id = args._[1];
  if (!id) die('usage: tinyzkp describe <template-id>');
  const base = resolveBaseUrl(args.flags);
  const r = await httpRequest('GET', `${base}/templates/${encodeURIComponent(id)}`);
  if (!r.ok) die(`unknown template '${id}'`);
  emit(args.flags, () => {
    console.log(c.bold(c.cyan(r.json.id)));
    if (r.json.backend) console.log(c.dim(`backend: ${r.json.backend}`));
    if (r.json.summary) console.log('\n' + r.json.summary);
    if (r.json.description) console.log('\n' + c.dim(r.json.description));
    if (Array.isArray(r.json.parameters) && r.json.parameters.length) {
      console.log('\n' + c.bold('Parameters:'));
      for (const p of r.json.parameters) {
        const req = p.required ? c.red('required') : c.dim('optional');
        console.log(`  ${c.cyan(p.name)} ${c.dim('(' + p.param_type + ')')} ${req}`);
        if (p.description) console.log(`    ${p.description}`);
      }
    }
    if (r.json.example) {
      console.log('\n' + c.bold('Example:'));
      console.log('  ' + JSON.stringify(r.json.example).replace(/\n/g, '\n  '));
    }
  }, r.json);
}

async function cmdEstimate(args) {
  const id = args._[1];
  const params = args._[2];
  if (!id || !params) die('usage: tinyzkp estimate <template-id> \'{"json":"params"}\'');
  let parsed;
  try { parsed = JSON.parse(params); } catch (e) { die(`invalid JSON params: ${e.message}`); }
  const base = resolveBaseUrl(args.flags);
  const r = await httpRequest('POST', `${base}/estimate`, {
    body: { template_id: id, params: parsed },
  });
  if (!r.ok) die(`estimate failed: HTTP ${r.status} ${JSON.stringify(r.json)}`);
  emit(args.flags, () => {
    console.log(c.bold('Estimate'));
    if (r.json.trace_length != null) console.log(`  trace length:    ${c.cyan(r.json.trace_length.toLocaleString())} steps`);
    if (r.json.estimated_cost_cents != null) console.log(`  cost (Developer): ${c.cyan('$' + (r.json.estimated_cost_cents / 100).toFixed(2))}`);
    if (r.json.estimated_proof_size_kb != null) console.log(`  proof size:      ${c.cyan(r.json.estimated_proof_size_kb)} KB`);
    if (r.json.estimated_prove_ms != null) console.log(`  prove time:      ${c.cyan(r.json.estimated_prove_ms + ' ms')}`);
  }, r.json);
}

async function cmdProve(args) {
  const id = args._[1];
  const paramsArg = args._[2];
  if (!id || !paramsArg) die('usage: tinyzkp prove <template-id> \'{"json":"params"}\'  (or pass a path to a JSON file)');
  let parsed;
  // Accept either inline JSON or a file path.
  let raw = paramsArg;
  try {
    raw = await fs.readFile(paramsArg, 'utf8');
  } catch {} // fall through if not a file
  try { parsed = JSON.parse(raw); } catch (e) { die(`invalid JSON params: ${e.message}`); }
  const apiKey = await resolveApiKey(args.flags);
  if (!apiKey) die('TINYZKP_API_KEY not set. Get a free key at https://tinyzkp.com/signup');
  const base = resolveBaseUrl(args.flags);
  const r = await httpRequest('POST', `${base}/prove/template/${encodeURIComponent(id)}`, {
    body: { params: parsed, ...(args.flags.zk ? { zk: true } : {}) },
    apiKey,
  });
  if (!r.ok) die(`prove submit failed: HTTP ${r.status} ${JSON.stringify(r.json)}`);
  const jobId = r.json.job_id;
  if (!args.flags.wait && !jsonOutput(args.flags)) {
    console.log(c.green('✔ ') + `submitted job ${c.cyan(jobId)}`);
    console.log(c.dim(`  poll: tinyzkp poll ${jobId}`));
    return;
  }
  if (args.flags.wait) {
    return await pollUntilComplete(args, jobId);
  }
  emit(args.flags, () => console.log(c.cyan(jobId)), r.json);
}

async function pollUntilComplete(args, jobId) {
  const apiKey = await resolveApiKey(args.flags);
  const base = resolveBaseUrl(args.flags);
  const deadline = Date.now() + (parseInt(args.flags.timeout, 10) || 300) * 1000;
  if (!jsonOutput(args.flags)) process.stderr.write(c.dim(`waiting on ${jobId}`));
  while (Date.now() < deadline) {
    if (!jsonOutput(args.flags)) process.stderr.write(c.dim('.'));
    const r = await httpRequest('GET', `${base}/prove/${encodeURIComponent(jobId)}`, { apiKey });
    if (!r.ok) die(`\npoll failed: HTTP ${r.status} ${JSON.stringify(r.json)}`);
    const status = r.json.status;
    if (status === 'completed') {
      if (!jsonOutput(args.flags)) process.stderr.write('\n');
      emit(args.flags, () => {
        console.log(c.green('✔ ') + `proof completed (${jobId})`);
        if (r.json.proof) {
          console.log(c.dim('  version: ') + r.json.proof.version);
          if (r.json.proof.size_kb != null) console.log(c.dim('  size:    ') + r.json.proof.size_kb + ' KB');
          if (r.json.proof.bytes) {
            const b = r.json.proof.bytes;
            const preview = typeof b === 'string' ? (b.slice(0, 60) + (b.length > 60 ? '...' : '')) : '<binary>';
            console.log(c.dim('  bytes:   ') + preview);
          }
        }
      }, r.json);
      return;
    }
    if (status === 'failed') {
      if (!jsonOutput(args.flags)) process.stderr.write('\n');
      die(`proof failed: ${r.json.error || JSON.stringify(r.json)}`);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  if (!jsonOutput(args.flags)) process.stderr.write('\n');
  die(`timed out waiting on ${jobId}`);
}

async function cmdPoll(args) {
  const jobId = args._[1];
  if (!jobId) die('usage: tinyzkp poll <job-id>');
  const apiKey = await resolveApiKey(args.flags);
  if (!apiKey) die('TINYZKP_API_KEY not set');
  const base = resolveBaseUrl(args.flags);
  if (args.flags.wait) {
    return await pollUntilComplete(args, jobId);
  }
  const r = await httpRequest('GET', `${base}/prove/${encodeURIComponent(jobId)}`, { apiKey });
  if (!r.ok) die(`poll failed: HTTP ${r.status} ${JSON.stringify(r.json)}`);
  emit(args.flags, () => {
    const color = r.json.status === 'completed' ? c.green : r.json.status === 'failed' ? c.red : c.yellow;
    console.log(color(r.json.status));
    if (r.json.eta_ms != null) console.log(c.dim('  eta_ms: ') + r.json.eta_ms);
    if (r.json.proof) {
      console.log(c.dim('  version: ') + r.json.proof.version);
      if (r.json.proof.size_kb != null) console.log(c.dim('  size:    ') + r.json.proof.size_kb + ' KB');
    }
  }, r.json);
}

async function cmdVerify(args) {
  const proofArg = args._[1];
  if (!proofArg) die('usage: tinyzkp verify <proof-file-or-inline-json>');
  let raw = proofArg;
  try { raw = await fs.readFile(proofArg, 'utf8'); } catch {}
  let parsed;
  try { parsed = JSON.parse(raw); } catch (e) { die(`invalid JSON: ${e.message}`); }
  // Accept either {proof: {...}} or just {...}
  const proof = parsed.proof || parsed;
  if (!proof.version || !proof.bytes) {
    die('proof must have version and bytes fields');
  }
  const apiKey = await resolveApiKey(args.flags);
  if (!apiKey) die('TINYZKP_API_KEY not set (verification is free but auth-gated to prevent abuse)');
  const base = resolveBaseUrl(args.flags);
  const r = await httpRequest('POST', `${base}/verify`, {
    body: { proof, allow_legacy_v2: Boolean(args.flags['allow-legacy-v2']) },
    apiKey,
  });
  if (!r.ok) die(`verify failed: HTTP ${r.status} ${JSON.stringify(r.json)}`);
  const valid = r.json.ok || r.json.valid;
  emit(args.flags, () => {
    if (valid) console.log(c.green('✔ ') + 'valid' + c.dim(`  (round-trip ${r.elapsed} ms)`));
    else {
      console.log(c.red('✘ ') + 'INVALID');
      if (r.json.error) console.log(c.dim('  ') + r.json.error);
    }
  }, { ...r.json, round_trip_ms: r.elapsed });
  if (!valid) process.exit(2);
}

// ── Help ──────────────────────────────────────────────────────────────

function printHelp() {
  console.log(`${c.bold('tinyzkp')} — TinyZKP CLI for zero-knowledge proofs

${c.bold('USAGE')}
  tinyzkp <command> [args] [--flags]

${c.bold('COMMANDS')}
  ${c.cyan('templates')}                            list available proof templates
  ${c.cyan('describe')} <template-id>               show parameters and example for a template
  ${c.cyan('estimate')} <template-id> <params>      estimate cost/time/proof size before proving
  ${c.cyan('prove')} <template-id> <params>         submit a proof (JSON or path to .json file)
  ${c.cyan('poll')} <job-id>                        check status of a prove job
  ${c.cyan('verify')} <proof-file>                  verify a proof (file or inline JSON)
  ${c.cyan('healthz')}                              probe the API health endpoint

${c.bold('FLAGS')}
  --api-key=<key>           override TINYZKP_API_KEY
  --base-url=<url>          override TINYZKP_API_URL (default https://api.tinyzkp.com)
  --json                    machine-readable JSON output
  --wait                    on prove/poll: block until proof is complete
  --timeout=<seconds>       max wait when --wait is set (default 300)
  --zk                      enable ZK masking on prove (hides intermediate state)
  --allow-legacy-v2         allow legacy v2 proof format on verify

${c.bold('AUTH')}
  In order of precedence:
    1. --api-key flag
    2. TINYZKP_API_KEY environment variable
    3. ~/.tinyzkp/credentials  (line: TINYZKP_API_KEY=tzk_...)

${c.bold('EXAMPLES')}
  ${c.dim('# List templates and describe one')}
  tinyzkp templates
  tinyzkp describe range_proof

  ${c.dim('# Estimate cost (no key required)')}
  tinyzkp estimate range_proof '{"min":0,"max":100,"witness_steps":[42,44]}'

  ${c.dim('# Generate a proof end-to-end')}
  export TINYZKP_API_KEY=tzk_xxxx
  tinyzkp prove range_proof '{"min":0,"max":100,"witness_steps":[42,44]}' --wait > proof.json
  tinyzkp verify proof.json

${c.bold('LINKS')}
  Free API key:  https://tinyzkp.com/signup
  Try it live:   https://tinyzkp.com/try
  Docs:          https://tinyzkp.com/docs
`);
}

// ── Main ──────────────────────────────────────────────────────────────

(async function main() {
  const args = parseArgs(process.argv);
  const cmd = args._[0];
  if (!cmd || args.flags.help || args.flags.h || cmd === 'help') {
    printHelp();
    process.exit(cmd ? 0 : 1);
  }
  try {
    switch (cmd) {
      case 'templates': await cmdTemplates(args); break;
      case 'describe':  await cmdDescribe(args); break;
      case 'estimate':  await cmdEstimate(args); break;
      case 'prove':     await cmdProve(args); break;
      case 'poll':      await cmdPoll(args); break;
      case 'verify':    await cmdVerify(args); break;
      case 'healthz':   await cmdHealthz(args); break;
      default:
        console.error(c.red(`unknown command: ${cmd}`));
        printHelp();
        process.exit(1);
    }
  } catch (e) {
    die(e.message || String(e));
  }
})();
