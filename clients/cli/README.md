# @tinyzkp/cli

Generate and verify [TinyZKP](https://tinyzkp.com) zero-knowledge proofs from your terminal. One command, zero setup.

```bash
npx @tinyzkp/cli templates
npx @tinyzkp/cli prove range_proof '{"min":0,"max":100,"witness_steps":[42,44]}' --wait > proof.json
npx @tinyzkp/cli verify proof.json
```

That's the whole flow.

## Install

```bash
# Run without installing (recommended for one-off use)
npx @tinyzkp/cli <command>

# Or install globally
npm install -g @tinyzkp/cli
tinyzkp <command>
```

Requires Node.js 18+ (uses built-in `fetch`).

## Authentication

Get a free API key at [tinyzkp.com/signup](https://tinyzkp.com/signup) — 100 proofs/month, no credit card. Then expose it via any of:

```bash
# Option 1: environment variable
export TINYZKP_API_KEY=tzk_xxxx

# Option 2: per-command flag
tinyzkp prove ... --api-key=tzk_xxxx

# Option 3: credentials file
mkdir -p ~/.tinyzkp
echo "TINYZKP_API_KEY=tzk_xxxx" > ~/.tinyzkp/credentials
chmod 600 ~/.tinyzkp/credentials
```

## Commands

| Command | Description |
|---|---|
| `tinyzkp templates` | List all available proof templates |
| `tinyzkp describe <id>` | Show parameters + example for a template |
| `tinyzkp estimate <id> <params>` | Estimate cost / time / proof size (no key needed) |
| `tinyzkp prove <id> <params>` | Submit a proof job, returns `job_id` |
| `tinyzkp poll <job-id>` | Check status / fetch completed proof |
| `tinyzkp verify <proof>` | Verify a proof from file or inline JSON |
| `tinyzkp healthz` | Probe the API |

## Common flags

| Flag | Purpose |
|---|---|
| `--wait` | On `prove`/`poll`: block until proof is complete |
| `--timeout=<s>` | Max seconds to wait (default 300) |
| `--json` | Machine-readable JSON output (good for piping) |
| `--zk` | Enable zero-knowledge masking on `prove` |
| `--api-key=<key>` | Override env var |
| `--base-url=<url>` | Use a non-default API host (e.g., for staging) |

## End-to-end example

```bash
# 1. List what's available
$ npx @tinyzkp/cli templates
Available proof templates:

  range_proof         (lightweight)
    Prove a secret value lies within a range
  hash_preimage       (lightweight)
    Prove knowledge of a hash preimage
  ...

# 2. See how to use one
$ npx @tinyzkp/cli describe range_proof
range_proof
backend: vm

Prove a secret value lies within a range

Parameters:
  min (integer) required
    Lower bound of the allowed range (inclusive)
  max (integer) required
    Upper bound of the allowed range (inclusive)
  witness_steps (array) required
    Additive steps from min that sum to (value - min)

Example:
  {"min":18,"max":120,"witness_steps":[7]}

# 3. Estimate before paying
$ npx @tinyzkp/cli estimate range_proof '{"min":0,"max":100,"witness_steps":[42,44]}'
Estimate
  trace length:     128 steps
  cost (Developer): $0.05
  proof size:       12 KB
  prove time:       1200 ms

# 4. Generate
$ npx @tinyzkp/cli prove range_proof '{"min":0,"max":100,"witness_steps":[42,44]}' --wait
✔ proof completed (prf_a1b2c3)
  version: 4
  size:    12.4 KB
  bytes:   0x6a8f7c4b1e9d2a3f5e8b6c9d2a3f5e8b6c9d2a3f5e8b...

# 5. Verify (always free)
$ npx @tinyzkp/cli prove ... --wait --json > proof.json
$ npx @tinyzkp/cli verify proof.json
✔ valid  (round-trip 8 ms)
```

## Pipe-friendly mode

Add `--json` to any command for machine-readable output. Plays nicely with `jq`:

```bash
JOB=$(tinyzkp prove range_proof '{"min":0,"max":100,"witness_steps":[42]}' --json | jq -r .job_id)
tinyzkp poll "$JOB" --wait --json | jq .proof.bytes
```

## What about MCP?

If you're building an AI agent (Claude Code, Claude Desktop, Cursor, OpenAI agents), prefer the MCP integration — your agent gets these same operations as native function calls without shelling out to a CLI:

```bash
claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com
```

See [tinyzkp.com/docs](https://tinyzkp.com/docs) for the MCP integration guide.

## License

MIT — see [LICENSE](./LICENSE).

## Links

- [tinyzkp.com](https://tinyzkp.com) — homepage
- [tinyzkp.com/try](https://tinyzkp.com/try) — browser playground (no signup)
- [tinyzkp.com/docs](https://tinyzkp.com/docs) — full docs
- [github.com/logannye/hc-stark](https://github.com/logannye/hc-stark) — open source
