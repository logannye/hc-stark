# External listing retraction (2026-07-29)

TinyZKP published itself to three external directories while it operated a
hosted MCP endpoint. That endpoint was retired in `b4570c5` ("Retire the
hosted stack and Guard SKU"), which also **deleted the `crates/hc-mcp`
crate**. The directory manifests were left behind, so for months they
advertised a service that returns `410 Gone` and a source subfolder that no
longer exists.

## What the manifests claimed, and what was actually true

| Claim | Reality |
|---|---|
| `server.json` → `remotes[0].url: https://mcp.tinyzkp.com/mcp` | **410 Gone**, permanently |
| `server.json` → `_meta…contactUrl: /requests` | **410 Gone** |
| `server.json` → `repository.subfolder: crates/hc-mcp` | crate deleted in `b4570c5` |
| `smithery.yaml` → `startCommand.url: https://mcp.tinyzkp.com` | **410 Gone** |
| `smithery.yaml` → "100 evaluation receipts/month" | no receipts product exists |
| `smithery.yaml` → "Get a free key at https://tinyzkp.com/signup" | **410 Gone** |
| `smithery.yaml` → ten MCP tools | none exist |

## Decision: delist, do not repair

A "capability-only" MCP entry whose own description concedes that proving,
verification, accounts, API keys, and checkout are all unavailable describes
no product. Keeping a truthful-but-empty listing costs credibility in a
directory whose entire purpose is telling people what they can call. The
files are therefore deleted rather than corrected.

The resource estimator (`POST /v1/estimate`) is **not** an MCP server and
should not be listed as one. It is documented at
<https://tinyzkp.com/docs#estimator> and in `site/llms.txt`.

## Owner actions — deleting these files does NOT delist anything

Registry entries live on the registries, not in this repository. Removing the
manifests stops future publishes; the published entries must be withdrawn
explicitly. **Verified against each registry's live API on 2026-07-29:**

### 1. MCP registry — LISTED, and worse than `server.json` was

The published entry is **not** the "capability-only, backend recovery" text
that was in `server.json`. `server.json` was revised at some point and never
re-published, so the registry still serves the original marketing copy:

> `io.github.logannye/tinyzkp` — "Hosted MCP server for STARK proof receipts.
> **Agents mint receipts and verify proofs for free.**"
> `remotes[0].url: https://mcp.tinyzkp.com` · `subfolder: crates/hc-mcp`

Every clause is false: the host is a permanent 410 and the crate was deleted
in `b4570c5`. **This is the most misleading artifact TinyZKP still has in
public.** Retract with the `mcp-publisher` CLI (already installed):

```sh
mcp-publisher login github          # interactive; opens a browser
mcp-publisher status --status deleted --all-versions \
  --message "Hosted MCP endpoint retired; mcp.tinyzkp.com returns 410" \
  io.github.logannye/tinyzkp
mcp-publisher logout
```

Verify: `curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=tinyzkp"`

### 2. Smithery — LISTED

`logan/tinyzkp-mcp` (id `cf89af6f-4bba-4af1-8766-2acb94c24624`, created
2026-04-28), still titled "TinyZKP — Verifiable Receipts for AI Agents".
`useCount` is **0**, so nothing has ever called it.

`DELETE https://registry.smithery.ai/servers/logan/tinyzkp-mcp` returns
**401**, not 404 — the endpoint exists but needs a Smithery API key, which is
not stored on this machine. Either obtain a key from the Smithery dashboard
and call that endpoint, or remove the server from the dashboard UI.

### 3. Glama — NOT LISTED, no action needed

`glama.ai/api/mcp/v1/servers?query=tinyzkp` returns an empty result set and
`glama.ai/mcp/servers/logannye/hc-stark` returns 404. The `glama.json` in
this repo was a maintainer claim that never produced a listing. Deleting the
file was sufficient. *(An earlier revision of this runbook listed a Glama
removal as outstanding; that was wrong.)*

### 4. claude.ai connector — owner-only, no CLI

A TinyZKP MCP connector is registered on the owner's claude.ai account and
points at the 410 host. Remove it in connector settings. There is no CLI or
API path for this from the repository.

## Preventing recurrence

`scripts/ci/external_listing_check.py` resolves every URL that appears in a
published manifest or in `site/llms.txt` against the route table declared in
`site/_worker.js`, and fails on any that maps to a retired host, a `410`, or
a path the site does not serve. It needs no network access: the retired hosts
and permanent redirects are already declared in the worker.

That check would have caught all seven rows in the table above on the commit
that retired the hosted stack.
