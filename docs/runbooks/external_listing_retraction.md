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

## Status as of 2026-07-29

| Surface | State |
|---|---|
| MCP registry | ✅ **Retracted** — `0.1.0: active → deleted` |
| Glama | ✅ Never listed; nothing to do |
| Smithery | ⏸️ **Still listed, deliberately deferred** (`useCount: 0`) |
| claude.ai connector | ⏸️ Outstanding — owner-only, no CLI path |

### 1. MCP registry — ✅ RETRACTED 2026-07-29

Done with the commands below; verified absent from
`?search=tinyzkp` and from `?search=tinyzkp&version=latest` (the latter would
still surface a merely-deprecated entry, so this confirms a real delete).
The section is kept because the *reason* it mattered is the reusable lesson.

### 1a. What it had been serving — worse than `server.json` was

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

### 2. Smithery — STILL LISTED, deliberately deferred

`logan/tinyzkp-mcp` (id `cf89af6f-4bba-4af1-8766-2acb94c24624`, created
2026-04-28), still titled "TinyZKP — Verifiable Receipts for AI Agents".
**`useCount` is 0 — nothing has ever called it.**

Deletion via the API is a real, supported operation. Probed 2026-07-29:

```
DELETE /servers/logan/tinyzkp-mcp     -> 401   (exists, auth-gated)
DELETE /definitely-not-a-real-route   -> 404
DELETE /servers                       -> 404
GET    /servers/logan/tinyzkp-mcp     -> 200
```

A bogus path returns 404, so the 401 is genuine auth enforcement on a real
route, not a gateway catch-all. A valid key should therefore work:

```sh
curl -sS -X DELETE https://registry.smithery.ai/servers/logan/tinyzkp-mcp \
  -H "Authorization: Bearer <smithery-key>" -w '\nHTTP %{http_code}\n'
```

**Deferred on 2026-07-29 after the key handling proved fiddly** (Smithery
auto-regenerates the key when you delete it, which is a rotation mechanism
rather than a bug, but made the flow awkward). This was a considered call,
not an oversight: with `useCount: 0` the listing has misled no one, and the
two surfaces that actually reached people — the privacy notice and the MCP
registry entry advertising free receipt minting — are both fixed. Clear it
from the Smithery dashboard whenever convenient.

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
