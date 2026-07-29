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
manifests stops future publishes and, for the directories that read the repo,
should cause the entry to fall out on the next scan. The published entries
still need to be withdrawn by hand:

- [ ] **MCP registry** (`io.github.logannye/tinyzkp`) — delete or mark the
      server entry withdrawn at <https://registry.modelcontextprotocol.io>.
- [ ] **Smithery** — remove the `tinyzkp` server at <https://smithery.ai>.
      Smithery builds from `smithery.yaml` in the repo root; with the file
      gone the build should fail rather than publish a broken endpoint, but
      the catalog entry needs removing explicitly.
- [ ] **Glama** — remove the maintainer claim at <https://glama.ai/mcp>.
- [ ] **claude.ai connector** — a TinyZKP MCP connector is registered on the
      owner's claude.ai account and points at the 410 host. Remove it in
      connector settings. This one cannot be done from this repository at
      all.

## Preventing recurrence

`scripts/ci/external_listing_check.py` resolves every URL that appears in a
published manifest or in `site/llms.txt` against the route table declared in
`site/_worker.js`, and fails on any that maps to a retired host, a `410`, or
a path the site does not serve. It needs no network access: the retired hosts
and permanent redirects are already declared in the worker.

That check would have caught all seven rows in the table above on the commit
that retired the hosted stack.
