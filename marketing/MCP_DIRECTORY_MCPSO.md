# mcp.so submission notes — TinyZKP

mcp.so aggregates public MCP servers. Listings are free.

> **Important — only one submission path exists.** An earlier draft of
> this doc described a "PR path" through `github.com/chatmcp/mcp-directory`
> as a fallback. That repo is the *Next.js source code for the mcp.so
> website* — its `data/` directory contains only `install.sql` (the schema
> for a self-hosted Supabase instance), and its README walks through
> cloning the repo to *self-host the directory*. Public-listing data
> lives in mcp.so's own Supabase, not the git repo. The submission form
> is the only path. Verified 2026-04-28.

## Pre-flight checklist

- [x] Public repo: https://github.com/logannye/hc-stark
- [x] `crates/hc-mcp/mcp.json` is the canonical descriptor — kept in sync with `crates/hc-mcp/src/lib.rs`
- [x] Hosted URL live at https://mcp.tinyzkp.com
- [x] License: MIT
- [x] One-line install command in README

## What mcp.so renders

The catalog page pulls the following from `mcp.json`:

| Field | Source | Used for |
|---|---|---|
| `name` | `mcp.json#/name` | URL slug (`mcp.so/server/tinyzkp`) |
| `display_name` | `mcp.json#/display_name` | Card title |
| `description` | `mcp.json#/description` | Card body |
| `categories` | `mcp.json#/categories` | Filtering |
| `tools[]` | `mcp.json#/tools` | "Available tools" list |
| `install.remote.claude` | `mcp.json#/install/remote/claude` | Copy-paste install button |

## Submission steps

1. Open https://mcp.so/submit.
2. Repository URL: `https://github.com/logannye/hc-stark`.
3. Server type: **Hosted (HTTP)** — endpoint `https://mcp.tinyzkp.com`.
4. Manifest path: `crates/hc-mcp/mcp.json`.
5. Submit. The expected listing URL pattern is `https://mcp.so/server/tinyzkp`.

If `mcp.so/submit` ever requires a self-hosted manifest mirror instead
of a path inside this repo, the manifest is also reachable at
https://raw.githubusercontent.com/logannye/hc-stark/main/crates/hc-mcp/mcp.json.

## Verifying the listing went live

```bash
# After submission is approved, the listing URL becomes a real page:
curl -fsSL "https://mcp.so/server/tinyzkp" 2>&1 | grep -iE "TinyZKP - " | head -1
# Empty output (or "Project not found" body on 200) means the listing
# is not yet active. Their review queue can take days.
```

## Post-acceptance

- [ ] Verify the rendered page at `mcp.so/server/tinyzkp` matches expectations (tools list, install command).
- [ ] Watch `Referrer: mcp.so*` in MCP server logs.
- [ ] Update `crates/hc-mcp/mcp.json` whenever tool list or descriptions change. mcp.so re-syncs from the manifest URL on a schedule; if the page goes stale, the fix is to push manifest changes to `main`.

## Submission status

- [ ] Submitted via mcp.so/submit — date: ____ — listing URL: ____
