# mcp.so submission notes — TinyZKP

mcp.so aggregates public MCP servers. Listings are free and added by submitting a PR to
https://github.com/chatmcp/mcp-directory (the catalog repo), or by filling out the
"Submit Server" form at https://mcp.so/submit.

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

## Submission steps (form path — fastest)

1. Open https://mcp.so/submit.
2. Repository URL: `https://github.com/logannye/hc-stark`.
3. Server type: **Hosted (HTTP)** — endpoint `https://mcp.tinyzkp.com`.
4. Manifest path: `crates/hc-mcp/mcp.json`.
5. Submit. Listing URL will be `https://mcp.so/server/tinyzkp`.

## Submission steps (PR path — fallback)

```bash
# In a fork of chatmcp/mcp-directory:
mkdir -p servers/tinyzkp
cp /path/to/hc-stark/crates/hc-mcp/mcp.json servers/tinyzkp/server.json
git checkout -b add-tinyzkp
git add servers/tinyzkp/
git commit -m "Add TinyZKP — verifiable receipts for AI agents"
gh pr create --title "Add TinyZKP" \
  --body "Hosted ZK-STARK prover. 10 tools, 6 templates, free 100/mo. https://tinyzkp.com"
```

## Post-acceptance

- [ ] Verify the rendered page at `mcp.so/server/tinyzkp` matches expectations (tools list, install command).
- [ ] Watch `Referrer: mcp.so*` in MCP server logs.
- [ ] Update `crates/hc-mcp/mcp.json` whenever tool list or descriptions change — mcp.so re-syncs from the manifest.
