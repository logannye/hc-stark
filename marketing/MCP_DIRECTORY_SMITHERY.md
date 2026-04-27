# Smithery.ai submission notes — TinyZKP

Smithery is the largest community MCP catalog. Listings are free; submission is via PR to
https://github.com/smithery-ai/registry **or** by importing a public repo through the
Smithery web UI at https://smithery.ai/new.

## Pre-flight checklist

- [x] `smithery.yaml` at repo root (this PR adds it)
- [x] Public repo at https://github.com/logannye/hc-stark
- [x] Hosted endpoint live at https://mcp.tinyzkp.com (HTTPS, valid cert)
- [x] License: MIT
- [x] All 10 tools annotated (title, read_only_hint, destructive_hint) — see `crates/hc-mcp/src/lib.rs`

## Submission steps (web UI path — fastest)

1. Sign in at https://smithery.ai with the `logannye` GitHub account.
2. Click **"New Server"** and paste `https://github.com/logannye/hc-stark`.
3. Smithery auto-detects `smithery.yaml`. Confirm the parsed metadata (name, description, transport, tools).
4. Hit **"Publish"**. Listing URL will be `https://smithery.ai/server/@logannye/tinyzkp`.

## Submission steps (PR path — fallback if web UI rejects auto-detect)

```bash
# In a fork of smithery-ai/registry:
mkdir -p servers/tinyzkp
cat > servers/tinyzkp/server.json <<'JSON'
{
  "name": "tinyzkp",
  "displayName": "TinyZKP — Verifiable Receipts for AI Agents",
  "description": "Mint zero-knowledge proofs as a tool call. Free 100/month.",
  "homepage": "https://tinyzkp.com",
  "repository": "https://github.com/logannye/hc-stark",
  "license": "MIT",
  "transport": "http",
  "url": "https://mcp.tinyzkp.com"
}
JSON
git checkout -b add-tinyzkp
git add servers/tinyzkp/
git commit -m "Add TinyZKP server"
gh pr create --title "Add TinyZKP — verifiable receipts for AI agents" \
  --body "Hosted ZK-STARK prover exposed as MCP. 10 tools, 6 templates, free 100/mo."
```

## Post-acceptance

- [ ] Add the Smithery badge to `README.md` and `tinyzkp.com/docs`.
- [ ] Watch `Referrer: smithery.ai*` in MCP server logs for first 14 days.
- [ ] Reply to first 3 issues opened on the Smithery server detail page within 24h.
