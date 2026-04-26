# Anthropic MCP Directory Submission

Anthropic maintains an official directory of MCP servers. Getting listed there is the single highest-quality lead source available to TinyZKP — every Claude user looking for what to install browses it.

**Where to submit:** Anthropic's MCP server registry. As of early 2026 the canonical submission flow is via PR to https://github.com/modelcontextprotocol/servers (or the directory site they may have stood up since). Confirm the current process at https://modelcontextprotocol.io before submitting.

## Server Manifest (paste into PR / form)

```json
{
  "name": "tinyzkp",
  "displayName": "TinyZKP — Verifiable Receipts",
  "description": "Mint zero-knowledge proofs for any computation as a native tool call. 6 templates (range, hash preimage, data integrity, accumulator, policy, computation attestation) covering common privacy and attestation patterns. Free tier with 100 proofs/month, no credit card.",
  "homepage": "https://tinyzkp.com",
  "repository": "https://github.com/logannye/hc-stark",
  "license": "MIT",
  "categories": ["cryptography", "verification", "privacy", "developer-tools"],
  "transports": ["http", "stdio"],
  "endpoints": {
    "http": "https://mcp.tinyzkp.com",
    "stdio": "hc-mcp-stdio"
  },
  "install": {
    "claudeCode": "claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com",
    "claudeDesktop": "Add to claude_desktop_config.json with command 'hc-mcp-stdio' and args '--api-key tzk_...'",
    "cursor": "Add to ~/.cursor/mcp.json with command 'hc-mcp-stdio' and args '--api-key tzk_...'"
  },
  "tools": [
    "prove",
    "verify",
    "prove_status",
    "list_jobs",
    "healthz",
    "list_programs",
    "describe_program",
    "list_workloads",
    "submit_workload",
    "workload_status"
  ],
  "auth": {
    "type": "bearer",
    "envVar": "TINYZKP_API_KEY",
    "signupUrl": "https://tinyzkp.com/signup"
  },
  "screenshots": [
    "https://tinyzkp.com/og-image.png"
  ],
  "version": "1.0.0",
  "maintainer": {
    "name": "Logan Wyne",
    "email": "logan@tinyzkp.com",
    "github": "logannye"
  }
}
```

## Cover Letter (for the PR description)

```
This adds TinyZKP, a hosted ZK-STARK proving service that ships as an MCP server.

Why it belongs in the directory:
- Free tier (100 proofs/month, no credit card) — Claude users can install and try
  it in 30 seconds without committing to a paid plan.
- Both HTTP and stdio transports supported (mcp.tinyzkp.com is publicly reachable;
  hc-mcp-stdio is also distributed for Claude Desktop / Cursor).
- 10 tools cover the full prove/verify/discover lifecycle for 6 proof templates.
  Tool names are stable and follow the MCP naming conventions.
- Auth via standard Bearer token in env var (TINYZKP_API_KEY); no surprise OAuth
  detours.
- Open-source backend: https://github.com/logannye/hc-stark (MIT licensed).

Happy to iterate on the manifest if anything doesn't match the registry's current
schema.
```

## After acceptance

- Add the directory listing URL to the homepage as a trust badge.
- Mention it in the next product update / X post.
- Monitor signups attributable to "directory" referrer for the first 2 weeks; if it's the top channel, double-down on directory metadata richness (screenshots, demo video).
