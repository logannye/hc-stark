# TinyZKP MCP Distribution Pack

> Purpose: keep every MCP directory, agent-IDE community, and curated list on a
> current, source-tagged TinyZKP listing so directory traffic can become
> measurable signups and paid accounts.
>
> Last updated: 2026-06-25

---

## Canonical Listing Copy

### One-Liner

Proof receipts for agent actions, API mutations, and state transitions.

### Short Description

TinyZKP gives agents and backend workflows a native MCP tool for minting
transparent STARK state-transition receipts. Agents can prove that a supported
workflow advanced from an initial state to a final state by declared steps, then
hand the receipt to another human, service, or agent for independent
verification without replaying the producer system.

### Boundaries

- Hosted endpoint: `https://mcp.tinyzkp.com`
- Install: `claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com`
- Verification is free.
- Free signup includes evaluation receipts and no credit card.
- Optional `Authorization: Bearer tzk_...` unlocks account-scoped limits.
- Default receipts are transparent state-transition receipts, not generic
  private-input ZK, arbitrary zkVM execution, zkML, or universal on-chain
  verification.
- Do not put secrets, private customer data, API keys, or unsupported private
  inputs into transparent receipt parameters.

### Suggested Tags

`mcp`, `agents`, `proof-receipts`, `stark`, `verification`, `audit`, `developer-tools`, `security`, `api`

---

## Source-Tagged Directory CTAs

The machine-readable source of truth is
[`mcp_distribution_targets.json`](./mcp_distribution_targets.json). Each target
has a directory-specific signup URL with:

- `source=<directory_or_community>`
- `medium=mcp_directory`
- `platform=<directory_or_client>`
- `intent=mcp_install`

Use the directory's own install button for MCP setup, but keep the TinyZKP
signup URL in the description, docs, or "homepage" field whenever the surface
allows it.

| Surface | Status | Signup URL |
|---|---|---|
| Smithery | Active | `https://tinyzkp.com/signup?source=smithery_mcp&medium=mcp_directory&platform=smithery&intent=mcp_install` |
| mcp.so | Target | `https://tinyzkp.com/signup?source=mcp_so&medium=mcp_directory&platform=mcp_so&intent=mcp_install` |
| Glama MCP Registry | Target | `https://tinyzkp.com/signup?source=glama_mcp&medium=mcp_directory&platform=glama&intent=mcp_install` |
| mcpservers.org | Target | `https://tinyzkp.com/signup?source=mcpservers_org&medium=mcp_directory&platform=mcpservers_org&intent=mcp_install` |
| Anthropic Connectors Directory | Submission ready | `https://tinyzkp.com/signup?source=anthropic_connector&medium=mcp_directory&platform=anthropic&intent=mcp_install` |
| PulseMCP | Target | `https://tinyzkp.com/signup?source=pulsemcp&medium=mcp_directory&platform=pulsemcp&intent=mcp_install` |
| Cursor Directory | Submission ready | `https://tinyzkp.com/signup?source=cursor_directory&medium=mcp_directory&platform=cursor&intent=mcp_install` |
| awesome-mcp-servers | Target | `https://tinyzkp.com/signup?source=awesome_mcp_servers&medium=mcp_directory&platform=github&intent=mcp_install` |

---

## Submission Checklist

Before submitting or updating a listing:

1. Confirm `https://mcp.tinyzkp.com/.well-known/mcp/server-card.json` includes
   the current tool list and optional Bearer-token language.
2. Confirm `site/mcp.json` and `crates/hc-mcp/mcp.json` describe the same live
   template and product boundary.
3. Use the source-tagged signup URL from `mcp_distribution_targets.json`.
4. Include the install command exactly:
   `claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com`
5. Include the transparent-receipt warning: do not put secrets, private
   customer data, or API keys into receipt parameters.
6. After publication, add the public listing URL back into
   `mcp_distribution_targets.json`, change `status` to `active`, and run the
   online monitor.

---

## Monitor

Static checks run in CI:

```bash
python3 scripts/monitoring/gtm_distribution_monitor.py --offline
```

Online checks are for ops after directory changes:

```bash
python3 scripts/monitoring/gtm_distribution_monitor.py
```

The online monitor checks canonical TinyZKP assets plus every `active` target
that has a `listing_url`. Targets without live listing URLs are skipped online
but still validated offline for source-tagged CTA shape.

---

## Operating Rule

Do not optimize for the biggest generic directory list. Prioritize surfaces
where an agent builder can install MCP immediately, create one receipt, and
click a source-tagged signup URL when they need authenticated limits.
