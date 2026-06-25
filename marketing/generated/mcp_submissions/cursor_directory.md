# TinyZKP MCP Submission: Cursor Directory

Status: `submission_ready`
Kind: `agent_ide_directory`
Submission URL: https://cursor.directory/plugins/new
Current listing: Not published yet

## Directory Fields

Name: TinyZKP

One-line description: Proof receipts for agent actions, API mutations, and state transitions.

Website / CTA: https://tinyzkp.com/signup?source=cursor_directory&medium=mcp_directory&platform=cursor&intent=mcp_install

Hosted MCP endpoint: https://mcp.tinyzkp.com

Install command:

```bash
cursor --plugin-dir ./plugins/tinyzkp-cursor
```

Tags: mcp, agents, proof-receipts, stark, verification, audit, developer-tools, security, api

## Short Description

TinyZKP gives agents and backend workflows a native MCP tool for minting
transparent STARK state-transition receipts. Agents can prove that a supported
workflow advanced from an initial state to a final state by declared steps, then
hand the receipt to another human, service, or agent for independent
verification without replaying the producer system.

## Boundaries

- Transparent STARK state-transition receipts for supported templates; verification is free.
- Do not put secrets, private customer data, API keys, or unsupported private inputs into transparent receipt parameters.
- Free signup includes evaluation receipts and no credit card.
- Optional `Authorization: Bearer tzk_...` unlocks account-scoped limits.
- Verification is free and can be performed by humans, services, or agents.

## Source-Tagged Signup URL

https://tinyzkp.com/signup?source=cursor_directory&medium=mcp_directory&platform=cursor&intent=mcp_install

## Submission Checklist

- Use the hosted endpoint exactly: `https://mcp.tinyzkp.com`
- Include the install command exactly as written above.
- Include the source-tagged signup URL, not a generic homepage URL.
- Include the transparent-receipt warning from the Boundaries section.
- After publication, update `marketing/mcp_distribution_targets.json` with the
  live listing URL and set `status` to `active`.
- Run `python3 scripts/monitoring/gtm_distribution_monitor.py`.

## Required Listing Markers

TinyZKP, Proof Receipts
