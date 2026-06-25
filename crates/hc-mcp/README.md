# TinyZKP MCP Server

[Model Context Protocol](https://modelcontextprotocol.io) server for TinyZKP proof receipts. It lets Claude Desktop, Claude Code, Cursor, and MCP-compatible clients generate, poll, fetch, summarize, and verify transparent STARK state-transition receipts for supported workflows.

Use this when an agent needs a native tool for minting and checking receipts
instead of shelling out to a CLI. Get an API key at
[tinyzkp.com/signup](https://tinyzkp.com/signup?source=github_mcp_readme&medium=github&platform=mcp_readme&intent=mcp_install)
or use the hosted public MCP lane for unauthenticated discovery and free
verification.

## Install

Download the pre-built binary for your platform from [Releases](https://github.com/logannye/hc-stark/releases):

```bash
# macOS (Apple Silicon)
curl -L -o hc-mcp https://github.com/logannye/hc-stark/releases/latest/download/hc-mcp-macos-arm64
chmod +x hc-mcp
```

Or build from source:

```bash
cargo build --release -p hc-mcp
```

## Setup

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tinyzkp": {
      "command": "/path/to/hc-mcp",
      "args": ["--api-key", "tzk_your_key_here"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add tinyzkp /path/to/hc-mcp -- --api-key tzk_your_key_here
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "tinyzkp": {
      "command": "/path/to/hc-mcp",
      "args": ["--api-key", "tzk_your_key_here"]
    }
  }
}
```

## Tools

| Tool | Description |
|---|---|
| `list_templates` | List supported proof templates with lifecycle status, summaries, and tags. |
| `describe_template` | Return the statement boundary, parameter schema, and example for a template. |
| `prove_template` | Submit a supported proof-template job and receive a job ID. |
| `poll_job` | Poll a submitted proof job until it succeeds or fails. |
| `get_proof` | Fetch proof bytes plus a tracked `verifier_url` and, when the proof fits the public share-link limit, a proof-embedded `receipt_url`. |
| `get_proof_summary` | Fetch a compact, agent-friendly receipt summary with the verifier URL when the proof fits the share-link limit. |
| `verify_proof` | Verify a TinyZKP proof receipt. Verification is free. |
| `list_workloads` | List registered workload IDs for supported long-running or reviewed proving workflows. |
| `prove_workload` | Submit a supported workload or Compute proof job. |

## Get an API Key

Visit [tinyzkp.com/signup](https://tinyzkp.com/signup?source=github_mcp_readme&medium=github&platform=mcp_readme&intent=mcp_install) to sign up. Verification is free and does not require an API key. Default receipts are transparent. Do not put secrets, private customer data, or raw credentials into receipt parameters; use [the agent policy](https://tinyzkp.com/agent-policy?source=github_mcp_readme&medium=github&platform=mcp_readme&intent=agent_policy) for when to mint, attach, verify, skip, or escalate receipts.

## Distribution Links

- [Get an API key](https://tinyzkp.com/signup?source=github_mcp_readme&medium=github&platform=mcp_readme&intent=mcp_install)
- [Verify a receipt in the browser](https://tinyzkp.com/verify?source=github_mcp_readme&medium=github&platform=mcp_readme&intent=verify_receipt)
- [Pricing and limits](https://tinyzkp.com/limits?source=github_mcp_readme&medium=github&platform=mcp_readme&intent=limits)
- [Agent-readable offers](https://tinyzkp.com/.well-known/tinyzkp-offers.json?source=github_mcp_readme&medium=github&platform=mcp_readme&intent=agent_offer)
