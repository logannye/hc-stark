# TinyZKP MCP Server

[Model Context Protocol](https://modelcontextprotocol.io) server for TinyZKP proof receipts. It lets Claude Desktop, Claude Code, Cursor, and MCP-compatible clients generate, poll, fetch, summarize, and verify transparent STARK state-transition receipts for supported workflows.

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
| `get_proof` | Fetch the proof bytes for a completed job. |
| `get_proof_summary` | Fetch a compact, agent-friendly receipt summary for a completed job. |
| `verify_proof` | Verify a TinyZKP proof receipt. Verification is free. |
| `list_workloads` | List registered workload IDs for supported long-running or reviewed proving workflows. |
| `prove_workload` | Submit a supported workload or Compute proof job. |

## Get an API Key

Visit [tinyzkp.com/signup](https://tinyzkp.com/signup) to sign up. Verification is free and does not require an API key. Do not put secrets, private customer data, or raw credentials into transparent receipt parameters; use [the agent policy](https://tinyzkp.com/agent-policy) for when to mint, attach, verify, skip, or escalate receipts.
