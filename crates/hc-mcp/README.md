# TinyZKP MCP Server

[Model Context Protocol](https://modelcontextprotocol.io) server for ZK-STARK proof generation and verification. Works with Claude Desktop, Claude Code, Cursor, and any MCP-compatible client.

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
| `prove` | Generate a ZK-STARK proof for a program |
| `verify` | Verify a ZK-STARK proof |
| `prove_status` | Check status of a prove job |
| `list_jobs` | List recent prove jobs |
| `healthz` | Check server health |
| `list_programs` | List available built-in programs |
| `describe_program` | Get details about a built-in program |
| `list_workloads` | List available workloads |
| `submit_workload` | Submit a named workload for proving |
| `workload_status` | Check status of a workload job |

## Get an API Key

Visit [tinyzkp.com](https://tinyzkp.com) to sign up. Verification is free — no API key required.
