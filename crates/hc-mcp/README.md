# TinyZKP MCP Server

TinyZKP's production MCP surface is capability-only while the resource-bounded
Plonky3 backend is under review. It does not expose proving, verification,
polling, receipt, account, API-key, or billing tools.

The only production tool is `get_capabilities`. It reports the release identity,
the pinned Plonky3 compatibility target, unavailable features, and the safe next
action. No credentials are accepted.

## Run locally

```bash
cargo run -p hc-mcp --bin hc-mcp-stdio
```

The hosted Streamable HTTP endpoint is
`https://mcp.tinyzkp.com/mcp`. Current status and evaluation intake are at
[tinyzkp.com/status](https://tinyzkp.com/status) and
[tinyzkp.com/contact](https://tinyzkp.com/contact).

Legacy receipt tools compile only with the explicit `legacy-research` feature
and are not part of production binaries or supported hosted operations.
