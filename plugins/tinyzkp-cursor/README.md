# TinyZKP for Cursor

TinyZKP gives Cursor agents native MCP tools for minting, fetching, summarizing,
and verifying transparent STARK proof receipts for supported state-transition
workflows.

Install this plugin from Cursor Directory or load the directory locally while it
is awaiting publication:

```bash
cursor --plugin-dir ./plugins/tinyzkp-cursor
```

The plugin connects Cursor to the hosted TinyZKP MCP endpoint through
`mcp-remote`:

```json
{
  "mcpServers": {
    "tinyzkp": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.tinyzkp.com/mcp"]
    }
  }
}
```

Cursor will expose tools such as `get_capabilities`, `list_templates`,
`describe_template`, `prove_template`, `poll_job`, `get_proof_summary`,
`get_proof`, and `verify_proof`.

## Use It

Ask Cursor:

> Use TinyZKP to prove that an account moved from 1000 to 1045 by applying
> deltas [10, 20, 15], then verify the receipt.

Cursor should call `list_templates`, inspect `accumulator_step` with
`describe_template`, submit the proof with `prove_template`, poll until the job
is complete, and call `verify_proof`.

## Production Usage

The hosted public lane is suitable for discovery, demos, and free verification.
For production proving limits, support expectations, spend controls, and paid
plans, create a TinyZKP account:

- Signup: https://tinyzkp.com/signup?source=cursor_directory&medium=mcp_directory&platform=cursor&intent=mcp_install
- Docs: https://tinyzkp.com/docs?source=cursor_directory&medium=mcp_directory&platform=cursor&intent=docs
- Pricing: https://tinyzkp.com/pricing?source=cursor_directory&medium=mcp_directory&platform=cursor&intent=pricing
- Agent policy: https://tinyzkp.com/agent-policy?source=cursor_directory&medium=mcp_directory&platform=cursor&intent=agent_policy

Default receipts are transparent. Do not put secrets, private customer data,
API keys, credentials, or unsupported private inputs into receipt parameters.

## Direct Cursor Config

If you prefer to configure Cursor manually instead of installing the plugin,
add this to your Cursor MCP config:

```json
{
  "mcpServers": {
    "tinyzkp": {
      "url": "https://mcp.tinyzkp.com/mcp"
    }
  }
}
```

Use the browser signup link above for paid hosted proving when you need higher
limits or account-scoped support.
