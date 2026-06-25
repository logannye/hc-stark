# Add Proof Receipts to Cursor in 30 Seconds (MCP Install)

> Target: ~600 words. Publish to: TinyZKP blog, Cursor community Discord, dev.to, Medium

## Hook

Cursor is brilliant at writing code. It's not great at *proving* the workflow did what you say it did. If you're building a tool, an agent, or a deploy bot inside Cursor that changes important state, you eventually need a way to attach a verifiable receipt to its actions — for the user, for an auditor, for a compliance team.

This post adds TinyZKP's MCP server to Cursor. After ~30 seconds of setup, every Cursor agent on your machine can mint transparent STARK state-transition receipts as a native tool call. Free tier, no credit card.

## The 30-second install

Open `~/.cursor/mcp.json` (create it if it doesn't exist) and paste:

```json
{
  "mcpServers": {
    "tinyzkp": {
      "command": "hc-mcp-stdio",
      "args": ["--api-key", "tzk_YOUR_KEY"]
    }
  }
}
```

Get a free `tzk_...` key at https://tinyzkp.com/signup?source=cursor_community_post&medium=community&platform=cursor&intent=api_key (no credit card, 100 proofs/month).

If you don't have `hc-mcp-stdio` on your `$PATH` yet:

```bash
# macOS / Linux
curl -L https://github.com/logannye/hc-stark/releases/latest/download/hc-mcp-stdio-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o ~/.local/bin/hc-mcp-stdio
chmod +x ~/.local/bin/hc-mcp-stdio
```

Restart Cursor. Done. The TinyZKP tools are now available to every chat.

## What Cursor can do with this

Open a chat in any project and try:

> Use the tinyzkp tools to prove that an account moved from 1000 to 1045 via the deltas [10, 20, 15], then verify the proof.

Cursor will:

1. Call `prove_template` on the `accumulator_step` template
2. Poll `poll_job` until done
3. Call `get_proof_summary` or `get_proof`
4. Call `verify_proof` to confirm
5. Hand you back a proof ID + a verifiable receipt

The proof is a tamper-evident receipt your user can verify in their own browser.

## The 10 tools you just installed

Cursor sees these as regular function calls. You can chain them in agent loops, embed them in `.cursorrules`, or just use them ad-hoc in chat:

- `get_capabilities` — product boundary, workflow, and limits
- `list_templates` — list live proof templates
- `describe_template` — inspect schema and example parameters
- `prove_template` — submit a template proof job
- `poll_job` — check job status
- `get_proof_summary` — get a receipt summary for humans and agents
- `get_proof` — retrieve base64 proof bytes
- `verify_proof` — check a proof (always free)
- `list_workloads` / `prove_workload` — reviewed workload-style proving

## When to use which template

The mental model: each template wraps one common attestation pattern.

- **accumulator_step** — "Starting at X, applying these ops gets to Y." For state machines, audit chains, balance receipts.

For the current list of available templates, call `list_templates` via MCP or the REST API.

## Cost

- **Free tier**: 100 proofs/month, no credit card.
- **Developer ($19/month)**: 100 RPM, 4 concurrent jobs, $500 monthly cap. Per-proof rates from $0.05 (small) to $30 (10M+ steps).
- **Verification**: always free for supported receipts.

Most Cursor-side workloads (small accumulator / state-transition proofs) land squarely in the $0.05 tier. A typical developer pays $19–$25 per month all-in.

## Try it

Free signup: https://tinyzkp.com/signup?source=cursor_community_post&medium=community&platform=cursor&intent=api_key
GitHub: https://github.com/logannye/hc-stark
Docs: https://tinyzkp.com/docs?source=cursor_community_post&medium=community&platform=cursor&intent=docs

The first proof is genuinely 30 seconds in. If you hit anything weird, the founder personally reads contact-form messages — reply rate is same-day.
