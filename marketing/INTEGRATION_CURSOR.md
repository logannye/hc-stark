# Add ZK Proofs to Cursor in 30 Seconds (MCP Install)

> Target: ~600 words. Publish to: TinyZKP blog, Cursor community Discord, dev.to, Medium

## Hook

Cursor is brilliant at writing code. It's not great at *proving* the code did what you say it did. If you're building a tool, an agent, or a deploy bot inside Cursor that touches sensitive data, you eventually need a way to attach a verifiable receipt to its actions — for the user, for an auditor, for a compliance team.

This post adds TinyZKP's MCP server to Cursor. After ~30 seconds of setup, every Cursor agent on your machine can mint zero-knowledge proofs as a native tool call. Free tier, no credit card.

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

Get a free `tzk_...` key at https://tinyzkp.com/signup (no credit card, 100 proofs/month free forever).

If you don't have `hc-mcp-stdio` on your `$PATH` yet:

```bash
# macOS / Linux
curl -L https://github.com/logannye/hc-stark/releases/latest/download/hc-mcp-stdio-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o ~/.local/bin/hc-mcp-stdio
chmod +x ~/.local/bin/hc-mcp-stdio
```

Restart Cursor. Done. The TinyZKP tools are now available to every chat.

## What Cursor can do with this

Open a chat in any project and try:

> Use the tinyzkp tools to prove that the file `secrets.txt` hashes to `<digest>` without revealing the contents, then verify the proof.

Cursor will:

1. Read the file (locally — never leaves your machine)
2. Call `prove` on the `hash_preimage` template
3. Poll `prove_status` until done
4. Call `verify` to confirm
5. Hand you back a proof ID + a verifiable byte string

Other patterns that work well from inside Cursor:

| Prompt to Cursor | Template it picks |
|---|---|
| "Prove this user is over 18 without exposing their birthdate." | `range_proof` |
| "Attest that the test suite passed without revealing the test inputs." | `computation_attestation` |
| "Prove the spending in this audit log stayed under $1000." | `policy_compliance` |
| "Prove these CSV rows sum to the checksum in the previous commit." | `data_integrity` |

Each generates a tamper-evident proof your user can verify in their own browser.

## The 10 tools you just installed

Cursor sees these as regular function calls. You can chain them in agent loops, embed them in `.cursorrules`, or just use them ad-hoc in chat:

- `prove` — submit a proof
- `verify` — check a proof (always free)
- `prove_status` — poll a job
- `list_jobs` — see jobs for your tenant
- `healthz` — service status
- `list_programs` / `describe_program` — registered workloads
- `list_workloads` / `submit_workload` / `workload_status` — workload-style proving

## When to use which template

The mental model: each template wraps one common privacy/attestation pattern.

- **range_proof** — "I know a number in [X, Y]." For age gates, credit checks, salary bands.
- **hash_preimage** — "I know the secret behind this hash." For password proofs, commitments, file integrity.
- **computation_attestation** — "f(secret) = public_output." The general-purpose one.
- **accumulator_step** — "Starting at X, applying these ops gets to Y." For state machines.
- **policy_compliance** — "These actions sum stayed under threshold." For spend caps, rate limits.
- **data_integrity** — "These rows sum to this committed checksum." For datasets, ledgers.

If none of those fit, the `computation_attestation` template is the catch-all.

## Cost

- **Free tier**: 100 proofs/month, no credit card.
- **Developer ($9/month)**: 100 RPM, 4 concurrent jobs, $500 monthly cap. Per-proof rates from $0.05 (small) to $30 (10M+ steps).
- **Verification**: always free. 10K free verify calls/month even on no-card plans.

Most Cursor-side workloads (small range/hash/policy proofs) land squarely in the $0.05 tier. A typical developer pays $9–$25 per month all-in.

## Try it

Free signup: https://tinyzkp.com/signup
GitHub: https://github.com/logannye/hc-stark
Docs: https://tinyzkp.com/docs

The first proof is genuinely 30 seconds in. If you hit anything weird, the founder personally reads contact-form messages — reply rate is same-day.
