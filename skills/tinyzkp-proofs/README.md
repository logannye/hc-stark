# tinyzkp-proofs

A Claude Skill that teaches Claude when and how to use the **TinyZKP** MCP server to mint and verify zero-knowledge proofs.

## What it does

When you ask Claude something like *"prove this account balance is in [$0, $10k] without revealing the amount"* or *"attach a verifiable receipt to this agent action,"* this skill helps Claude:

1. Recognize that the request maps to a zero-knowledge proof
2. Pick the right TinyZKP template (`range_proof`, `policy_compliance`, `hash_preimage`, `data_integrity`, `accumulator_step`, or `computation_attestation`)
3. Walk the standard `prove → poll → get_proof → verify` workflow
4. Communicate results in a way that makes the privacy / public-input / verification contract explicit

## Install

The skill itself is just `SKILL.md` — Claude loads it from this directory. To use it alongside the live TinyZKP MCP:

```
claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com
```

No signup, no API key, no credit card. Free tier: 100 proofs/month.

## What's TinyZKP?

A hosted ZK-STARK proving service. Six production templates, ≥128-bit soundness, MIT-licensed open-source backend at https://github.com/logannye/hc-stark.

Homepage: https://tinyzkp.com
Browser playground: https://tinyzkp.com/try
Live API status: https://tinyzkp.com/status

## License

MIT.
