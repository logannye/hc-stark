# Add Verifiable Receipts to Your LangChain Agent in 10 Lines

> Target: ~700 words. Publish to: TinyZKP blog, dev.to, Medium (LangChain publication), submit as a docs PR to https://github.com/langchain-ai/langchain/tree/main/docs

## Hook

Your LangChain agent talks to private data, runs sensitive computations, takes actions on a user's behalf. When the user — or their compliance team, or an auditor, or a regulator — asks "can you prove that?", the honest answer today is "the agent's logs say so."

Logs are not proofs. A tampered log file says whatever the tamperer wants it to say. A zero-knowledge proof says one thing: this exact computation produced this exact output, signed by physics. Once you generate one, no party (including the agent itself) can forge a different result.

This post adds verifiable receipts to a LangChain agent in **10 lines of integration code**. Free tier, no credit card.

## The 60-second install

TinyZKP exposes its prove/verify API as an MCP server. The Claude Code installer is one line:

```bash
claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com
```

For LangChain agents, you have two options:

1. **MCP path** (recommended if you're using LangGraph or any LangChain agent that already speaks MCP). The agent gets 10 ZK tools as standard function calls. No SDK to import.
2. **SDK path** (recommended if you're using a vanilla `AgentExecutor`). Import `tinyzkp` as a Python tool wrapper.

We'll show the SDK path first because it lands cleanly in any LangChain stack.

## The 10 lines

```python
from langchain.agents import Tool, initialize_agent, AgentType
from langchain.chat_models import ChatAnthropic
from tinyzkp import TinyZKP

zkp = TinyZKP("https://api.tinyzkp.com", api_key="tzk_...")

async def prove_range(args: dict) -> str:
    job_id = await zkp.prove_template("range_proof", params=args)
    proof = await zkp.wait_for_proof(job_id)
    return f"proof_id={job_id}, version={proof['version']}, bytes_kb={proof['size_kb']}"

tools = [Tool(name="prove_range", func=prove_range, description="Prove a value lies in [min, max] without revealing it. Args: {min, max, witness_steps}.")]
agent = initialize_agent(tools, ChatAnthropic(model="claude-opus-4-5"), agent=AgentType.OPENAI_FUNCTIONS)

result = agent.run("Prove that 42 is in the range [0, 100] without revealing the value.")
```

That's the whole integration. The agent now decides on its own when to mint a proof, gets a `proof_id`, and can return it to the user as a receipt. Verification is a separate `await zkp.verify(proof)` call, free to call, sub-5ms in WASM.

## What you can prove today

TinyZKP ships 6 templates that cover most attestation patterns agents care about:

| Template | When the agent uses it |
|---|---|
| `range_proof` | "User is between 18 and 65" — without storing the birthdate |
| `hash_preimage` | "I know the password that hashes to X" — for credential checks |
| `computation_attestation` | "I ran f() on these private inputs and got this public output" |
| `accumulator_step` | "The state machine moved from A to B by these specific deltas" |
| `policy_compliance` | "The agent's spending stayed under the $100 cap this session" |
| `data_integrity` | "These data rows sum to this checksum the user committed to earlier" |

The patterns map cleanly onto things a LangChain agent already does — chain-of-thought verification, tool-call provenance, RAG output attestation.

## Verifying client-side (the magic part)

Verification doesn't need TinyZKP to be online. Ship the proof + the WASM verifier (`@tinyzkp/verify`, 785K) and the user's browser checks the proof itself in under 5 milliseconds:

```javascript
import init, { verify } from '@tinyzkp/verify';
await init();
const result = verify({ version: 4, bytes: proofBytes });
console.log(result.ok); // true — verified offline
```

This is what makes verifiable receipts actually useful. A receipt the user has to round-trip back to your server to verify is a trust extension, not a trust replacement. A receipt the user verifies in their own browser is a trust replacement.

## What this costs

- **Free tier**: 100 proofs/month, no credit card. Lasts indefinitely if your agent only mints occasional proofs.
- **Developer**: $9/month + $0.05–$30/proof depending on trace size. Most agent receipts are small (range, policy) and land in the $0.05 tier.
- **Verification**: always free. 10K free verify calls/month even on no-card plans.

For agent workloads (small attestation proofs at moderate volume) the typical Developer-tier customer pays $20–50/month all-in. Self-hosting a STARK prover for the same workload starts around $1,500/month all-in once you count DevOps and on-call.

## Why this beats logging

- **Logs are mutable.** Anyone with write access can rewrite history. Proofs are not.
- **Logs require trust in your server.** The user has to believe you didn't tamper. Proofs verify offline.
- **Logs need re-architecting for audit.** Proofs are signed receipts users hold themselves.

## Try it now

```bash
pip install tinyzkp                   # Python SDK
npm install tinyzkp                   # TypeScript SDK
npm install @tinyzkp/verify           # Browser/WASM verifier
claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com  # MCP install
```

Free signup at https://tinyzkp.com/signup. The first proof is genuinely 60 seconds in. The 10-line integration above is the whole onboarding. If you hit anything weird, ping us — the founder reads every contact form and replies within the day.
