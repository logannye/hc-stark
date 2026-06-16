# Give Your LangChain Agent a Verifiable State Receipt (10 Lines)

> Target: ~700 words. Publish to: TinyZKP blog, dev.to, Medium (LangChain publication), submit as a docs PR to https://github.com/langchain-ai/langchain/tree/main/docs

## Hook

Some agents don't just chat — they **settle a running state**. A balance, a usage counter, a reserve total, an aggregated value over many inputs. When a counterparty, an auditor, or the user's own compliance team asks *"can you prove that number is right?"*, the honest answer today is usually "our logs say so."

A signed log proves *you* asserted the number. It doesn't let someone who can't see or re-run your system confirm the arithmetic themselves. A **TinyZKP state receipt** does: it's a transparent ZK-STARK that a committed value advanced from X to Y by exactly this ordered set of steps — transferable, checkable offline in ~5 ms, with no trusted setup and post-quantum by construction.

One honest note up front: the audited path makes the steps **public and verifiable**, not hidden. This is transparency and *transferable* verification, not privacy. (A private-witness variant is in audit; not covered here.) That's exactly what you want for proof-of-reserves, audit chains, and usage attestation — anywhere the point is "anyone can check this," not "hide the inputs."

This post adds a verifiable state receipt to a LangChain agent in **10 lines**. Free tier, no credit card.

## The 60-second install

TinyZKP exposes its prove/verify API as an MCP server. The Claude Code installer is one line:

```bash
claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com
```

For LangChain agents, two options:

1. **MCP path** (recommended for LangGraph or any LangChain agent that already speaks MCP). The agent gets 10 proof tools as standard function calls — no SDK to import.
2. **SDK path** (recommended for a vanilla `AgentExecutor`). Import `tinyzkp` as a Python tool wrapper.

We'll show the SDK path first because it lands cleanly in any LangChain stack.

## The 10 lines

```python
from langchain.agents import Tool, initialize_agent, AgentType
from langchain.chat_models import ChatAnthropic
from tinyzkp import TinyZKP

zkp = TinyZKP("https://api.tinyzkp.com", api_key="tzk_...")

async def prove_state_transition(args: dict) -> str:
    job_id = await zkp.prove_template("accumulator_step", params=args)
    proof  = await zkp.wait_for_proof(job_id)
    return f"proof_id={job_id}, version={proof['version']}, bytes_kb={proof['size_kb']}"

tools = [Tool(name="prove_state_transition", func=prove_state_transition, description="Prove a committed value advanced from initial to final by an ordered set of public deltas. Args: {initial, final, deltas}.")]
agent = initialize_agent(tools, ChatAnthropic(model="claude-sonnet-4-6"), agent=AgentType.OPENAI_FUNCTIONS)

result = agent.run("Prove that an account moved from 1000 to 1045 via the deltas [10, 20, 15].")
```

That's the whole integration. The agent decides when to mint a receipt, gets a `proof_id`, and hands it to the user. Verification is a separate `await zkp.verify(proof)` — free to call, sub-5 ms in WASM.

## What you can prove today

TinyZKP's live, **audited** template is `accumulator_step` — a state transition over a public delta chain:

| Pattern | When the agent uses it |
|---|---|
| `accumulator_step` | "This committed value moved from A to B by exactly these steps" — running balances, reserve/ledger totals, usage counters, append-only audit chains |

For the current list of available templates, call `list_templates` via the MCP server or the REST API. zkVM and zkML proving are in development, not yet available — don't build against them yet.

## Verifying client-side (the part that matters)

Verification doesn't need TinyZKP to be online. Ship the proof + the WASM verifier (`@tinyzkp/verify`, 785 KB) and the recipient's browser checks it in under 5 ms:

```javascript
import init, { verify } from '@tinyzkp/verify';
await init();
const result = verify({ version: 4, bytes: proofBytes });
console.log(result.ok); // true — verified offline, no server round-trip
```

A receipt the recipient has to send back to your server to verify is a trust *extension*. A receipt they verify in their own browser is a trust *replacement*. That's the whole point.

## What this costs

- **Free tier**: 100 proofs/month, no credit card. Lasts indefinitely if your agent only mints occasional receipts.
- **Developer**: $19/month + $0.05–$30/proof by trace size. Small state-transition proofs land in the $0.05 tier.
- **Compute (usage)**: $0.50 per million trace steps, no monthly base — for large traces.
- **Verification**: always free, in-browser via WASM.

## When you actually need this (and when you don't)

Be honest with yourself before you reach for a proof:

- **A signed log is enough** when you just need a tamper-evident record that *you* attested something happened. Don't add ZK for that — it's slower and more complex with no gain.
- **A state receipt earns its keep** when a third party who can't see or re-run your system must independently confirm a state transition's arithmetic — proof-of-reserves, an auditor checking a reconciliation, an oracle attesting an aggregate — or when you specifically want transparency / no-trusted-setup / post-quantum verification that survives a long horizon.

That honesty is the point: TinyZKP is the right tool for a narrow, real job, and we'd rather you use it where it wins.

## Try it now

```bash
pip install tinyzkp                   # Python SDK
npm install tinyzkp                   # TypeScript SDK
npm install @tinyzkp/verify           # Browser / WASM verifier
claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com  # MCP install
```

Free signup at https://tinyzkp.com/signup. The first proof is genuinely 60 seconds in, and the 10-line integration above is the whole onboarding. Hit something weird? Email logan@tinyzkp.com — we read every message and reply within a couple of business days.
