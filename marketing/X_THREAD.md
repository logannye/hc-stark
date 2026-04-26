# Twitter / X Launch Thread

**When to post:** ~30 minutes after the HN post hits the front page (gives both a coordinated lift and tracks separately). Otherwise, Tuesday/Wednesday 9:30 a.m. ET.

**Tag the right people in replies (not in the post itself):** @swyx, @AravSrinivas, @LangChainAI, @AnthropicAI, @assaf_elovic. Tag in a *follow-up reply* on your own tweet, not in the body of the original — Twitter throttles tag-in-body posts.

---

**Post 1/4 (the hook):**

```
Verifiable receipts for AI agents.

One MCP install. Claude / Cursor / OpenAI agents get 10 zero-knowledge proof tools
as native function calls.

  $ claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com

That's it. Free tier, no credit card.

🧵
```

Attach: short screen recording (≤ 30 seconds) showing:
1. The `claude mcp add` command
2. Inside Claude Code, asking "prove that 42 is in [0, 100]"
3. Claude calling `prove`, polling, calling `verify`, returning {valid: true}

If you don't have a recording yet, use a clean GIF of the same flow.

---

**Post 2/4 (the why):**

```
Most ZK-as-a-service is built for crypto/web3 devs. We built TinyZKP for AI agent
builders specifically.

Templates instead of circuits. MCP transport instead of glue code. WASM verifier
in 785K so your end-user verifies in their browser, no server round-trip.

The structural unlock: O(√T) prover memory.
```

---

**Post 3/4 (the cost angle):**

```
The √T memory architecture is why we can price the small-proof tier at $0.05/proof
and the free tier at 100 proofs/month.

Self-hosting a STARK prover = $700/mo bare-metal + DevOps + on-call rotation.
TinyZKP @ Developer ($9/mo + usage) = ~70% lower for typical workloads.

Cost calculator: tinyzkp.com/#cost-calc
```

---

**Post 4/4 (the close):**

```
Open source: github.com/logannye/hc-stark
Free signup: tinyzkp.com/signup
Docs: tinyzkp.com/docs

If you're building an agent and want verifiable receipts attached to its actions,
the MCP install is genuinely 30 seconds. Reply if you hit anything weird; I'll
respond within the day.
```

---

**Notes:**

- Pin the thread on the founder profile for a week.
- After 24 hours, write a single-tweet update if the launch went well: "X new signups today, top integration request was [Y]. Building it next week." — this drives the second wave.
- DO NOT auto-DM new followers. It tanks deliverability and looks desperate.
- If the thread underperforms (< 50 likes after 4 hours), DON'T amplify with a paid boost. Pull the post the next day and try a different hook the following week. Twitter algorithms punish stale ad-boosted dev-tools posts hard.
