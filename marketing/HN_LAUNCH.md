# Show HN Launch Post

**When to post:** Tuesday or Wednesday between 8:00–9:30 a.m. Eastern. Avoid Mondays (HN front page is crowded with weekend backlog) and Friday afternoons (worst engagement window).

**Title (≤ 80 chars):**

```
Show HN: Verifiable receipts for AI agent actions (free MCP server)
```

Alternate title to A/B if the first underperforms:

```
Show HN: TinyZKP — ZK proofs as one API call, native MCP for Claude/Cursor
```

---

**Body:**

```
TinyZKP is a hosted ZK-STARK proving service. The angle that makes it different from
Sindri/Bonsai/etc. is that we ship as an MCP server — your Claude/Cursor/OpenAI agent
can mint a tamper-evident proof for any computation as a native tool call:

    claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com

After that, the agent has 10 ZK tools (prove, verify, list_workloads, ...) the same
way it has filesystem or git. Proofs go through 6 templates (range, hash preimage,
data integrity, etc.) — no circuit writing.

Under the hood, the prover runs in O(√T) memory instead of the usual O(T) by way of
a height-compressed streaming architecture. That structural advantage is why we can
price the small-proof tier at $0.05/proof and the free tier at 100 proofs/month with
no credit card.

What it's good for today:
- Verifiable agent receipts ("this ran the code I claim")
- Privacy-preserving compliance (range proofs, policy proofs)
- Audit trails (data-integrity, accumulator chains)
- Browser-side verification via @tinyzkp/verify (WASM, 785K)

What it's NOT yet:
- A zkVM (Risc0/SP1 territory — different product)
- A polynomial-commitment-bound zkML/Spartan (in progress; current zkml/spartan
  endpoints ship as Preview tier with explicit soundness caveats)

Free tier: https://tinyzkp.com/signup
Source: https://github.com/logannye/hc-stark
Docs: https://tinyzkp.com/docs

Happy to answer questions about the √T trick, the MCP integration, or the pricing
math vs. self-hosting.
```

**Notes for the day-of:**

- Be on HN actively for the first ~3 hours after submitting. Reply to every comment within 15 minutes during that window. Drop-off on first-page rank is brutal if author engagement stalls.
- Pre-warm: do NOT ask anyone to upvote (against HN guidelines and detected algorithmically). It IS fine to share the link in your existing communities once it's submitted.
- Best top-level reply pattern: "Good question. [direct answer]. We chose X over Y because [reason]. Happy to go deeper if useful."
- If a thread of skeptics forms around "why not Risc0/SP1/Sindri/etc.": don't get defensive. Acknowledge what those tools do well, position TinyZKP as the *template + MCP* angle, not a zkVM competitor.

**Day-after follow-up:**

- Save the HN thread URL.
- Go through every comment. For each substantive one, reply with a thanks and a 1-sentence next-step (link to docs, link to a feature request issue, etc.).
- If anyone asks for a feature you're going to ship, file a public GitHub issue and link it back. Show responsiveness in public; it's free retention.
