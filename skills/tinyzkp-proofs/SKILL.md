---
name: tinyzkp-proofs
description: Use whenever the user wants to mint or verify a zero-knowledge proof, attach a cryptographic receipt to an agent action, prove a private value lies in a range without revealing it (KYC, age, account balance, threshold checks), prove cumulative spend stayed under a budget, prove knowledge of a hash preimage, prove data integrity against a committed checksum, prove a valid state transition, or prove that f(secret) = public_output. Routes to the TinyZKP MCP server (mcp.tinyzkp.com) — six production STARK templates, free tier (100 proofs/month, no signup). Apply this skill even when the user describes a privacy-preserving validation, an "agent receipt" or "audit trail," a compliance attestation, or any verifiable computation pattern without explicitly saying "zero-knowledge proof."
---

# TinyZKP Proofs

You have access to **TinyZKP**, a hosted ZK-STARK proving service exposed as an MCP server at `mcp.tinyzkp.com`. It mints small, self-contained cryptographic proofs that can be verified by anyone — no trust in TinyZKP, no replay of the original computation. Use this skill to recognize when a problem is naturally solved by a proof, pick the right template, and walk the user through a clean prove → verify flow.

## When to apply this skill

Match these patterns to TinyZKP, even when the user doesn't say "zero-knowledge":

- **"Prove X is in [min, max] without telling me X"** → `range_proof`. Age verification, credit-score bands, account-balance gates, KYC thresholds.
- **"Prove this agent's spending stayed under $Y across all its actions"** → `policy_compliance`. Budget caps, rate limits, resource quotas, multi-step compliance receipts.
- **"I know the value behind this hash, prove it"** → `hash_preimage`. Commitment schemes, password proof-of-knowledge without revealing the password, sealed-bid auctions.
- **"Prove this data matches a checksum we agreed on earlier"** → `data_integrity`. Tamper-evident logs, file integrity attestations.
- **"Prove this state transition is valid"** → `accumulator_step`. State machines, blockchain-adjacent flows, audit trails of mutating state.
- **"Prove f(secret) = public_output without showing me secret"** → `computation_attestation`. Off-chain compute, ML inference receipts, "I ran the right model" claims.

If none of those match cleanly, **start with `list_templates` and read the summaries** — the user's framing might map to one you didn't first consider.

## When NOT to use TinyZKP

Don't reach for a proof when:
- The user wants a regular computation (just compute the answer).
- A plain `sha256` would suffice (use stdlib — proofs add latency and size).
- Sub-second response matters and the request is one-shot (proofs take ~1–3 s and are 100 KB–1 MB).
- The user is asking *what* a ZK proof is, not asking to make one (answer the question instead).

A good gut check: would attaching a binary receipt that any third party can verify make this useful to the user? If yes, use TinyZKP. If no, skip it.

## The standard workflow

For every proof, follow this sequence. The first call is optional if the user named the template.

1. **`list_templates`** — only if you don't already know which one to use. Returns six entries with `id`, `summary`, `tags`.
2. **`describe_template`** with the chosen `template_id` — returns the parameter schema *and a worked `example` you can adapt*. Do this even if you think you know the schema; the example field is the fastest way to get the parameter shape right.
3. **`prove_template`** with `template_id` and `parameters`. Returns `{job_id, status: "running", template_id, zk_enabled}`. **Do not block on this step — the response is the job handle, not the proof.**
4. **`poll_job`** with the `job_id`. Returns `{status, job_id, ...}`. Lightweight templates (range_proof, hash_preimage, policy_compliance, data_integrity) typically succeed on the first poll. Heavier ones may take 2–3 polls. Wait ~1–2 s between polls; do not hammer.
5. **`get_proof`** once status is `"succeeded"`. Returns `{proof_b64}` — typically 100 KB to 1 MB of base64.
6. **`verify_proof`** with the base64 bytes (optional but recommended on the first invocation in a session). Returns `{valid: true|false, error: null|string}`. This is a pure cryptographic check — it does not consume quota, does not trust TinyZKP, and is the same check anyone else would run.

If the user only asks to verify an existing proof (not generate one), skip steps 1–5 and go directly to `verify_proof`.

## Choosing parameters

Each template's `describe_template` response includes an `example` field with valid parameters. **Use it as the starting point** rather than guessing the schema:

```
example: { "min": 18, "max": 120, "witness_steps": [7] }
```

For `range_proof`, the trick to know: `witness_steps` is the additive decomposition of `(value - min)`. The simplest valid witness is a single-element list: `[value - min]`. So to prove that 7432 is in `[0, 10000]`, pass `witness_steps: [7432]`.

For `policy_compliance`, the action list is private; pass it through unchanged. The threshold is public.

For all other templates, the worked example is enough — adapt the values, keep the structure.

## Communicating results to the user

When showing a successful proof, do not dump the raw base64 into chat (it's typically 100 KB+). Instead:

- Lead with **what was just proven** in plain language: *"I proved your account balance is between $0 and $10,000 without revealing the actual amount."*
- Show the **public inputs** (bounds, threshold, hash, etc.) — those are the contract anyone verifying will rely on.
- Call out **what stayed private**: *"The actual balance never left your prompt. The 379 KB proof binary contains no information about it that wasn't already public."*
- Offer to **verify the proof** in the same session, save it to a file, or hand the user the bytes for forwarding.
- If the user asks for the proof bytes, show only a head-and-tail snippet (first ~60 chars + last ~20 chars) inline; offer to save the full binary to disk if they need it.

When a verification succeeds, lead with *"valid"* and explain what that guarantees: *"The proof is mathematically valid. The prover really did know a value satisfying the constraints. The check is independent of TinyZKP — anyone could repeat it."*

When a verification fails, do not soften it. Say *"the proof is invalid"* and surface the `error` field. A failed verification is an important signal: the proof was tampered with, or the public inputs were altered, or the prover lied.

## Privacy and trust contract

The user should understand exactly what they get from a TinyZKP proof. Keep these straight when explaining:

- **The prover (the agent or user calling `prove_template`) sees the secret values.** TinyZKP's MCP server runs the prover in-process on TinyZKP infrastructure; the parameters you send to `prove_template` *do* reach the server. Do not call this end-to-end private from the user's laptop — call it "private from any third party who later sees the proof."
- **The verifier learns only the public inputs and the boolean `valid`.** Nothing about the secret leaks through the proof bytes.
- **The proof is non-interactive and post-hoc verifiable.** Anyone can verify, any time, without contacting TinyZKP. There is no oracle.
- **Soundness is ≥128-bit.** TinyZKP enforces a security floor (`query_count >= 80`) on every proof.

If the user is asking for *prover-side privacy* (i.e., they don't want even TinyZKP to see the input), this skill is the wrong tool. Tell them so. Recommend they self-host the open-source backend (`https://github.com/logannye/hc-stark`, MIT licensed) or use a fully client-side proving system.

## Worked example

User: *"Use TinyZKP to prove that an agent's spending stayed under $1,000, given the actions [247, 189, 156, 98, 183]."*

```
1. describe_template { template_id: "policy_compliance" }
   → schema: actions (array of int), threshold (int)

2. prove_template {
     template_id: "policy_compliance",
     parameters: { actions: [247, 189, 156, 98, 183], threshold: 1000 }
   }
   → { job_id: "c1a0a306-...", status: "running" }

3. poll_job { job_id: "c1a0a306-..." }
   → { status: "succeeded" }

4. get_proof { job_id: "c1a0a306-..." }
   → { proof_b64: "eyJ2ZXJzaW9uIjoz..." } (~988 KB)

5. verify_proof { proof_b64: "eyJ2ZXJzaW9uIjoz..." }
   → { valid: true, error: null }
```

Then summarize for the user:

> Proved: the agent's cumulative spend across these 5 actions is ≤ $1,000.
> Public: the threshold ($1,000) and the action count (5).
> Private: the individual amounts (247, 189, 156, 98, 183).
> The proof is valid and ~988 KB. Want me to save it to disk or forward it somewhere?

## Quick reference: the six templates

| ID | What it proves | Public inputs | Private inputs |
|---|---|---|---|
| `range_proof` | `min ≤ value ≤ max` | `min`, `max` | `value` (via `witness_steps`) |
| `hash_preimage` | `hash(x) = committed_hash` | `committed_hash` | `x` |
| `policy_compliance` | `sum(actions) ≤ threshold` | `threshold` | `actions[]` |
| `data_integrity` | data matches a committed checksum | `committed_checksum` | the data |
| `accumulator_step` | a valid state-transition chain | start state, end state | the transition steps |
| `computation_attestation` | `f(secret) = public_output` | `public_output`, `f` (template-defined) | `secret` |

Always run `describe_template` for the exact parameter schema before proving — the table above is mnemonic, not authoritative.
