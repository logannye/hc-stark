---
name: tinyzkp-proofs
description: Use whenever the user wants to mint or verify a transparent STARK receipt for a state transition — "starting at X, applying a sequence of deltas, arrives at Y" — such as proving a running total reached a value, proving a multi-step accumulation is correct, or attaching a cryptographic receipt to an agent's cumulative state change. Routes to the TinyZKP MCP server (mcp.tinyzkp.com) — one live STARK template (`accumulator_step`), free tier (100 proofs/month, no signup). Apply this skill when the user describes a verifiable state transition, a running-total attestation, or an "agent receipt" for a sequence of incremental updates.
---

# TinyZKP Proofs

You have access to **TinyZKP**, a hosted STARK receipt service exposed as an MCP server at `mcp.tinyzkp.com`. It mints small, self-contained cryptographic receipts that can be verified by anyone — no trust in TinyZKP, no replay of the original transition chain. Use this skill to recognize when a problem is naturally solved by a receipt, and walk the user through a clean prove → verify flow.

## When to apply this skill

Match this pattern to TinyZKP, even when the user doesn't say "zero-knowledge":

- **"Prove that starting from X, after applying these incremental changes, the total reached Y"** → `accumulator_step`. State machines, running totals, sequential ledger updates, audit trails of mutating state, multi-step agent receipts.

If you're unsure whether the user's request maps to this pattern, **call `list_templates` first** and read the summaries — that is authoritative about what is currently available.

## When NOT to use TinyZKP

Don't reach for a proof when:
- The user wants a regular computation (just compute the answer).
- A plain `sha256` would suffice (use stdlib — proofs add latency and size).
- Sub-second response matters and the request is one-shot (proofs take ~1–3 s and are 100 KB–1 MB).
- The user is asking *what* a ZK proof is, not asking to make a state-transition receipt (answer the question instead).
- The request is a range check, hash preimage, policy-compliance threshold, data-integrity checksum, or ML-inference attestation — these are not currently supported; do not attempt them.

A good gut check: would attaching a binary receipt that any third party can verify make this useful to the user? If yes, and the shape is a state transition / accumulation, use TinyZKP. If no, skip it.

## The standard workflow

For every proof, follow this sequence.

1. **`list_templates`** — call this if you don't already know which template to use, or to confirm `accumulator_step` is available. Returns entries with `id`, `summary`, `tags`.
2. **`describe_template`** with `template_id: "accumulator_step"` — returns the parameter schema *and a worked `example` you can adapt*. Do this even if you think you know the schema; the example field is the fastest way to get the parameter shape right.
3. **`prove_template`** with `template_id: "accumulator_step"` and `parameters`. Returns `{job_id, status: "running", template_id, zk_enabled}`. **Do not block on this step — the response is the job handle, not the proof.**
4. **`poll_job`** with the `job_id`. Returns `{status, job_id, ...}`. Wait ~1–2 s between polls; do not hammer.
5. **`get_proof`** once status is `"succeeded"`. Returns `{proof_b64}` — typically 100 KB to 1 MB of base64.
6. **`verify_proof`** with the base64 bytes (optional but recommended on the first invocation in a session). Returns `{valid: true|false, error: null|string}`. This is a pure cryptographic check — it does not consume quota, does not trust TinyZKP, and is the same check anyone else would run.

If the user only asks to verify an existing proof (not generate one), skip steps 1–5 and go directly to `verify_proof`.

## Choosing parameters

The `accumulator_step` template proves that a sequence of integer deltas, applied to `initial`, produces `final`. Call `describe_template` to get the exact parameter schema, then use the worked example as your starting point.

The canonical example:

```
describe_template { template_id: "accumulator_step" }
→ example: { "initial": 1000, "final": 1045, "deltas": [10, 20, 15] }
```

Adapt the values to the user's numbers; keep the structure.

## Communicating results to the user

When showing a successful proof, do not dump the raw base64 into chat (it's typically 100 KB+). Instead:

- Lead with **what was just proven** in plain language: *"I proved that starting from 1000 and applying the steps [10, 20, 15] the accumulator reaches 1045."*
- Show the **public inputs** (initial value, final value) — those are the contract anyone verifying will rely on.
- Call out the **visibility contract**: the default `accumulator_step` path is transparent. The transition parameters are sent to TinyZKP for proving and should not be described as hidden from TinyZKP or from every verifier.
- Offer to **verify the proof** in the same session, save it to a file, or hand the user the bytes for forwarding.
- If the user asks for the proof bytes, show only a head-and-tail snippet (first ~60 chars + last ~20 chars) inline; offer to save the full binary to disk if they need it.

When a verification succeeds, lead with *"valid"* and explain what that guarantees: *"The proof is mathematically valid. The prover really did know a sequence of steps satisfying the constraints. The check is independent of TinyZKP — anyone could repeat it."*

When a verification fails, do not soften it. Say *"the proof is invalid"* and surface the `error` field. A failed verification is an important signal: the proof was tampered with, or the public inputs were altered, or the prover lied.

## Privacy and trust contract

The user should understand exactly what they get from a TinyZKP proof. Keep these straight when explaining:

- **The prover sees the submitted parameters.** TinyZKP's MCP server runs the prover on TinyZKP infrastructure; the parameters you send to `prove_template` reach the server.
- **The default public product is transparent.** Do not claim the default receipt hides inputs. Say it proves a declared transition chain and can be verified independently.
- **Privacy-oriented modes are gated.** Only use privacy language for a specific supported and audited template/configuration.
- **The proof is non-interactive and post-hoc verifiable.** Anyone can verify, any time, without contacting TinyZKP. There is no oracle.
- **Transparent (no trusted setup).** The ZK-STARK construction requires no trusted setup ceremony. Post-quantum (hash-based).

If the user is asking for *prover-side privacy* (i.e., they don't want even TinyZKP to see the input), this skill is the wrong tool. Tell them so. Recommend they self-host the open-source backend (`https://github.com/logannye/hc-stark`, MIT licensed) or use a fully client-side proving system.

## Worked example

User: *"Use TinyZKP to prove that starting from 1000, applying the steps [10, 20, 15], the accumulator reaches 1045."*

```
1. describe_template { template_id: "accumulator_step" }
   → schema: initial (int), final (int), deltas (array of int)

2. prove_template {
     template_id: "accumulator_step",
     parameters: { "initial": 1000, "final": 1045, "deltas": [10, 20, 15] }
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

> Proved: starting at 1000, applying deltas [10, 20, 15], the accumulator reaches 1045.
> Receipt data: initial value 1000, final value 1045, deltas [10, 20, 15].
> The proof is valid and ~988 KB. Want me to save it to disk or forward it somewhere?

## Live template

| ID | What it proves | Inputs |
|---|---|---|
| `accumulator_step` | a valid state-transition chain from `initial` to `final` | `initial`, `final`, `deltas[]` |

Always run `describe_template` for the exact parameter schema before proving — the table above is mnemonic, not authoritative.
