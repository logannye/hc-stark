# Anthropic MCP Directory Submission

This is the canonical packet for submitting **TinyZKP** to the Anthropic MCP / connector directory. It is structured to mirror the actual fields the submission form asks for, per https://claude.com/docs/connectors/building/submission.

> **Form to use:** "MCP directory submission form" (remote MCP, since `mcp.tinyzkp.com` is internet-hosted). The Desktop Extension form is **not** the right one for us — `hc-mcp-stdio` ships as a binary, not as an `.mcpb` bundle.
>
> If review correspondence is needed (firewall, tenant restrictions, escalation): **mcp-review@anthropic.com**.

---

## 0. Pre-submission checklist

Run through this before hitting submit. Every box must be true.

- [x] Privacy policy is live and HTTPS: https://tinyzkp.com/privacy
- [x] Terms of service are live and HTTPS: https://tinyzkp.com/terms
- [x] Public quickstart documentation is live: https://tinyzkp.com/docs and https://github.com/logannye/hc-stark
- [x] Every tool has a `title` annotation (`crates/hc-mcp/src/lib.rs` — 10 production tools, confirmed by `cargo build -p hc-mcp`)
- [x] Every tool has `read_only_hint` and `destructive_hint` annotations
- [x] HTTP transport validates `Origin` header (`crates/hc-mcp/src/bin/hc-mcp-http.rs`, allowlist includes `claude.ai`)
- [x] `mcp.tinyzkp.com` serves over HTTPS with a valid certificate
- [x] Free tier exists so a reviewer can test without a credit card
- [x] Test account credentials prepared (see §6)
- [x] 3 PNG screenshots ready at `marketing/screenshots/shot{1,2,3}_*.png` (1400×620, real data from live MCP — see §8)
- [x] Server logo at `marketing/screenshots/logo-1024.png` ready to upload (see §8)

---

## 1. Server basics

| Field | Value |
|---|---|
| **Name** | TinyZKP |
| **Display name** | TinyZKP — Transparent State-Transition Attestation |
| **Server URL** | https://mcp.tinyzkp.com |
| **Homepage** | https://tinyzkp.com |
| **Repository** | https://github.com/logannye/hc-stark |
| **License** | MIT |
| **Category** | Developer Tools (primary), Security & Cryptography (secondary) |
| **GA date** | Live since 2026-04-25. Free tier (100 proofs/month) requires no credit card. |

### Tagline (≤80 chars)

> Prove a state transition as a tool call. Anyone verifies it in ~5 ms. Free 100/month, no card.

### One-paragraph description

TinyZKP is a hosted ZK-STARK service that exposes transparent state-transition attestation as a native MCP tool. An agent can mint a cryptographic receipt that a committed value advanced from an initial value to a final value by a declared, ordered set of steps — in a single tool call — then hand that receipt to any counterparty or auditor for independent offline verification in about 5 ms, with no trusted setup and post-quantum by construction. The free tier ships with 100 proofs/month and no credit card. The proving stack runs in O(√T) memory via height-compressed streaming, which keeps heavy state-transition traces on commodity hardware.

### Use cases (3–5 bullets)

- **Verifiable state-transition receipts.** An agent tracking a running total or state machine (a balance, a spend counter, a step chain) can attach a cryptographic proof that the reported transition is arithmetically consistent — start at X, apply these declared steps, reach Y — tamper-evident and verifiable offline. (Hiding the intermediate steps is opt-in ZK, not the default; do not imply input privacy unless it is enabled.)
- **Accumulator / audit-chain proofs.** Prove a running total or state machine advanced from a known initial value to a known final value via a sequence of declared steps.
- **Off-chain compute attestation.** Prove a computation produced a given output, so a downstream consumer can accept the result without re-executing.
- **Tamper-evident receipts.** Any process that needs a verifiable "this happened" receipt can mint one as a single tool call and hand it to the user for independent verification.

---

## 2. Connection details

| Field | Value |
|---|---|
| **Transport protocol** | Streamable HTTP (`POST /mcp`) — the modern MCP transport. Stdio also available via `hc-mcp-stdio` binary for desktop clients, but the directory listing should point at the remote URL. |
| **Authentication type** | None today. The endpoint is public and rate-limited via a server-side concurrency cap (`HC_MCP_MAX_INFLIGHT=2`). API-key Bearer enforcement and per-tenant quota are tracked as a follow-up — see §3. |
| **Read/write capabilities** | Reads: list/describe templates and workloads, poll job, get proof, verify proof. Writes (in the sense of consuming quota and creating server-side jobs): `prove_template`, `prove_workload`. No external mutation outside the user's own tenant. |
| **Connection requirements** | Internet access to `mcp.tinyzkp.com` (port 443). API key in `TINYZKP_API_KEY` env var or `Authorization: Bearer tzk_…` header. |
| **Origin validation** | The HTTP transport validates the `Origin` header against an allowlist that includes `https://claude.ai`, the Anthropic API, and TinyZKP's own domains. Configurable via `HC_MCP_ALLOWED_ORIGINS`. |
| **Rate limiting** | Per-tenant quota enforced server-side. Free tier: 100 proofs/month. Higher tiers: see https://tinyzkp.com/#pricing. |

### One-line install

```
claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com
```

---

## 3. Note on authentication (read this before reviewing)

The Anthropic submission requirements list "OAuth 2.0 for authenticated services." The current TinyZKP MCP endpoint is **unauthenticated** — anyone with the URL can call any of the 10 tools, capped only by a server-side concurrency limit (`HC_MCP_MAX_INFLIGHT=2`).

This is intentional for the launch:

1. **No protected user resource exists yet on the MCP path.** The MCP server runs the prover in-process and does not touch the per-tenant quota database; every MCP call is treated as anonymous. There is nothing for an attacker to steal — only proving CPU, which is rate-limited at the server.
2. **Free tier means there is no paywall to authenticate.** The 100-proofs/month quota lives on the JSON-HTTP API at `api.tinyzkp.com` (which *does* require Bearer keys). The reviewer can exercise every MCP tool without any credential.
3. **Roadmap.** Per-tenant Bearer enforcement (forwarding the `Authorization` header and metering against the same store as the JSON API) is on the roadmap. We will ship it before any paid plan gates MCP access. If Anthropic considers unauthenticated access disqualifying, we will accelerate this work — please flag it in the first round of review and we'll turn it around in 1–2 weeks.

---

## 4. Tools, resources & prompts

**Tools (10 total).** All tools declare `title`, `read_only_hint`, `destructive_hint`, `idempotent_hint`, and `open_world_hint` annotations per `crates/hc-mcp/src/lib.rs`.

| Tool | Title | Read-only | Destructive | Idempotent |
|---|---|:-:|:-:|:-:|
| `list_templates` | List Proof Templates | ✓ | ✗ | ✓ |
| `list_workloads` | List Workloads | ✓ | ✗ | ✓ |
| `describe_template` | Describe Proof Template | ✓ | ✗ | ✓ |
| `get_capabilities` | Get Server Capabilities | ✓ | ✗ | ✓ |
| `prove_template` | Generate Proof from Template | ✗ | ✗ | ✗ |
| `prove_workload` | Generate Proof from Workload | ✗ | ✗ | ✗ |
| `poll_job` | Poll Proof Job Status | ✓ | ✗ | ✓ |
| `verify_proof` | Verify Proof | ✓ | ✗ | ✓ |
| `get_proof` | Get Proof Bytes | ✓ | ✗ | ✓ |
| `get_proof_summary` | Get Proof Summary | ✓ | ✗ | ✓ |

Proof templates available via `list_templates` include `accumulator_step` (state-transition / accumulator proofs). Call `list_templates` for the current live catalog.

No tool is marked `destructive` because none mutates anything outside the calling tenant's own job queue. The `prove_*` family is non-read-only because each call consumes quota and creates a job record.

**Resources:** none (this is intentional — proofs are returned via tool responses).
**Prompts:** none.

---

## 5. Data & compliance

| Question | Answer |
|---|---|
| What data does the server collect? | Tenant ID, request metadata (template ID, parameter sizes, duration), and result status. Program contents and proof byte streams are not retained beyond delivery. See https://tinyzkp.com/privacy. |
| Where is data stored? | Hetzner (Falkenstein, DE). PostgreSQL for tenant/usage; ephemeral disk for in-flight proof artifacts. |
| Third-party connections? | Stripe (billing), Cloudflare Pages (marketing site / browser playground only — does not touch MCP traffic). |
| Health data? | No. |
| Personal / sensitive data sent to LLMs? | No — TinyZKP does not call any LLM or pass user data to third-party AI providers. |
| Data retention? | Usage logs retained for billing/audit. Account data retained while active and 90 days after deletion. |
| Encryption in transit / at rest? | TLS 1.3 in transit (Caddy + Let's Encrypt). Tenant DB encrypted at rest by Hetzner volume encryption. |

---

## 6. Test account for the reviewer

The MCP endpoint is currently public and unauthenticated, so **no test credential is required**. The reviewer can install in one line and exercise every tool with no key:

```
claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com
```

If the reviewer also wants to exercise the **JSON-HTTP API** at `api.tinyzkp.com` (which is the real per-tenant billed surface, not strictly required for the MCP review), provide a fresh API key in the form's private test-account field:

```
# On the production tenant DB (Hetzner):
docker exec hc-stark-hc-server-1 hc-admin issue-key \
    --label "anthropic-mcp-reviewer" \
    --plan developer \
    --quota-override 5000
```

**Email contact for the reviewer:** logan@tinyzkp.com

---

## 7. Step-by-step setup instructions for an unfamiliar reviewer

Paste this verbatim into the "setup instructions" field.

> **Setup (30 seconds, no signup, no API key):**
>
> 1. Run: `claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com`
> 2. In a new Claude Code session, ask: *"Use the tinyzkp MCP to list all available proof templates."* → expect at least `accumulator_step` in the catalog.
> 3. Ask: *"Use the accumulator_step template to prove that an account moved from 1000 to 1045 via the deltas [10, 20, 15]."* → expect a `job_id`, then `poll_job` returns `succeeded`, then `get_proof` returns base64 proof bytes.
> 4. Ask: *"Use verify_proof on the proof you just generated."* → expect `{valid: true}`.
>
> **Browser-only smoke test (no setup at all):**
>
> Open https://tinyzkp.com/try in any browser. Click "Generate proof." Click "Verify." This exercises the same backend with no signup.

---

## 8. Assets to upload

### Server logo

- **Source SVG:** [`site/favicon.svg`](../site/favicon.svg)
- **Hosted PNG (1024×1024):** [`marketing/screenshots/logo-1024.png`](./screenshots/logo-1024.png) — pre-rendered.

### Screenshots (3 PNGs, 1400×620, response-only crops)

The three submission screenshots live in [`marketing/screenshots/`](./screenshots/) and were generated from real MCP data captured against the live `mcp.tinyzkp.com` endpoint. Each is 1400 × 620 PNG (well above the 1000px minimum). Reproduce or regenerate at any time with `python3 marketing/screenshots/render_shots.py`.

| # | File | What it shows | Paired prompt for the form |
|---|---|---|---|
| 1 | `shot1_state_transition.png` | `prove_template` with the `accumulator_step` template — proves an account moved from an initial balance to a final balance via a sequence of declared deltas. Shows the returned job and base64 proof blob. | "Use TinyZKP to prove that this account balance moved from 1000 to 1045 via the deltas [10, 20, 15]." |
| 2 | `shot2_verify.png` | `verify_proof` on the proof from shot 1 — returns `valid: true` in under a second. Demonstrates that anyone can independently verify without trusting TinyZKP. | "Now verify that proof independently — show me that anyone in the world could do this same check without trusting TinyZKP." |
| 3 | `shot3_agent_state_transition.png` | `prove_template` with the `accumulator_step` template — proves an agent's state machine advanced from a declared start to a declared end via a sequence of recorded steps, transferably verifiable by any third party offline. | "Use TinyZKP's accumulator_step template to prove that this agent's running total moved from 0 to 945 via these steps, so an auditor can verify it without re-running anything." |

The three shots cover the complete narrative the directory carousel needs to tell: **(1)** the headline use-case (mint a transparent state-transition receipt), **(2)** the trust model (independent verification), **(3)** a second accumulator example that demonstrates the shape across domains. Anthropic's submission requirements ask for 3–5; we ship 3 intentional ones rather than 5 mediocre ones.

---

## 9. Allowed link URIs (`ui/open-link`)

We do not currently use the `ui/open-link` capability — all responses are inline text/JSON. Leave this section blank on the form.

(If we later add inline "open in dashboard" links, the allowlist will be `https://tinyzkp.com` and `https://api.tinyzkp.com`, both org-owned.)

---

## 10. Compliance attestations (for the form's checklist section)

Tick all of:

- [x] I agree to the **Anthropic Software Directory Terms**.
- [x] I agree to the **Anthropic Software Directory Policy**.
- [x] All tools have a `title` field. *(Verify: `grep -c 'annotations(title' crates/hc-mcp/src/lib.rs` returns 10.)*
- [x] All tools have appropriate `read_only_hint` / `destructive_hint` annotations.
- [x] The server is served over HTTPS with a valid TLS certificate.
- [x] The server validates the `Origin` header. *(See `crates/hc-mcp/src/bin/hc-mcp-http.rs`, `validate_origin` middleware.)*
- [x] I have published documentation (https://tinyzkp.com/docs, repo README).
- [x] I have published a privacy policy (https://tinyzkp.com/privacy).
- [x] I have tested the server with at least one Anthropic surface (Claude Code via `claude mcp add`).
- [x] I will respond to security-vulnerability reports promptly.
- [x] All listed link allowlist domains are owned by my organization. *(N/A — not using `ui/open-link`.)*

---

## 11. Cover note (optional "anything else" field on the form)

> TinyZKP turns ZK-STARK proving into a primitive that an AI agent can use the same way it uses a database lookup. The wedge is the free tier (100 proofs/month, no card) plus the streaming O(√T)-memory prover that lets us price an order of magnitude below the alternatives. Open-source backend: github.com/logannye/hc-stark.
>
> The bearer-key auth (rather than OAuth) is a deliberate choice for a dev-tools service that has no third-party identity to delegate; happy to add OAuth in a follow-up if that is a hard requirement for inclusion. We are based in San Francisco and will respond to any review feedback within 24 hours.

---

## 12. Post-acceptance follow-ups

- [ ] Add the directory listing URL to the homepage as a trust badge (replaces the "live" badge in the hero).
- [ ] Mention it in the Show HN post (`marketing/HN_LAUNCH.md`) — directory listings move that audience.
- [ ] Add it to the X thread (`marketing/X_THREAD.md`).
- [ ] Watch `Referrer: claude.ai/directory*` in the logs for the first 14 days. If it's the top channel, double down on directory metadata richness (more screenshots, demo video).
- [ ] Add to the LangChain / Cursor integration tutorials (`marketing/INTEGRATION_*.md`).
