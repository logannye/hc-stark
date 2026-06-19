# TinyZKP — Autonomous, Self-Service Growth Operating System

> **Purpose.** Run TinyZKP as a hands-off, high-margin passive side business: a
> self-service product where discovery, conversion, billing, and support
> deflection all happen **without a human in the loop**. This doc replaces the
> high-touch playbooks (`OUTBOUND_EMAIL.md`, `USER_INTERVIEWS.md`,
> `HN_LAUNCH.md` as a recurring effort) with an inbound machine you build once.
>
> **Status:** strategy + ready-to-use assets. Nothing here auto-deploys.

---

## 0. The honest frame (read this first)

A passive business and "outbound sales" are mutually exclusive. Cold outbound
that converts requires a human replying within 15 minutes (see the now-retired
`OUTBOUND_EMAIL.md`), and automated cold email gets spam-flagged and burns the
founder's sending domain. **So we do zero cold outbound.** Instead we build
*inbound infrastructure* — discovery surfaces and a self-serve funnel — that
earns signups and dollars while you sleep.

Three consequences to accept up front:

1. **ACV is capped at what people pay without a call:** Free → Developer $19 →
   Pro $79 → Scale $199 → the Compute meter. The $15k–$40k/yr design-partner
   contracts (the highest-WTP path in the strategy review) are **out of scope** —
   they are a job, not passive income. If you ever want them, that's a different
   business mode.
2. **Absolute revenue will be modest; margin will be excellent.** Marginal cost
   is ~$0 on the fixed Hetzner box, so even 20–50 self-serve subscribers is
   steady, near-100%-margin income. Target shape: *ramen-profitable, set-and-
   forget*, not a venture outcome.
3. **The product must sell itself in 60 seconds to a stranger.** That raises the
   bar on honest, self-evident copy — which is exactly why the positioning was
   moved off "verifiable receipts for AI agents" (a free signed hash-chain wins
   that, so a self-serve stranger never converts) and onto **transparent
   state-transition attestation** (the one audited thing the engine actually
   does that a signature can't: transferable, no-re-execution, post-quantum
   verification anyone can run offline).

**The optimization target is dollars-per-founder-hour, not dollars.** Every
section below is chosen to add revenue without adding recurring work.

---

## 1. The self-service ICP (who converts without talking to you)

Not "AI agent builders." The stranger who finds TinyZKP via an MCP directory or
npm, gets it in 60 seconds, and pays on a card is one of:

- **Crypto-native / web3 infra developers** — already buy proving/infra
  self-serve, already understand STARKs and off-chain WASM verification, and
  want a transparent state/commitment attestation as a drop-in API.
- **Backend/platform devs who want a tamper-evident, third-party-verifiable
  audit trail** for a running counter/ledger/aggregate, and don't want to roll
  their own crypto. "Anyone can verify it, free, forever" is the hook.
- **Compliance-curious engineers** at high-risk-AI / fintech shops doing an
  early "can we make our state log independently verifiable?" spike (the
  self-serve front door to the SOC-2-gated Article-12 buyer; no sales motion).

Disqualifier baked into the copy: anyone whose need is "attest that my agent did
X" is told, implicitly, that a signature suffices — so they self-select out
instead of signing up and churning.

---

## 2. The autonomous channel stack (build once, runs forever)

Ranked by leverage-per-hour. Items 1–4 are set-and-forget; item 5 is a slow
compounding engine; item 6 is a one-time spike.

### 2.1 MCP directory presence — set and forget
The single best fit for a passive ZK-infra tool: directories are evergreen
discovery you configure once.
- **Smithery** — listed. Re-publish after the `smithery.yaml` reframe (done in
  this repo) so the catalog shows the new positioning.
- **Anthropic MCP directory** — submit using `MCP_DIRECTORY.md` (reframed).
  One-time web form.
- **mcp.so** — submit using `MCP_DIRECTORY_MCPSO.md`. One-time.
- **`glama.ai/mcp`, `mcpservers.org`, `cursor.directory`, PulseMCP** — submit
  the same packet. Each is a free, permanent backlink + discovery surface.
- Maintenance: ~0. Re-check listings once a quarter.

### 2.2 Package-registry discovery — set and forget
Your SDKs are already published; the READMEs are the ad. Make each registry page
lead with the new one-liner + a 5-line quickstart that ends in a free signup
link:
- npm: `tinyzkp`, `@tinyzkp/cli`, `@tinyzkp/verify`
- PyPI: `tinyzkp`
- crates.io: `tinyzkp`
Keyword-load the descriptions: *zk-stark, state-transition proof, verifiable
attestation, post-quantum, transparent, audit trail*. Maintenance: ~0.

### 2.3 The free browser playground (`/try`) + viral verify loop
The `/try` page (live, no signup) is your top-of-funnel. Add one passive loop:
after a user generates a proof, give them a **shareable verify link** ("Send
this — anyone can verify it in 5 ms, no account") that opens a public
`@tinyzkp/verify` WASM page showing ✓ valid, with a "Mint your own → free" CTA.
Every shared proof is a free impression to a pre-qualified stranger. Build once.

### 2.4 SEO use-case pages — the compounding inbound engine (see §5)
Programmatic landing pages that rank for high-intent, low-competition queries.
The classic dev-tools passive growth motion. Slow to start, compounds for years,
zero recurring work after publish.

### 2.5 One-time Show HN (founder spike, then passive)
Post once, re-anchored on the **√T streaming architecture + the reproducible
memory sweep** (not agent receipts), with an honest statement of the √T time
trade-off and that zkVM/zkML are in development. Use the rewritten
`HN_LAUNCH.md`. Be present for 3 hours that one morning; then it's a permanent
backlink and a traffic spike that seeds the SEO flywheel. Do **not** make HN a
recurring obligation.

### 2.6 What NOT to do (these are not passive)
- ❌ Cold email / automated outreach (spam-flagged, domain-burning, needs human
  replies).
- ❌ Recurring social posting cadence, "content calendars," paid ads on a
  pre-PMF infra tool (negative ROI, ongoing labor).
- ❌ Conference talks, webinars, design-partner sales, SOC 2 — all are
  high-touch revenue modes you've opted out of.

---

## 3. Self-serve conversion funnel (100% Stripe, no calls)

```
MCP directory / npm / SEO / HN
        │
        ▼
   tinyzkp.com  ──►  /try (no-signup playground)  ──►  "aha": a valid proof
        │                                                     │
        ▼                                                     ▼
   /signup (free, no card)  ──────────────────────────►  Stripe Checkout
        │   (self-serve, Free → Developer/Compute)            (Developer/Pro/Scale/Compute)
        ▼
   lifecycle email automation (§4)  ──►  activation + upgrade, hands-off
```

Every step is already self-serve (Stripe Checkout is live). The only additions
are the lifecycle automation (§4) and removing every friction point that would
make a stranger need to email you (covered by docs, §6).

---

## 4. Lifecycle email automation — the *compliant* "autonomous outbound"

This is the only automated email you should run: **transactional + lifecycle
messages to people who signed up**, not cold strangers. It runs on autopilot via
a cheap ESP wired to your signup/usage events.

**Minimal stack:** [Loops.so](https://loops.so) or Resend + a Cloudflare
Function that fires events on signup / first-proof / quota-threshold / card-add.
~2 hours one-time wiring; then fully automatic. Budget: $0–$30/mo.

**The sequence (ready to paste — keep them plaintext, founder-from address):**

**E1 — Instant, on signup (transactional):**
> Subject: Your TinyZKP API key
> Your key: `tzk_...`  ·  Free tier: 100 proofs/month, no card.
> Mint your first proof in 60 seconds: [quickstart link]
> Reply if anything's unclear — it comes straight to me. — Logan

**E2 — +24h, only if zero proofs minted (activation nudge):**
> Subject: 60 seconds to your first proof
> You grabbed a key but haven't minted yet. Here's the smallest possible
> example — copy/paste, done: [one curl block]
> What are you trying to attest? Reply and I'll point you at the right shape.

**E3 — +3 days, only if ≥1 proof minted (deepen):**
> Subject: Hand your proof to someone who doesn't trust you
> The point of a TinyZKP receipt is that your counterparty verifies it
> themselves — offline, in ~5 ms, no access to your system. Here's the WASM
> verifier: [link]. Drop it in their stack in 3 lines.

**E4 — On hitting ~80% of free quota (upgrade trigger, the money email):**
> Subject: You're at 80% of your free proofs
> Nice — you're actually using it. Developer ($19/mo) unlocks 100 RPM, 4
> concurrent jobs, and a $500/mo cap; or skip the plan and pay-as-you-go on the
> Compute meter ($0.50/M trace steps). Upgrade in two clicks: [Stripe link]

**E5 — +14 days idle after activation (win-back, one shot):**
> Subject: Still need verifiable state transitions?
> If TinyZKP wasn't the right fit, a one-line reply tells me why and I'll stop
> emailing. If it was a missing feature, tell me which — it's the only thing
> that changes the roadmap.

Rules: one founder-from sender, plaintext, no images/attachments (deliverability),
hard stop after E5. This is the autonomous engine that turns free signups into
$19–$199/mo subscribers without you touching it.

---

## 5. SEO content engine (the compounding passive asset)

Goal: own the long tail of "how do I prove/verify a state transition / audit
trail" queries. One page template, filled per use case, published once, ranks
for years.

**Page template** (`/use-cases/<slug>`, match `site/` styling):
`H1 = the buyer's outcome` · problem (3 sentences) · "the TinyZKP receipt"
(what `accumulator_step` attests, honestly) · 5-line code block ending in a
free-signup CTA · "verify it yourself" (`@tinyzkp/verify`) · honest limits (what
it does *not* prove). `<title>`/meta tuned to the target query.

**Keyword map (high-intent, low-competition, honest-to-the-product):**

| Slug | Target query | Angle |
|---|---|---|
| `proof-of-reserves-attestation` | "proof of reserves api / attestation" | running-total state commitment |
| `tamper-evident-audit-log` | "tamper evident audit log api" | append-only state-transition receipt |
| `verifiable-state-transition` | "verifiable state transition proof" | the core primitive, defined |
| `post-quantum-stark-proving` | "transparent post-quantum stark prover" | no-trusted-setup angle vs SNARKs |
| `offline-proof-verification` | "verify zk proof in browser wasm" | the free 5 ms WASM verifier |
| `mcp-zero-knowledge-proof` | "mcp zk proof server / tool" | the MCP install, the one novel channel |

Write 6 pages once (an afternoon, or have an assistant draft them against the
template). Maintenance after publish: ~0. This is what turns the one-time HN
spike into a permanent traffic floor.

> **Disclosure ceiling — never violate it.** No page may claim input-hiding
> privacy, a finished 100M-step proof, or that zkVM/zkML is
> available. The shipped, audited default path proves a **public** delta chain.
> An honesty slip on a security product is a permanent credibility loss and you
> won't be there to talk a confused buyer down.

---

## 6. Support deflection (so it stays hands-off)

A self-serve product still needs to *look* maintained without consuming you:
- **Docs deflect tickets.** Keep `tinyzkp.com/docs` copy-pasteable and current;
  most "how do I" emails should be answerable by a doc link.
- **Status page** (`/status`, live) deflects "is it down?" — keep it honest.
- **Support email autoresponder:** "Thanks — I read every message and reply
  within 2 business days. For quickstart help, [docs]; for outages, [status]."
  Sets an async expectation you can actually keep.
- **Triage cadence:** 30 minutes, twice a week. That's the *entire* recurring
  human commitment if §1–§5 are built. Do not promise SLAs (they'd chain you to
  a pager); reserve SLAs for the Enterprise "contact us" lane you can ignore
  until inbound forces the issue.

---

## 7. Pricing config for self-serve (apply in `pricing.json` + Stripe)

Tuned for hands-off PLG (full rationale in the strategy review). Lead with the
**Compute meter**; demote subscriptions to convenience; drop the sales tiers from
the storefront.

- **Free** → raise to a **50M trace-steps/mo** meter budget (from 100 proofs/$5
  cap) so a technical evaluator can prove a *real* trace before paying. Marginal
  cost ≈ 0.
- **Developer $19** → keep; purge every `$9` (done in this repo's marketing
  files; verify Stripe shows $19).
- **Pro $79** (new self-serve rung) → surface the existing `team` economics
  (0.75 discount, 8 inflight, 300 RPM) in Stripe to bridge the $19→$199 gap.
- **Scale $199** → keep, demote narratively.
- **Compute $0.50/M steps** → make it the homepage CTA; **add a $0.05/proof
  floor** so tiny-proof spraying can't run sub-cost.
- **Enterprise** → inbound-only "contact us"; no proactive effort.

Storefront principle: feature **Free → Compute meter**, with the subscriptions as
a secondary "prefer a flat monthly plan?" footnote. Five prominent tiers is
decision-paralysis for a self-serve stranger.

---

## 8. The one metric, and the one switch trigger

**Track one number:** *net new self-serve paid subscribers / month* (Stripe
dashboard, zero extra tooling). If the inbound machine works, it climbs on its
own. If it's flat at zero for 60 days after §2–§5 are live, the market is telling
you the truth.

**Switch trigger (be honest with yourself):** if 90 days after the machine is
built you have **zero paying self-serve customers**, the passive-ZK-attestation
thesis is falsified at self-serve ACV. Two honest options then:
1. **Accept it as a free OSS project + permanent MCP demo** (near-zero cost to
   keep running; it's a credential and a backlink), and stop spending hours on
   it; or
2. **Switch modes deliberately** to the high-touch design-partner motion from the
   strategy review — which is real revenue but is a *job*, not passive income.

Either way, the machine above costs you ~1 hour/week to run, so the downside is
bounded and the experiment is cheap.

---

## 9. One-time build checklist (then you're done)

- [ ] Deploy the reframed site copy (`site/index.html`, `site/compute.html`) — review `git diff`, then `wrangler pages deploy` / push.
- [ ] Re-publish Smithery (reframed `smithery.yaml`); submit Anthropic + mcp.so + glama + cursor.directory + PulseMCP.
- [ ] Rewrite the 3 SDK registry READMEs (npm/PyPI/crates) to the new one-liner + keyworded description.
- [ ] Wire the §4 lifecycle automation (Loops/Resend + signup/usage webhooks).
- [ ] Add the §2.3 shareable WASM-verify loop to `/try`.
- [ ] Publish the 6 §5 SEO pages.
- [ ] Apply the §7 pricing changes in `pricing.json` + Stripe; verify parity tests pass.
- [ ] Add the §6 support autoresponder.
- [ ] Post the one-time reframed Show HN.
- [ ] Set a recurring 30-min, twice-weekly triage block. That's the job now.
