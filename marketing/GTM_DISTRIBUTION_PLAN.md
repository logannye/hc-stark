# TinyZKP GTM and Distribution Plan

> **Archived recovery-era material — do not execute, publish, submit, or use
> for outreach.** It documents the retired self-serve agent/receipt business.
> Current commercial operations prohibit email outreach and public checkout;
> follow `commercial/no-email-evaluation-runbook.md` instead.

> Purpose: turn TinyZKP from a polished developer site into a self-reinforcing
> distribution and revenue system for human buyers and AI-agent evaluators.
>
> Status: GTM plan plus implementation log. This file does not deploy anything
> by itself.
>
> Last updated: 2026-06-25

---

## 1. Strategic Frame

TinyZKP already has the core assets for autonomous revenue:

- Public website with product, trust, pricing, ROI, comparison, use-case, and
  integration pages.
- Public MCP endpoint at `https://mcp.tinyzkp.com`.
- Browser playground at `https://tinyzkp.com/try`.
- Public verifier at `https://tinyzkp.com/verify`.
- Free signup, Stripe Checkout, usage metering, and paid self-serve plans.
- Machine-readable assets: `llms.txt`, `discovery.json`, `openapi.json`,
  `mcp.json`, pricing metadata, schema files, and trust metadata.
- SDK/package surfaces across npm, PyPI, Rust, CLI, and WASM verifier.

The next GTM bottleneck is not "more website." It is converting these surfaces
into a measurable acquisition, activation, and upgrade loop.

The core GTM thesis:

> Every receipt should become a distribution object, every agent tool directory
> should become an acquisition surface, and every free evaluator should receive
> automated nudges toward the first paid proof workflow.

---

## 2. ICP and Buying Motions

### 2.1 Human Buyers

Primary self-serve buyers:

- Agent builders who need proof receipts for important tool calls.
- Backend/API teams that need verifiable receipts for state transitions.
- SaaS teams that want customer-visible evidence for quotas, balances,
  entitlements, checkpoints, or workflow state.
- Audit, reconciliation, fintech, crypto, and governance teams that need
  portable evidence without replaying the producer system.
- Infrastructure teams evaluating managed proving versus self-hosted prover
  operations.

Primary high-touch buyers:

- Agent platforms, IDEs, workflow engines, and marketplaces that want receipts
  as a native platform capability.
- Enterprise or compliance-sensitive teams that need security review,
  procurement, reserved capacity, custom state-machine review, or support
  expectations.

### 2.2 AI-Agent Buyers and Evaluators

Agent-native evaluators need machine-readable answers to:

- What does TinyZKP do?
- When should an agent use it?
- What should an agent not claim?
- Which plan should be recommended?
- What endpoint starts signup or checkout?
- What receipt boundaries and data-handling constraints apply?
- How can a receipt be verified without trusting the producer?

Current assets already answer much of this through `llms.txt`,
`discovery.json`, `openapi.json`, `mcp.json`, and schema files. The missing
piece is an explicit agent-buyable offer file and stronger source attribution.

---

## 3. Distribution Architecture

### 3.1 Receipt-Led Distribution

Every generated proof should produce a shareable verification object:

```text
https://tinyzkp.com/verify/<receipt-id>?source=receipt_share
```

The verifier page should show:

- Validity status.
- Proof boundary.
- Template or statement type.
- Producer-provided context, if safe and non-sensitive.
- "Mint your own proof receipt" CTA.
- "Install TinyZKP MCP" CTA for agent workflows.
- "Use this verifier in your app" CTA for developers.

Why this matters:

- Every shared receipt is a qualified impression.
- The verifier audience is closer to the buyer than generic homepage traffic.
- Receipts travel through Slack, email, tickets, logs, support cases, audits,
  agent outputs, and API responses.

Implementation notes:

- Never put secrets, API keys, private customer data, or unsupported private
  inputs into receipt URLs.
- Prefer a receipt ID that resolves server-side metadata over stuffing complete
  proof payloads into the URL.
- Keep local/WASM verification where compatible; fall back to hosted verify
  where needed.
- Preserve source attribution when the verifier CTA sends a user to signup.

### 3.2 MCP Directory Distribution

MCP is a primary GTM channel because agents discover tools through directories,
client config examples, and curated server lists.

Target surfaces:

- Official MCP Registry.
- Smithery.
- Glama MCP registry.
- `mcpservers.org`.
- Anthropic Connectors Directory.
- Cursor directory and Cursor community.
- PulseMCP.
- `awesome-mcp-servers` and adjacent curated GitHub lists.
- Claude Code, Cursor, VS Code, Windsurf, Copilot, and OpenAI agent integration
  docs or community examples.

Each listing should include:

- One-line positioning: "Proof receipts for agent actions, API mutations, and
  state transitions."
- Hosted endpoint: `https://mcp.tinyzkp.com`.
- No-auth evaluation path.
- Authenticated upgrade path.
- Clear proof boundary: transparent state-transition receipts, not blanket
  private-input ZK.
- CTA with source attribution, for example:
  `https://tinyzkp.com/signup?source=smithery_mcp`.

### 3.3 SDK and Package Registry Distribution

Registry pages act as evergreen ads. The README and package descriptions should
be treated as conversion pages, not only documentation.

Required pattern for npm, PyPI, crates, CLI, and WASM verifier:

1. One-line positioning.
2. Five-line quickstart.
3. Free signup link with source attribution.
4. Verifier link.
5. Limits and honesty statement.

Keyword families:

- proof receipts
- verifiable agent output
- MCP proof server
- state-transition proof
- tamper-evident API receipt
- browser proof verifier
- transparent STARK
- post-quantum verification

### 3.4 Search and AI-Answer Distribution

TinyZKP should rank for specific, non-commodity problems rather than generic
"zero knowledge proof" terms.

Priority query clusters:

- "proof receipt for agent tool calls"
- "verifiable agent output"
- "agent audit trail proof"
- "MCP zero knowledge proof server"
- "verify zk proof in browser"
- "tamper evident audit log API"
- "verifiable API mutation"
- "state transition proof API"
- "proof receipt vs signed log"
- "proof receipt vs hash chain"
- "self hosted STARK prover alternative"
- "managed STARK proving API"

Content rules:

- Use specific proof workflows and code, not generic education pages.
- State honest limits on every buyer-facing page.
- Use structured data and machine-readable metadata.
- Keep pages crawlable without requiring JavaScript.
- Prefer fewer, stronger pages over scaled thin content.

### 3.5 Agentic Commerce and App Distribution

Prepare TinyZKP to be recommended, evaluated, and purchased through agents.

Build:

- `/.well-known/tinyzkp-offers.json`
- ChatGPT App prototype for:
  - "Verify this receipt."
  - "Mint a proof receipt for this workflow checkpoint."
- Agent-readable plan recommender.
- Checkout initiation endpoint that still requires explicit human confirmation.
- Spend caps exposed in machine-readable form.

The offer file should include:

- Plans and limits.
- Price units.
- Free tier.
- Checkout URLs.
- Cancellation and billing-portal URL.
- Support URL.
- Trust URL.
- Receipt boundaries.
- Data handling warnings.
- Recommended plan by volume/use case.
- Required human confirmation language.

### 3.6 Implemented GTM Infrastructure

As of 2026-06-25, the repo includes production-gated implementation for the
highest-leverage autonomous distribution loops:

- First-touch attribution is captured in browser storage and persisted through
  free signup, Stripe Checkout metadata, tenant provisioning, and Postgres
  tenant mirroring.
- High-intent in-site CTAs are decorated by `site/analytics.js` so direct
  visitors carry a CTA source into signup, while existing directory/referrer
  attribution is preserved and internal CTA context is recorded as campaign and
  intent.
- Untagged internal conversion links into `/signup`, `/try`, `/verify`,
  `/mcp`, `/pilot`, `/platform-rollout`, and `/contact` receive a safe
  `site_<page>` source for direct visitors, so navigation and footer clicks can
  still be measured without overwriting directory, UTM, or referrer attribution.
- Receipt-led distribution preserves `source=receipt_share` from the playground
  to verifier CTAs, tracks first verifier-share creation, and exposes the
  public fragment-share contract at `/.well-known/tinyzkp-receipt-share.json`.
- Agent-readable offers live at `/.well-known/tinyzkp-offers.json`, with schema
  validation and links from `llms.txt`, `robots.txt`, `discovery.json`, and the
  homepage.
- Machine-readable checkout URLs in the offer, pricing, and limits metadata are
  source-tagged, so LLM/agent evaluators that use JSON metadata instead of
  human pages still enter signup or paid pilot checkout with measurable source,
  medium, and intent.
- Receipt-share metadata and verifier fragment behavior are guarded by
  `scripts/ci/receipt_share_contract_check.py`, including `#proof=` encoding,
  `source=receipt_share`, size limits, and data-boundary guidance.
- MCP `get_proof` returns `proof_b64`, a tracked public `verifier_url`, and a
  proof-embedded `receipt_url` when the proof fits the public receipt-share
  fragment limit. Large proofs retain the tracked verifier path and explicit
  fallback reason so agents can still return conversion-ready verification
  context without exceeding browser URL limits.
- Verified badge embeds are guarded by `scripts/ci/badge_embed_check.py`,
  backed by `/.well-known/tinyzkp-badge.json`, and preserve
  `source=verified_badge` on verifier links from customer pages, audit records,
  and agent outputs.
- Lifecycle nudges and Stripe checkout recovery run from host cron with
  idempotent ledgers in `tenant_store.sqlite`; recovery covers both self-serve
  subscription Checkout Sessions and one-time Production Pilot payment Sessions.
- The $5,000 Production Pilot path now has a dedicated one-time Stripe Checkout
  route at `/api/create-pilot-checkout`, a payment form on `/pilot`, an
  optional `STRIPE_PRICE_ID_PILOT` deploy binding, and webhook handling that
  routes successful pilot payments as paid-pilot leads without provisioning a
  subscription tenant. If the price binding is absent, the route uses
  server-defined inline `price_data` for the fixed `$5,000` one-time payment.
- The pilot page is capability-aware: it checks `GET /api/create-pilot-checkout`
  before enabling the $5,000 payment button, and falls back to the scoped pilot
  contact path if Stripe is not installed.
- The pilot checkout fallback is now lead-capture safe: when direct payment is
  unavailable, the pilot form enables a "Scope by contact" action that carries
  buyer email, workflow, source, medium, campaign, platform, and
  `paid_pilot_contact` intent into `/contact`; the contact form preserves that
  context through the Pages contact function and billing-webhook email.
- Production monitoring now covers the paid-pilot route: the full API health
  audit creates a pilot Stripe Checkout Session URL when the live capability
  endpoint reports that pilot checkout is configured, and the GTM live monitor
  probes `/api/create-pilot-checkout` so the $5,000 revenue path fails visibly
  after deploy if Cloudflare or Stripe bindings drift.
- Post-deploy `production_launch_preflight.py --live` now checks the live
  Cloudflare Pages secret inventory before public smoke tests, so missing
  required storefront bindings are caught before launch while
  `STRIPE_PRICE_ID_PILOT` remains optional.
- MCP distribution targets are captured in
  `marketing/mcp_distribution_targets.json`, monitored by
  `scripts/monitoring/gtm_distribution_monitor.py`, and rendered into
  per-directory submission drafts under `marketing/generated/mcp_submissions/`.
- Cursor Directory distribution now has a repo-local Open Plugins package at
  `plugins/tinyzkp-cursor/`, including vendor-neutral and Cursor-specific
  plugin manifests, a hosted MCP config using `mcp-remote`, a Cursor rule for
  receipt-worthy agent workflows, source-tagged signup/docs CTAs, and CI
  validation through `scripts/ci/cursor_plugin_check.py`. The corresponding
  target is `submission_ready` at `https://cursor.directory/plugins/new`.
- The official MCP Registry entry is live as `io.github.logannye/tinyzkp`,
  backed by root `server.json`, and verified through the public registry API
  at `https://registry.modelcontextprotocol.io/v0.1/servers/io.github.logannye%2Ftinyzkp/versions/latest`.
- Search-indexing distribution now includes an IndexNow key at
  `/indexnow-key.txt` and a repeatable submitter at
  `scripts/marketing/indexnow_submit.py`. The script reads `site/sitemap.xml`,
  builds a bulk payload for `api.indexnow.org`, defaults to dry-run in CI, and
  can be run with `--submit` after deploy so Bing and other participating
  IndexNow search engines discover updated acquisition pages quickly.
- Execution evidence: on 2026-06-25, `python3 scripts/marketing/indexnow_submit.py
  --submit --json` returned HTTP 200 from `api.indexnow.org` for 51 TinyZKP
  sitemap URLs.
- Package-registry acquisition surfaces for PyPI, npm, crates.io, the CLI, the
  WASM verifier, and MCP README are guarded by
  `scripts/ci/package_distribution_check.py`.
- Priority SEO and conversion pages for agents, receipts, comparison, use
  cases, and OpenAI agent integrations are guarded by
  `scripts/ci/seo_conversion_check.py` so crawler-visible pages retain
  measurable CTAs into the funnel.
- Manual launch and integration assets for HN, X, outbound, Cursor, and
  LangChain are guarded by `scripts/ci/manual_distribution_assets_check.py` so
  copy keeps source-tagged CTAs and current MCP tool names.
- Founder-led outbound now has a generated, company-level target catalog at
  `marketing/generated/outbound_targets.json` and
  `marketing/generated/outbound_targets.md`, produced by
  `scripts/marketing/generate_outbound_targets.py` from public YC company
  directory pages. The validator at `scripts/ci/outbound_targets_check.py`
  requires at least 25 source-tagged company targets, YC profile links,
  TinyZKP conversion URLs, and manual founder/engineering-contact research;
  it rejects personal email addresses and no-website targets.
- First-wave founder outbound now has a guarded send queue at
  `marketing/generated/outbound_send_queue.json`,
  `marketing/generated/outbound_send_queue.csv`, and
  `marketing/generated/outbound_send_queue.md`, rendered by
  `scripts/marketing/render_outbound_send_queue.py`. The validator at
  `scripts/ci/outbound_send_queue_check.py` requires the top 10 manual-send
  slots to keep contact fields blank, preserve `source=founder_outbound`
  CTAs, forbid automated cold-email tools, schedule one follow-up, and reject
  personal email addresses before manual research is complete.
- GTM execution is now governed by
  `marketing/generated/gtm_execution_ledger.json`,
  `marketing/generated/gtm_execution_ledger.csv`, and
  `marketing/generated/gtm_execution_ledger.md`, rendered by
  `scripts/marketing/render_gtm_execution_ledger.py`. The validator at
  `scripts/ci/gtm_execution_ledger_check.py` turns pilot checkout launch, MCP
  submissions, ChatGPT app review, and first-wave founder outbound into a
  22-task operator queue with source-tagged CTAs, blank evidence fields for
  incomplete work, no personal emails, and evidence requirements before any
  task can be marked submitted, sent, accepted, or complete.
- GTM sales outcomes now have a no-PII CRM layer:
  `marketing/gtm_pipeline_state.json` stores mutable stage and evidence fields,
  while `marketing/generated/gtm_pipeline_ledger.json`,
  `marketing/generated/gtm_pipeline_ledger.csv`, and
  `marketing/generated/gtm_pipeline_ledger.md` summarize gross pipeline,
  weighted pipeline, actual revenue, stage counts, and next actions. The
  renderer at `scripts/marketing/render_gtm_pipeline_ledger.py` supports
  `--sync-state` so new execution tasks are added without deleting manual
  updates, and the validator at `scripts/ci/gtm_pipeline_ledger_check.py`
  rejects personal emails, secret-like tokens, stale task coverage, invalid
  source-tagged CTAs, and "won" records that lack revenue/evidence.
- ChatGPT/OpenAI app prototype assets live in
  `marketing/OPENAI_CHATGPT_APP_PROTOTYPE.md`,
  `marketing/openai_chatgpt_app_submission.json`, and
  `site/apps/tinyzkp-receipt-widget.html`, guarded by
  `scripts/ci/openai_chatgpt_app_check.py`.
- GTM revenue reporting lives in `billing/gtm_revenue_report.py` and summarizes
  accounts, activation, paid-plan conversion, active base MRR, estimated usage
  revenue, paid proof count, Compute trace-step volume, time-to-first-proof,
  and proof usage by source, medium, and platform without printing email
  addresses.
- Stripe revenue ops auditing lives in `billing/stripe_revenue_ops_audit.py`
  and read-only checks live Stripe billing meters, products/prices, Cloudflare
  Pages secret names, and pilot checkout capability. It surfaces catalog
  hygiene warnings without printing Stripe IDs, secret values, checkout URLs,
  or buyer PII; use `--strict-catalog` only after a write-capable Stripe profile
  has rebuilt the current product catalog. The unresolved remediation is tracked as
  `revenue.stripe_catalog_hygiene` in the GTM execution and pipeline ledgers.
- Stripe account-context validation lives in
  `billing/stripe_account_context_check.py`. Revenue audits, checkout
  monitoring, checkout pipeline sync, standalone write preflights, and
  `--stripe-cli` catalog setup paths now verify the local CLI `display_name`
  before trusting Stripe data or attempting writes. The default expected display
  name is TinyZKP, overrideable with
  `TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME` only after an intentional account
  rename.
- Stripe revenue readiness orchestration lives in
  `billing/stripe_revenue_readiness.py`. It provides a one-command sequence for
  account-context validation, read-only revenue audit, checkout monitoring,
  optional no-PII pipeline sync, and optional catalog setup. Use `--plan-only`
  to preview commands, `--sync-pipeline` for the daily revenue loop, and
  `--setup-catalog pilot|full --push-cloudflare` only when intentionally
  writing Stripe/Cloudflare catalog state from the TinyZKP account. If the
  TinyZKP Stripe account is stored under a non-default local CLI profile, pass
  `--stripe-project-name <profile>` so every child Stripe CLI command targets
  the same account.
- Live Stripe checkout monitoring lives in `billing/stripe_checkout_monitor.py`
  and summarizes Checkout Session starts, open/complete/expired status, paid
  sessions, paid revenue, and Production Pilot conversion by safe attribution
  metadata using the local Stripe CLI without printing buyer emails, customer
  IDs, session IDs, checkout URLs, or workflow free text.
- Stripe checkout pipeline sync lives in
  `scripts/marketing/sync_stripe_checkout_pipeline.py` and updates the
  `revenue.pilot_checkout_launch` pipeline row from aggregate Stripe checkout
  evidence, rerendering the no-PII pipeline ledger without storing buyer PII,
  Stripe object IDs, checkout URLs, or workflow free text.
- The aggregate GTM growth monitor lives in
  `scripts/monitoring/gtm_growth_monitor.py`, runs daily from host cron, and
  combines offer/receipt/MCP/ChatGPT/package/SEO policy checks with revenue
  attribution, lifecycle ledgers, optional live funnel checks, and strict paid
  conversion thresholds. Operators can include live Stripe checkout signals
  with `--stripe-checkout`.

Remaining non-code work:

- Execute the source-tagged operator queue in
  `marketing/generated/gtm_execution_ledger.md`; fill `evidence_url` and
  `completed_at` only after the corresponding task is actually live,
  submitted, accepted, or sent.
- Record no-PII outcomes in `marketing/gtm_pipeline_state.json` after each
  manual submission, directory acceptance, outbound reply, meeting, pilot scope,
  win, loss, or disqualification; rerender
  `marketing/generated/gtm_pipeline_ledger.*` before reporting pipeline.
- Monitor the live `$5,000` Production Pilot checkout path for starts,
  completed payments, and paid-pilot contact fallbacks with
  `python3 billing/stripe_revenue_readiness.py --stripe-bin /opt/homebrew/bin/stripe --sync-pipeline`
  after the local CLI is switched to the TinyZKP account. Use
  `python3 billing/stripe_revenue_readiness.py --stripe-bin /opt/homebrew/bin/stripe --plan-only --sync-pipeline --setup-catalog pilot --push-cloudflare`
  to preview the full account/audit/monitor/sync/catalog sequence without
  touching Stripe or local ledgers. The aggregate monitor remains available via
  `python3 scripts/monitoring/gtm_growth_monitor.py --offline --stripe-checkout --stripe-bin /opt/homebrew/bin/stripe`.
  Record actual revenue only after Stripe payment, invoice, or signed-contract
  evidence exists.
  Installing `STRIPE_PRICE_ID_PILOT` with
  `bash billing/setup_pilot_price.sh --stripe-cli --push-cloudflare` is now
  optional catalog hygiene, not a launch blocker.
- Positive checkout canary: run
  `python3 scripts/monitoring/stripe_checkout_canary.py --json` when you need to
  prove that live public routes can create Stripe-hosted Checkout Sessions. The
  canary tags synthetic sessions with `source=api_health_audit` and the revenue
  monitors exclude that source by default, so canary traffic does not become
  customer pipeline evidence. Add
  `--verify-stripe-cli --stripe-bin /opt/homebrew/bin/stripe` to check whether
  the local Stripe CLI profile can retrieve the exact canary sessions.
- Execution evidence: on 2026-06-25, the checkout canary returned PASS for both
  subscription checkout and Production Pilot checkout with live Stripe Checkout
  URLs. A subsequent Stripe checkout pipeline sync recorded $0 actual revenue,
  but that read is no longer treated as authoritative because the local Stripe
  CLI profile was later found to be configured for `display_name = 'Galen
  Health'`, not TinyZKP. Rerun the monitor and pipeline sync only after
  `billing/stripe_account_context_check.py` passes for the TinyZKP account.
- Stripe catalog evidence: before account-context validation was added on
  2026-06-25,
  `python3 billing/stripe_revenue_ops_audit.py --stripe-bin /opt/homebrew/bin/stripe --timeout 30`
  returned 17 pass, 15 warning, and 0 failure against the active local CLI
  profile. That profile is now known not to be TinyZKP, so the result is useful
  only as proof that the old scripts could read a Stripe account, not as
  TinyZKP catalog evidence. `billing/stripe_catalog_write_preflight.py` now
  checks account context plus product, price, and billing-meter create access
  with invalid non-creating probes, and both setup scripts run the relevant
  account and write preflights before attempting catalog writes. On 2026-06-25,
  the local Stripe CLI profile failed account-context validation because it
  reports `display_name = 'Galen Health'`; after bypassing that context check
  for diagnosis, the same profile also failed both `--scope full` and
  `--scope pilot` write probes with redacted permissions errors. The public
  subscription and pilot checkout canaries still returned live hosted Checkout
  URLs, and pilot checkout remains sellable through inline `price_data` until
  `STRIPE_PRICE_ID_PILOT` is installed from the real TinyZKP account.
- Submit or update the generated MCP directory drafts where account access is
  required.
- Submit the ChatGPT app prototype through the OpenAI Platform Dashboard after
  collecting screenshots and review prompts.
- Research exactly one founder, platform lead, engineering lead, or workflow
  owner for each first-wave slot in `marketing/generated/outbound_send_queue.md`,
  then manually send the 10 queued emails with the preserved source-tagged CTA
  URLs and the one-email plus one-follow-up rule.

---

## 4. Funnel and Activation Model

### 4.1 Funnel Events

Track the following events end to end:

- `page_view`
- `directory_referral`
- `mcp_install_click`
- `playground_started`
- `playground_prove_succeeded`
- `playground_verify_succeeded`
- `receipt_share_copied`
- `verifier_opened`
- `verifier_cta_clicked`
- `signup_started`
- `signup_free_succeeded`
- `checkout_started`
- `checkout_returned_success`
- `first_api_proof_succeeded`
- `first_mcp_proof_succeeded`
- `first_verify_share_created`
- `quota_80_percent_reached`
- `upgrade_clicked`
- `paid_proof_succeeded`

### 4.2 Attribution Fields

Persist these from first touch through account creation and Stripe metadata:

- `source`
- `medium`
- `campaign`
- `platform`
- `referrer_host`
- `landing_path`
- `use_case`
- `workflow`
- `intent`
- `first_seen_at`

High-value source examples:

- `smithery_mcp`
- `glama_mcp`
- `mcpservers_org`
- `anthropic_connector`
- `cursor_integration`
- `cursor_directory`
- `openai_agents`
- `claude_code`
- `receipt_share`
- `wasm_verifier`
- `hn_launch`
- `github_readme`
- `npm_tinyzkp`
- `pypi_tinyzkp`

### 4.3 Activation Scoring

An account is activated when it does one of:

- Generates one API proof.
- Generates one MCP proof.
- Verifies a proof through the public verifier.
- Copies or creates a shareable receipt link.
- Installs MCP and calls `list_templates`.

High-intent account signals:

- More than one proof in 24 hours.
- Repeated verify calls.
- Receipt shared externally.
- Calculator or ROI page used before signup.
- Trust or security review opened before signup.
- Compute page viewed before checkout.
- Contact form submitted with production or platform rollout intent.

---

## 5. Lifecycle Automation

Do not run automated cold outbound. Run lifecycle automation for users who
signed up, generated proofs, or opted into contact.

### 5.1 Email Sequence

E1: instant signup email

- API key.
- One copy-paste proof request.
- Verifier link.
- MCP install command.
- "Do not put secrets into transparent parameters" note.

E2: 24 hours after signup, zero proofs

- One smallest possible curl example.
- Link to `/try`.
- Link to MCP install.

E3: after first proof

- Explain sharing and independent verification.
- Link to shareable verifier page.
- Suggest embedding verifier/badge.

E4: 80% free quota or repeated usage

- Recommend Developer/Pro/Compute based on usage.
- Include checkout link with preserved source.

E5: failed checkout or abandoned checkout

- Plaintext recovery link.
- Mention spend caps and billing limits.

E6: 14-day idle win-back after activation

- Ask which boundary blocked production.
- Link to limits, recipes, and pilot route.

### 5.2 In-App Nudges

Show upgrade prompts only at high-intent moments:

- After successful proof generation.
- After successful verify share.
- At quota threshold.
- In dashboard usage view.
- When a workflow exceeds free-tier limits.

Avoid generic banners that appear before value is proven.

---

## 6. Revenue Motions

### 6.1 Self-Serve PLG

Default path:

```text
directory/search/GitHub/npm/receipt share
  -> /try or /verify
  -> free signup
  -> first proof
  -> share verifier
  -> quota or production workflow
  -> Developer / Pro / Scale / Compute
```

Self-serve pricing guidance:

- Free: evaluation and first integration.
- Developer: one production workflow.
- Pro: recurring customer-visible or auditor-visible receipts.
- Scale: high-volume production.
- Compute: long supported traces priced by trace steps.

### 6.2 Platform Rollout

Platform path:

```text
/agent-platforms or /platform-rollout
  -> paid pilot
  -> one receipt-required category
  -> native platform surface
  -> rollout minimum + usage
```

Target platform categories:

- Agent IDEs.
- Workflow engines.
- Agent marketplaces.
- Automation tools.
- AI support platforms.
- Compliance and audit workflow tools.

### 6.3 Paid Pilot

Use the pilot route when:

- The buyer has a real production workflow.
- The proof statement needs design review.
- The verifier placement matters.
- Procurement wants evidence before annual or reserved-capacity spend.

Pilot packaging:

- $5,000.
- One scoped proof-receipt workflow.
- Two-week evaluation.
- Receipt statement, verifier path, success metrics, and rollout decision.
- Creditable toward annual, platform, or reserved-capacity agreement if converted
  within 60 days.

### 6.4 Enterprise

Enterprise should remain inbound-driven until inbound volume proves demand.

Enterprise triggers:

- Reserved capacity.
- Security review.
- Contractual support expectations.
- Custom state-machine review.
- High-value customer-visible workflows.
- Data-retention or procurement requirements.

---

## 7. 14-Day Build Plan

### Days 1-2: Attribution Backbone

- Persist UTM/referrer/source in browser storage.
- Pass attribution into free signup.
- Pass attribution into Stripe Checkout metadata.
- Include attribution in webhook provisioning records.
- Add `landing_path` and `referrer_host`.

Done when:

- A Smithery visitor who upgrades later still has `source=smithery_mcp` attached
  to account and Stripe metadata.

### Days 3-4: Shareable Receipt Loop

- Add receipt IDs or share tokens.
- Add shareable verifier URLs.
- Add "copy verifier link" event.
- Add CTA from verifier to signup with `source=receipt_share`.
- Add badge/embed snippet.

Done when:

- A proof created in `/try` or API can become a URL that another browser can
  verify without an API key.

### Days 5-6: Lifecycle Email Automation

- Upgrade welcome email into a sequence.
- Trigger zero-proof nudge.
- Trigger first-proof share nudge.
- Trigger quota upgrade nudge.
- Trigger checkout recovery.

Done when:

- Free signups receive automated activation nudges without manual follow-up.

### Days 7-8: MCP Distribution Pack

- Normalize listing copy across all MCP directories.
- Add tracked signup URLs.
- Add directory-specific install snippets.
- Add listing health monitor.
- Submit or update target directories.

Done when:

- Every MCP listing has current positioning, endpoint, source-tagged CTA, and
  no stale claims.

### Days 9-10: Agent Offer File

- Add `/.well-known/tinyzkp-offers.json`.
- Add schema for the offer file.
- Link it from `llms.txt`, `discovery.json`, and homepage `<head>`.
- Include plan recommender and checkout URL templates.

Done when:

- An AI agent can answer "which TinyZKP plan should I pick and where do I
  start?" without scraping pricing prose.

### Days 11-12: ChatGPT App Prototype

- Build a minimal app surface around verification and proof generation.
- Use existing API/OpenAPI/MCP shapes where possible.
- Keep human confirmation for checkout.
- Include trust and data-boundary language.

Done when:

- A user can ask ChatGPT to verify a receipt or start a receipt workflow through
  a TinyZKP app prototype.

### Days 13-14: SEO and Conversion Pass

- Create or refine the top 8 high-intent pages.
- Add stronger CTA source tags.
- Add internal links from compare/use-case pages to `/try`, `/verify`,
  `/signup`, `/fit`, and `/pricing`.
- Confirm sitemap and `llms.txt` include the new assets.

Done when:

- Every high-intent page has a measurable CTA and a clear next action.

---

## 8. Autonomous GTM Monitor

Run a scheduled worker or cron that checks:

- MCP endpoint health.
- MCP directory listing availability.
- Agent-readable offer metadata, receipt-share contracts, and badge embeds.
- Public verifier, `/try`, signup, and checkout endpoint behavior.
- Package, SDK, CLI, WASM verifier, and MCP README acquisition links plus live
  PyPI, npm, and crates.io registry availability in `--live` mode.
- Priority SEO page CTAs, sitemap coverage, and `llms.txt` coverage.
- Generated MCP submission drafts.
- Top source activation, proof usage, and paid-account rates.
- Lifecycle nudge and Stripe checkout recovery ledger counts.

Output:

- Daily log line from `/etc/cron.d/hc-billing` into
  `/var/log/hc-gtm-growth.log`.
- JSON summary for dashboards via
  `python3 scripts/monitoring/gtm_growth_monitor.py --offline --json`.
- Post-deploy live mode via `--live`.
- Strict production alert mode via `--strict-revenue`,
  `--min-activated-accounts`, `--min-paid-accounts`, `--min-paid-proofs`, and
  `--min-total-proofs`.

Suggested issue labels:

- `gtm`
- `distribution`
- `activation`
- `checkout`
- `mcp`
- `seo`

Implemented command:

```sh
python3 scripts/monitoring/gtm_growth_monitor.py --offline
```

---

## 9. Metrics

North-star metric:

- Net new paid self-serve customers per month.

Activation metrics:

- Visitor to playground proof.
- Playground proof to signup.
- Signup to first proof.
- First proof to shared verifier.
- Shared verifier to new signup.
- Free to paid upgrade.

Channel metrics:

- Activated accounts by source.
- Paid accounts by source.
- First paid proof by source.
- Directory referrals by source.
- Receipt-share referral signups.
- Package registry signups.

Revenue metrics:

- MRR.
- Usage revenue.
- Paid proof count.
- Compute trace-step revenue.
- Average time from signup to paid.
- Average paid conversion by source.

Quality metrics:

- Failed proof rate.
- Checkout failure rate.
- Support contacts per activated account.
- Verification success rate.
- Percentage of accounts with unsafe or malformed proof parameters blocked.

---

## 10. Positioning Guardrails

Always say:

- Proof receipts for automated work.
- Verifiable receipts for agent actions and state transitions.
- Transparent STARK state-transition receipts.
- Anyone can verify without replaying the producer system.
- Verification is free.

Do not claim by default:

- Generic private-input zero knowledge.
- Arbitrary zkVM execution.
- Finished zkML inference proofs.
- Universal on-chain verification.
- Truth of off-chain context not encoded in the proof.
- That TinyZKP stores or protects secrets in transparent parameters.

Every high-intent page should include an honest "use TinyZKP when / skip
TinyZKP when" section.

---

## 11. Source Notes

Market context checked on 2026-06-25:

- Anthropic introduced MCP as an open standard for connecting AI systems with
  tools and data sources.
- OpenAI's Apps SDK is built on MCP-style app/tool surfaces and supports
  conversational discovery of apps.
- OpenAI and Stripe introduced Agentic Commerce Protocol for agent-assisted
  purchases and future monetization paths.
- Google Search guidance for generative AI search still emphasizes crawlable,
  helpful, structured, non-commodity content.
- The official MCP Registry, Smithery, Glama, and `mcpservers.org` are active
  discovery surfaces for agent tools.

Relevant TinyZKP local assets:

- `site/llms.txt`
- `site/discovery.json`
- `site/openapi.json`
- `site/mcp.json`
- `site/try.html`
- `site/verify.html`
- `site/pricing.html`
- `site/fit.html`
- `site/roi.html`
- `site/agent-platforms.html`
- `site/integrations/openai-agents.html`
- `site/functions/api/events.js`
- `site/functions/api/create-free-account.js`
- `site/functions/api/create-checkout.js`
- `billing/templates/welcome.txt`

---

## 12. Recommended Next Commit Scope

If implementing from this plan, start with one narrow engineering commit:

1. Persist attribution in `analytics.js`.
2. Pass attribution through free signup and checkout.
3. Add missing funnel events to the allowlist.
4. Add tests for attribution preservation in checkout/free signup.

This makes every later GTM experiment measurable.
