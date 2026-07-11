# TinyZKP Marketing & Launch Assets

> **Archived recovery-era material — do not execute, publish, submit, or use
> for outreach.** These files describe the retired agent/receipt/self-serve
> product. TinyZKP currently permits no email outreach and no public checkout.
> Use `commercial/no-email-evaluation-runbook.md` and applicant-selected
> no-email reply channels for the bounded evaluation program.

This directory holds **drafts** of customer-acquisition assets ready to publish or send. Nothing in here is auto-deployed — every file is a copy/paste artifact for the founder to send manually after final review.

## Live state (as of launch)

| Surface | Status | Verify |
|---|---|---|
| `tinyzkp.com` (homepage with new positioning, JSON-LD, OG image) | **Live** | `curl -I https://tinyzkp.com/ \| grep -i title` |
| `tinyzkp.com/try` (browser playground, no signup) | **Live, fully functional** | Open the URL, click Generate, click Verify |
| `tinyzkp.com/status` (real-time API health) | **Live** | Open the URL |
| `tinyzkp.com/signup` (self-serve monthly plans, Developer at $19) | **Live** | Real Stripe Checkout flows attached |
| Agent-readable offers, receipt-share, and badge metadata | **Live** | `python3 scripts/monitoring/gtm_growth_monitor.py --live --timeout 10` |
| Stripe self-serve products + price IDs in production | **Live** | `wrangler pages secret list --project-name tinyzkp` shows subscription and usage `STRIPE_PRICE_ID_*` |
| Production Pilot one-time checkout | **Live** | `GET /api/create-pilot-checkout` reports `pricing_source=inline_price_data`; direct POST returns a Stripe Checkout Session |
| Production Pilot contact fallback | **Live** | `/pilot` routes unavailable checkout to `/contact` with email, workflow, source, medium, campaign, platform, and intent |
| Founder outbound target catalog | **Ready: 50 YC-sourced company targets** | `python3 scripts/ci/outbound_targets_check.py` |
| Founder outbound first-wave send queue | **Ready: top 10 manual sends** | `python3 scripts/marketing/render_outbound_send_queue.py --check && python3 scripts/ci/outbound_send_queue_check.py` |
| GTM execution ledger | **Ready: 21 revenue/distribution tasks** | `python3 scripts/marketing/render_gtm_execution_ledger.py --check && python3 scripts/ci/gtm_execution_ledger_check.py` |
| GTM pipeline ledger | **Ready: no-PII CRM state and revenue forecast** | `python3 scripts/marketing/render_gtm_pipeline_ledger.py --check && python3 scripts/ci/gtm_pipeline_ledger_check.py` |
| IndexNow search-engine pings | **Submitted after deploy** | `python3 scripts/marketing/indexnow_submit.py --submit` |
| Stripe webhook at `webhook.tinyzkp.com` | **Live** | Subscribed to 4 events, signing secret deployed to `/opt/hc-stark/.env` |
| `@tinyzkp/cli` on npm | **Published v0.1.0** | `npx @tinyzkp/cli@latest healthz` |
| MCP server at `mcp.tinyzkp.com` | **Live** | `claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com` |
| Demo API key in Cloudflare Pages secret | **Set** | `wrangler pages secret list` includes `TINYZKP_DEMO_API_KEY` |
| Production hc-server template handler bug (template_id pre-flight) | **Fixed and deployed** | End-to-end prove → verify works against real templates |

## Contents

| File | What it is | Where to publish |
|---|---|---|
| `GTM_DISTRIBUTION_PLAN.md` | Current GTM and distribution operating plan for revenue, agent discovery, attribution, lifecycle automation, and receipt-led growth | Internal operating doc |
| `MCP_DISTRIBUTION_PACK.md` | Canonical MCP directory copy, source-tagged CTAs, submission checklist, and monitor workflow | MCP directories and agent-IDE communities |
| `mcp_distribution_targets.json` | Machine-readable source of truth for MCP distribution targets and tracked signup URLs | `scripts/monitoring/gtm_distribution_monitor.py` |
| `generated/mcp_submissions/` | Per-directory MCP submission drafts generated from the target catalog | `scripts/marketing/render_mcp_submissions.py` |
| IndexNow submitter | Sitemap-driven bulk indexing notification for Bing and other participating IndexNow search engines | `scripts/marketing/indexnow_submit.py --submit` |
| Receipt-share contract | Public verifier share-link format for receipt-led distribution from `/try`, `/verify`, API, and MCP contexts | `scripts/ci/receipt_share_contract_check.py` |
| Badge embed contract | Public Verified by TinyZKP badge asset, source-tagged verifier embed template, and distribution boundary rules | `scripts/ci/badge_embed_check.py` |
| `OPENAI_CHATGPT_APP_PROTOTYPE.md` + `openai_chatgpt_app_submission.json` | ChatGPT app prototype plan, source-tagged submission metadata, test prompts, and MCP/widget boundaries | OpenAI app review |
| SDK/package README CTAs | Source-tagged registry acquisition links for PyPI, npm, crates.io, WASM verifier, CLI, and MCP install surfaces | `scripts/ci/package_distribution_check.py` |
| Priority SEO/conversion pages | Source-tagged CTAs from agent, receipt, comparison, use-case, and integration pages into the funnel | `scripts/ci/seo_conversion_check.py` |
| Manual launch/outbound assets | Source-tagged HN, X, outbound, Cursor, and LangChain copy with current MCP tool names | `scripts/ci/manual_distribution_assets_check.py` |
| Founder outbound target catalog | Company-level YC target list, fit scoring, source-tagged TinyZKP CTAs, and manual-contact operating rules; no personal emails or auto-send logic | `scripts/marketing/generate_outbound_targets.py --limit 50` and `scripts/ci/outbound_targets_check.py` |
| Founder outbound send queue | First-wave top-10 manual-send queue with blank contact fields, send/follow-up dates, draft copy, CSV import surface, and source-tagged CTAs | `scripts/marketing/render_outbound_send_queue.py --check` and `scripts/ci/outbound_send_queue_check.py` |
| GTM execution ledger | Operator queue for pilot checkout launch, MCP submissions, ChatGPT app review, and first-wave outbound sends with evidence fields and source-tagged CTAs | `scripts/marketing/render_gtm_execution_ledger.py --check` and `scripts/ci/gtm_execution_ledger_check.py` |
| GTM pipeline ledger | No-PII CRM state, stage tracking, gross/weighted pipeline, actual revenue fields, and evidence rules for every execution-ledger task | `scripts/marketing/render_gtm_pipeline_ledger.py --sync-state`, then `scripts/ci/gtm_pipeline_ledger_check.py` |
| GTM revenue report | Attribution, activation, paid-account, MRR, usage-revenue, paid-proof, Compute trace-step, and proof-usage summary by source/medium/platform | `billing/gtm_revenue_report.py` |
| Stripe account-context check | Verifies the active local Stripe CLI profile before revenue reads or catalog writes; default expected display name is TinyZKP | `python3 billing/stripe_account_context_check.py --stripe-bin /opt/homebrew/bin/stripe` |
| Stripe revenue readiness runner | One-command safe sequence for account context, read-only audit, checkout monitor, optional no-PII pipeline sync, and optional catalog setup | `python3 billing/stripe_revenue_readiness.py --stripe-bin /opt/homebrew/bin/stripe --sync-pipeline` |
| Stripe revenue ops audit | Read-only live audit of Stripe billing meters, products/prices, Cloudflare Pages secret names, and pilot checkout capability; fails before reading Stripe when the local CLI account is not TinyZKP | `python3 billing/stripe_revenue_ops_audit.py --stripe-bin /opt/homebrew/bin/stripe` |
| Stripe checkout monitor | No-PII live Checkout Session summary for starts, paid sessions, paid revenue, and Production Pilot conversion using the local Stripe CLI after account-context validation | `python3 billing/stripe_checkout_monitor.py --stripe-bin /opt/homebrew/bin/stripe --lookback-hours 168` |
| Stripe checkout pipeline sync | Updates `revenue.pilot_checkout_launch` in the no-PII pipeline state from aggregate Stripe checkout evidence and rerenders the pipeline ledger after account-context validation | `python3 scripts/marketing/sync_stripe_checkout_pipeline.py --stripe-bin /opt/homebrew/bin/stripe --lookback-hours 168` |
| GTM growth monitor | Aggregate daily growth health check for offers, receipt sharing, MCP/ChatGPT distribution, package/SEO surfaces, revenue attribution, and lifecycle ledgers | `scripts/monitoring/gtm_growth_monitor.py --offline` |
| `HN_LAUNCH.md` | Show HN post draft (title + body) | https://news.ycombinator.com/submit |
| `X_THREAD.md` | 4-post thread for Twitter / X | Founder account |
| `MCP_DIRECTORY.md` | Submission body for Anthropic's MCP directory | Anthropic's MCP submission form / GitHub |
| `INTEGRATION_LANGCHAIN.md` | Integration tutorial: TinyZKP + LangChain agents | Blog + dev.to + LangChain docs PR |
| `INTEGRATION_CURSOR.md` | Integration tutorial: TinyZKP MCP in Cursor | Blog + Cursor community |
| `OUTBOUND_EMAIL.md` | Cold-email template for the 50-account outreach | Founder Gmail / Superhuman |

## Recommended sequence (90-day plan)

> Week 1's "deploy site acquisition surfaces" and `$5,000` Production Pilot
> checkout path are **done**. The pilot route is live with an inline price_data
> fallback, so `STRIPE_PRICE_ID_PILOT` is optional catalog hygiene and can still
> be installed later with
> `bash billing/setup_pilot_price.sh --stripe-cli --push-cloudflare`. If the
> TinyZKP Stripe account is stored under a non-default local CLI profile, add
> `--stripe-project-name <profile>` to Stripe readiness and setup commands.

| Week | Action |
|---|---|
| 1 | Switch the local Stripe CLI to the TinyZKP account, confirm with `python3 billing/stripe_account_context_check.py --stripe-bin /opt/homebrew/bin/stripe`, then run `python3 billing/stripe_revenue_readiness.py --stripe-bin /opt/homebrew/bin/stripe --sync-pipeline`; record revenue only after Stripe payment, invoice, or signed-contract evidence exists |
| 1 | Resolve `revenue.stripe_catalog_hygiene` in `marketing/generated/gtm_execution_ledger.md` only after running `billing/setup_stripe_products.sh` with write-capable live Stripe access, pushing generated Pages secrets, and passing `python3 billing/stripe_revenue_ops_audit.py --stripe-bin /opt/homebrew/bin/stripe --strict-catalog` |
| 1 | After each site deploy, run `python3 scripts/marketing/indexnow_submit.py --submit` so updated acquisition pages are submitted to participating IndexNow engines |
| 1–2 | Work from `marketing/generated/gtm_execution_ledger.md`; fill `evidence_url` and `completed_at` only after the task is actually submitted, sent, accepted, or live |
| 1–2 | After each manual action, update `marketing/gtm_pipeline_state.json`, rerender with `python3 scripts/marketing/render_gtm_pipeline_ledger.py`, and verify with `python3 scripts/ci/gtm_pipeline_ledger_check.py` |
| 2 | Submit `MCP_DIRECTORY.md` to Anthropic; submit PRs against LangChain/LlamaIndex/Cursor integration docs using `INTEGRATION_LANGCHAIN.md` and `INTEGRATION_CURSOR.md` |
| 3 | Post `HN_LAUNCH.md` on Tuesday morning ET; ship `X_THREAD.md` 30 minutes after the HN post hits the front page |
| 4–8 | Run `python3 scripts/marketing/generate_outbound_targets.py --limit 50`, then `python3 scripts/marketing/render_outbound_send_queue.py`, verify with `python3 scripts/ci/outbound_targets_check.py` and `python3 scripts/ci/outbound_send_queue_check.py`, then send from `marketing/generated/outbound_send_queue.md` using `OUTBOUND_EMAIL.md`. 10 manual emails/day, M/T/W |
| 5–8 | Kick off SOC 2 Type 1 with Drata or Vanta |
| 8–12 | First conference talk; second case study; usage-based overage live |

Every asset is intentionally short. Don't over-edit them — ship.
