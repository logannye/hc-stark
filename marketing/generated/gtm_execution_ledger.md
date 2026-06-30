# TinyZKP GTM Execution Ledger

Generated from checked-in GTM artifacts dated `2026-06-25`.

This ledger is the operator queue for revenue-critical work that still requires account access, manual review, or founder contact research. It deliberately does not contain personal email addresses and does not send messages.

## Manual Rules

- Do not mark a task complete until completed_at and evidence_url are filled.
- Do not automate cold outbound email sends.
- Do not add personal email addresses to generated artifacts.
- Preserve every source-tagged TinyZKP CTA URL when submitting or sending.
- Record accepted listing URLs, sent dates, replies, and paid-pilot outcomes back into this ledger or the source system after manual action.

## Summary

- Total tasks: 22
- Manual/account-required tasks: 16
- Active listing monitors: 2
- Founder outbound sends queued: 10

## Revenue Binding

### revenue.pilot_checkout_launch — $5K Production Pilot checkout

- Status: `completed`
- Owner: founder
- Type: `live_checkout_verification`
- Due date: 2026-06-25
- Primary CTA: https://tinyzkp.com/pilot?source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_checkout
- Secondary CTA: https://tinyzkp.com/contact?category=Paid%20Pilot&source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_contact
- Source artifact: `site/functions/api/create-pilot-checkout.js`
- Evidence command: `python3 scripts/ci/production_launch_preflight.py --live`
- Evidence URL: https://tinyzkp.com/api/create-pilot-checkout
- Next action: Monitor pilot checkout starts, completed payments, and paid-pilot contact fallbacks; record revenue only after Stripe or invoice evidence exists.
- Blocker: None; live route uses inline price_data when STRIPE_PRICE_ID_PILOT is absent.
### revenue.stripe_catalog_hygiene — Current Stripe product and price catalog

- Status: `external_secret_required`
- Owner: founder
- Type: `stripe_catalog_audit`
- Due date: 2026-06-25
- Primary CTA: https://tinyzkp.com/pricing?source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_signup
- Secondary CTA: https://tinyzkp.com/pilot?source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_checkout
- Source artifact: `billing/setup_stripe_products.sh`
- Evidence command: `python3 billing/stripe_revenue_ops_audit.py --stripe-bin /opt/homebrew/bin/stripe --strict-catalog`
- Next action: Switch the local Stripe CLI to the LN Holdings account used for TinyZKP, confirm billing/stripe_account_context_check.py passes, then run bash billing/setup_stripe_products.sh --stripe-cli --stripe-bin /opt/homebrew/bin/stripe --push-cloudflare with write-capable live access and rerun the strict revenue-ops audit.
- Blocker: Requires the LN Holdings Stripe account used for TinyZKP plus write-capable live API key or CLI profile; the current local CLI profile reports display_name='Galen Health' and is not authoritative for TinyZKP catalog or revenue evidence.

## MCP Directory Submissions

### mcp_submission.smithery — Smithery

- Status: `active_listing_monitor`
- Owner: founder
- Type: `directory_submission`
- Primary CTA: https://tinyzkp.com/signup?source=smithery_mcp&medium=mcp_directory&platform=smithery&intent=mcp_install
- Secondary CTA: https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install
- Submission URL: https://smithery.ai/new
- Source artifact: `marketing/generated/mcp_submissions/smithery.md`
- Evidence command: `python3 scripts/monitoring/gtm_distribution_monitor.py --offline`
- Evidence URL: https://smithery.ai/servers/logan/tinyzkp-mcp
- Next action: Monitor accepted listing for current copy and source-tagged CTA.
### mcp_submission.official_mcp_registry — Official MCP Registry

- Status: `active_listing_monitor`
- Owner: founder
- Type: `directory_submission`
- Primary CTA: https://tinyzkp.com/signup?source=official_mcp_registry&medium=mcp_directory&platform=modelcontextprotocol&intent=mcp_install
- Secondary CTA: https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install
- Submission URL: https://modelcontextprotocol.io/registry/quickstart
- Source artifact: `marketing/generated/mcp_submissions/official_mcp_registry.md`
- Evidence command: `python3 scripts/monitoring/gtm_distribution_monitor.py --offline`
- Evidence URL: https://registry.modelcontextprotocol.io/v0.1/servers/io.github.logannye%2Ftinyzkp/versions/latest
- Next action: Monitor accepted listing for current copy and source-tagged CTA.
### mcp_submission.mcp_so — mcp.so

- Status: `submitted`
- Owner: founder
- Type: `directory_submission`
- Primary CTA: https://tinyzkp.com/signup?source=mcp_so&medium=mcp_directory&platform=mcp_so&intent=mcp_install
- Secondary CTA: https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install
- Submission URL: https://mcp.so/submit
- Source artifact: `marketing/generated/mcp_submissions/mcp_so.md`
- Evidence command: `python3 scripts/monitoring/gtm_distribution_monitor.py --offline`
- Evidence URL: https://github.com/chatmcp/mcpso/issues/2916
- Next action: Follow up on mcp.so review, then update the public listing URL when accepted.
- Blocker: Awaiting directory review or merge.
### mcp_submission.glama — Glama MCP Registry

- Status: `ready_for_manual_submission`
- Owner: founder
- Type: `directory_submission`
- Primary CTA: https://tinyzkp.com/signup?source=glama_mcp&medium=mcp_directory&platform=glama&intent=mcp_install
- Secondary CTA: https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install
- Submission URL: https://glama.ai/mcp
- Source artifact: `marketing/generated/mcp_submissions/glama.md`
- Evidence command: `python3 scripts/monitoring/gtm_distribution_monitor.py --offline`
- Next action: Submit marketing/generated/mcp_submissions/glama.md through the target account or PR flow.
- Blocker: Requires account access or a manual PR/submission flow.
### mcp_submission.mcpservers_org — mcpservers.org

- Status: `submitted`
- Owner: founder
- Type: `directory_submission`
- Primary CTA: https://tinyzkp.com/signup?source=mcpservers_org&medium=mcp_directory&platform=mcpservers_org&intent=mcp_install
- Secondary CTA: https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install
- Submission URL: https://mcpservers.org
- Source artifact: `marketing/generated/mcp_submissions/mcpservers_org.md`
- Evidence command: `python3 scripts/monitoring/gtm_distribution_monitor.py --offline`
- Evidence URL: https://mcpservers.org/submit
- Next action: Follow up on mcpservers.org review, then update the public listing URL when accepted.
- Blocker: Awaiting directory review or merge.
### mcp_submission.anthropic_connectors — Anthropic Connectors Directory

- Status: `ready_for_manual_submission`
- Owner: founder
- Type: `directory_submission`
- Primary CTA: https://tinyzkp.com/signup?source=anthropic_connector&medium=mcp_directory&platform=anthropic&intent=mcp_install
- Secondary CTA: https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install
- Submission URL: https://claude.com/docs/connectors/building/submission
- Source artifact: `marketing/generated/mcp_submissions/anthropic_connectors.md`
- Evidence command: `python3 scripts/monitoring/gtm_distribution_monitor.py --offline`
- Next action: Submit marketing/generated/mcp_submissions/anthropic_connectors.md through the target account or PR flow.
- Blocker: Requires account access or a manual PR/submission flow.
### mcp_submission.pulsemcp — PulseMCP

- Status: `manual_submission_required`
- Owner: founder
- Type: `directory_submission`
- Primary CTA: https://tinyzkp.com/signup?source=pulsemcp&medium=mcp_directory&platform=pulsemcp&intent=mcp_install
- Secondary CTA: https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install
- Submission URL: https://www.pulsemcp.com
- Source artifact: `marketing/generated/mcp_submissions/pulsemcp.md`
- Evidence command: `python3 scripts/monitoring/gtm_distribution_monitor.py --offline`
- Next action: Submit marketing/generated/mcp_submissions/pulsemcp.md through the target account or PR flow.
- Blocker: Requires account access or a manual PR/submission flow.
### mcp_submission.cursor_directory — Cursor Directory

- Status: `ready_for_manual_submission`
- Owner: founder
- Type: `directory_submission`
- Primary CTA: https://tinyzkp.com/signup?source=cursor_directory&medium=mcp_directory&platform=cursor&intent=mcp_install
- Secondary CTA: https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install
- Submission URL: https://cursor.directory/plugins/new
- Source artifact: `marketing/generated/mcp_submissions/cursor_directory.md`
- Evidence command: `python3 scripts/monitoring/gtm_distribution_monitor.py --offline`
- Next action: Submit marketing/generated/mcp_submissions/cursor_directory.md through the target account or PR flow.
- Blocker: Requires account access or a manual PR/submission flow.
### mcp_submission.awesome_mcp_servers — awesome-mcp-servers

- Status: `submitted`
- Owner: founder
- Type: `directory_submission`
- Primary CTA: https://tinyzkp.com/signup?source=awesome_mcp_servers&medium=mcp_directory&platform=github&intent=mcp_install
- Secondary CTA: https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install
- Submission URL: https://github.com/punkpeye/awesome-mcp-servers
- Source artifact: `marketing/generated/mcp_submissions/awesome_mcp_servers.md`
- Evidence command: `python3 scripts/monitoring/gtm_distribution_monitor.py --offline`
- Evidence URL: https://github.com/punkpeye/awesome-mcp-servers/pull/8733
- Next action: Follow up on awesome-mcp-servers review, then update the public listing URL when accepted.
- Blocker: Awaiting directory review or merge.

## Agent App Submission

### agent_app.openai_chatgpt_app_submission — OpenAI ChatGPT app review

- Status: `ready_for_manual_submission`
- Owner: founder
- Type: `app_review_submission`
- Due date: 2026-06-25
- Primary CTA: https://tinyzkp.com/signup?source=openai_chatgpt_app&medium=chatgpt_app&platform=openai&intent=mcp_install
- Secondary CTA: https://tinyzkp.com/.well-known/tinyzkp-offers.json?source=openai_chatgpt_app&medium=chatgpt_app&platform=openai&intent=agent_offer
- Submission URL: https://platform.openai.com
- Source artifact: `marketing/openai_chatgpt_app_submission.json`
- Evidence command: `python3 scripts/ci/openai_chatgpt_app_check.py`
- Next action: Submit the ChatGPT app prototype with widget URL, MCP endpoint, screenshots, and review prompts.
- Blocker: Requires OpenAI Platform Dashboard account access and reviewer submission.

## Founder Outbound Sends

### outbound_send.01.alter — Alter

- Status: `ready_after_manual_contact_research`
- Owner: founder
- Type: `manual_email`
- Due date: 2026-06-29
- Follow-up date: 2026-07-06
- Primary CTA: https://tinyzkp.com/fit?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=find_route&workflow=alter
- Secondary CTA: https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow=alter
- Source artifact: `marketing/generated/outbound_send_queue.md`
- Evidence command: `python3 scripts/ci/outbound_send_queue_check.py`
- Next action: Research exactly one Founder, head of engineering, or workflow owner and send one human email from the generated draft.
- Blocker: Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.
### outbound_send.02.korso — Korso

- Status: `ready_after_manual_contact_research`
- Owner: founder
- Type: `manual_email`
- Due date: 2026-06-29
- Follow-up date: 2026-07-06
- Primary CTA: https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow=korso
- Secondary CTA: https://tinyzkp.com/calculator?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=calculator&workflow=korso
- Source artifact: `marketing/generated/outbound_send_queue.md`
- Evidence command: `python3 scripts/ci/outbound_send_queue_check.py`
- Next action: Research exactly one Founder, head of engineering, or workflow owner and send one human email from the generated draft.
- Blocker: Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.
### outbound_send.03.redouble-ai — Redouble AI

- Status: `ready_after_manual_contact_research`
- Owner: founder
- Type: `manual_email`
- Due date: 2026-06-29
- Follow-up date: 2026-07-06
- Primary CTA: https://tinyzkp.com/fit?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=find_route&workflow=redouble-ai
- Secondary CTA: https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow=redouble-ai
- Source artifact: `marketing/generated/outbound_send_queue.md`
- Evidence command: `python3 scripts/ci/outbound_send_queue_check.py`
- Next action: Research exactly one Founder, platform lead, or agent product owner and send one human email from the generated draft.
- Blocker: Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.
### outbound_send.04.cyberdesk — Cyberdesk

- Status: `ready_after_manual_contact_research`
- Owner: founder
- Type: `manual_email`
- Due date: 2026-06-29
- Follow-up date: 2026-07-06
- Primary CTA: https://tinyzkp.com/fit?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=find_route&workflow=cyberdesk
- Secondary CTA: https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow=cyberdesk
- Source artifact: `marketing/generated/outbound_send_queue.md`
- Evidence command: `python3 scripts/ci/outbound_send_queue_check.py`
- Next action: Research exactly one Founder, platform lead, or agent product owner and send one human email from the generated draft.
- Blocker: Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.
### outbound_send.05.inkeep — Inkeep

- Status: `ready_after_manual_contact_research`
- Owner: founder
- Type: `manual_email`
- Due date: 2026-06-29
- Follow-up date: 2026-07-06
- Primary CTA: https://tinyzkp.com/fit?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=find_route&workflow=inkeep
- Secondary CTA: https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow=inkeep
- Source artifact: `marketing/generated/outbound_send_queue.md`
- Evidence command: `python3 scripts/ci/outbound_send_queue_check.py`
- Next action: Research exactly one Founder, platform lead, or agent product owner and send one human email from the generated draft.
- Blocker: Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.
### outbound_send.06.archal — Archal

- Status: `ready_after_manual_contact_research`
- Owner: founder
- Type: `manual_email`
- Due date: 2026-06-29
- Follow-up date: 2026-07-06
- Primary CTA: https://tinyzkp.com/fit?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=find_route&workflow=archal
- Secondary CTA: https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow=archal
- Source artifact: `marketing/generated/outbound_send_queue.md`
- Evidence command: `python3 scripts/ci/outbound_send_queue_check.py`
- Next action: Research exactly one Founder, platform lead, or agent product owner and send one human email from the generated draft.
- Blocker: Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.
### outbound_send.07.godhands — GodHands

- Status: `ready_after_manual_contact_research`
- Owner: founder
- Type: `manual_email`
- Due date: 2026-06-29
- Follow-up date: 2026-07-06
- Primary CTA: https://tinyzkp.com/signup?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=api_key&workflow=godhands
- Secondary CTA: https://tinyzkp.com/?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=learn&workflow=godhands
- Source artifact: `marketing/generated/outbound_send_queue.md`
- Evidence command: `python3 scripts/ci/outbound_send_queue_check.py`
- Next action: Research exactly one Founder, developer-experience lead, or senior engineer and send one human email from the generated draft.
- Blocker: Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.
### outbound_send.08.tiny — Tiny

- Status: `ready_after_manual_contact_research`
- Owner: founder
- Type: `manual_email`
- Due date: 2026-06-29
- Follow-up date: 2026-07-06
- Primary CTA: https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow=tiny
- Secondary CTA: https://tinyzkp.com/calculator?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=calculator&workflow=tiny
- Source artifact: `marketing/generated/outbound_send_queue.md`
- Evidence command: `python3 scripts/ci/outbound_send_queue_check.py`
- Next action: Research exactly one Founder, head of engineering, or workflow owner and send one human email from the generated draft.
- Blocker: Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.
### outbound_send.09.coasty — Coasty

- Status: `ready_after_manual_contact_research`
- Owner: founder
- Type: `manual_email`
- Due date: 2026-06-29
- Follow-up date: 2026-07-06
- Primary CTA: https://tinyzkp.com/fit?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=find_route&workflow=coasty
- Secondary CTA: https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow=coasty
- Source artifact: `marketing/generated/outbound_send_queue.md`
- Evidence command: `python3 scripts/ci/outbound_send_queue_check.py`
- Next action: Research exactly one Founder, platform lead, or agent product owner and send one human email from the generated draft.
- Blocker: Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.
### outbound_send.10.corsair — Corsair

- Status: `ready_after_manual_contact_research`
- Owner: founder
- Type: `manual_email`
- Due date: 2026-06-29
- Follow-up date: 2026-07-06
- Primary CTA: https://tinyzkp.com/fit?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=find_route&workflow=corsair
- Secondary CTA: https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow=corsair
- Source artifact: `marketing/generated/outbound_send_queue.md`
- Evidence command: `python3 scripts/ci/outbound_send_queue_check.py`
- Next action: Research exactly one Founder, platform lead, or agent product owner and send one human email from the generated draft.
- Blocker: Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.
