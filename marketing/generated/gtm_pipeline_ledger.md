# TinyZKP GTM Pipeline Ledger

This no-PII ledger tracks GTM execution outcomes, pipeline value, and revenue evidence after manual submissions, outbound sends, and pilot checkout setup.

## Privacy Rules

- Do not commit personal email addresses, phone numbers, private CRM notes, API keys, or customer secrets.
- Use evidence URLs, public listing URLs, task IDs, and aggregate outcomes instead of personal contact details.
- Record actual revenue only after Stripe, invoice, or signed-contract evidence exists.

## Summary

- Total records: 22
- Open records: 22
- Gross pipeline: $57,280
- Weighted pipeline: $7,669
- Actual revenue recorded: $0

## Stage Counts

| Stage | Count |
|---|---:|
| `blocked_external_secret` | 1 |
| `company_research_ready` | 10 |
| `live_monitoring` | 3 |
| `ready_to_submit` | 5 |
| `submitted` | 3 |

## Pipeline Records

| Task | Stage | Target | Weighted | Next action |
|---|---|---|---:|---|
| `revenue.pilot_checkout_launch` | `live_monitoring` | $5K Production Pilot checkout | $1,500 | Monitor pilot checkout starts, completed payments, and paid-pilot contact fallbacks; record revenue only after Stripe or invoice evidence exists. |
| `revenue.stripe_catalog_hygiene` | `blocked_external_secret` | Current Stripe product and price catalog | $0 | Switch the local Stripe CLI to the TinyZKP account, confirm billing/stripe_account_context_check.py passes, then run bash billing/setup_stripe_products.sh --stripe-cli --stripe-bin /opt/homebrew/bin/stripe --push-cloudflare with write-capable live access and rerun the strict revenue-ops audit. |
| `mcp_submission.smithery` | `live_monitoring` | Smithery | $11 | Monitor accepted listing for current copy, endpoint health, and source-tagged CTA attribution. |
| `mcp_submission.official_mcp_registry` | `live_monitoring` | Official MCP Registry | $11 | Monitor accepted listing for current copy, endpoint health, and source-tagged CTA attribution. |
| `mcp_submission.mcp_so` | `submitted` | mcp.so | $18 | Follow up on mcp.so review, then update the evidence URL when the public listing is accepted. |
| `mcp_submission.glama` | `ready_to_submit` | Glama MCP Registry | $18 | Submit marketing/generated/mcp_submissions/glama.md through the target account or PR flow. |
| `mcp_submission.mcpservers_org` | `submitted` | mcpservers.org | $18 | Follow up on mcpservers.org review, then update the evidence URL when the public listing is accepted. |
| `mcp_submission.anthropic_connectors` | `ready_to_submit` | Anthropic Connectors Directory | $18 | Submit marketing/generated/mcp_submissions/anthropic_connectors.md through the target account or PR flow. |
| `mcp_submission.pulsemcp` | `ready_to_submit` | PulseMCP | $18 | Submit marketing/generated/mcp_submissions/pulsemcp.md through the target account or PR flow. |
| `mcp_submission.cursor_directory` | `ready_to_submit` | Cursor Directory | $18 | Submit marketing/generated/mcp_submissions/cursor_directory.md through the target account or PR flow. |
| `mcp_submission.awesome_mcp_servers` | `submitted` | awesome-mcp-servers | $18 | Follow up on awesome-mcp-servers review, then update the evidence URL when the public listing is accepted. |
| `agent_app.openai_chatgpt_app_submission` | `ready_to_submit` | OpenAI ChatGPT app review | $18 | Submit the ChatGPT app prototype with widget URL, MCP endpoint, screenshots, and review prompts. |
| `outbound_send.01.alter` | `company_research_ready` | Alter | $600 | Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft. |
| `outbound_send.02.korso` | `company_research_ready` | Korso | $600 | Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft. |
| `outbound_send.03.redouble-ai` | `company_research_ready` | Redouble AI | $600 | Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft. |
| `outbound_send.04.cyberdesk` | `company_research_ready` | Cyberdesk | $600 | Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft. |
| `outbound_send.05.inkeep` | `company_research_ready` | Inkeep | $600 | Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft. |
| `outbound_send.06.archal` | `company_research_ready` | Archal | $600 | Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft. |
| `outbound_send.07.godhands` | `company_research_ready` | GodHands | $600 | Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft. |
| `outbound_send.08.tiny` | `company_research_ready` | Tiny | $600 | Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft. |
| `outbound_send.09.coasty` | `company_research_ready` | Coasty | $600 | Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft. |
| `outbound_send.10.corsair` | `company_research_ready` | Corsair | $600 | Use the company-level research packet to manually identify exactly one founder or engineering owner, then send one human email from the generated draft. |
