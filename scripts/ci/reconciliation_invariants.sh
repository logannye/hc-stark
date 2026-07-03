#!/usr/bin/env bash
# Guard the public TinyZKP reconciliation story against silent regressions.
#
# Default mode checks local files only and is safe for CI.
# `--live` additionally checks production canaries after a coordinated deploy.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

MODE="${1:-local}"
SITE_URL="${SITE_URL:-https://tinyzkp.com}"
API_URL="${API_URL:-https://api.tinyzkp.com}"

failures=0

fail() {
  printf 'FAIL  %s\n' "$*" >&2
  failures=$((failures + 1))
}

pass() {
  printf 'PASS  %s\n' "$*"
}

require_file() {
  local file="$1"
  if [ -f "$file" ]; then
    pass "$file exists"
  else
    fail "$file is missing"
  fi
}

require_contains() {
  local file="$1"
  local marker="$2"
  local label="$3"
  if grep -Fq -- "$marker" "$file"; then
    pass "$label"
  else
    fail "$label (missing marker: $marker)"
  fi
}

require_regex() {
  local file="$1"
  local regex="$2"
  local label="$3"
  if grep -Eq "$regex" "$file"; then
    pass "$label"
  else
    fail "$label (missing pattern: $regex)"
  fi
}

require_no_regex() {
  local regex="$1"
  local label="$2"
  shift 2
  local matches
  matches=$(grep -RInE "$regex" "$@" 2>/dev/null || true)
  if [ -z "$matches" ]; then
    pass "$label"
  else
    fail "$label"
    printf '%s\n' "$matches" >&2
  fi
}

require_url_contains() {
  local url="$1"
  local marker="$2"
  local label="$3"
  local body
  if ! body=$(curl -fsSL --max-time 30 "$url" 2>/dev/null); then
    fail "$label (request failed: $url)"
    return
  fi
  if grep -Fq "$marker" <<<"$body"; then
    pass "$label"
  else
    fail "$label (missing live marker: $marker)"
  fi
}

require_file site/research.html
require_file site/security.html
require_file .github/CODEOWNERS
require_file CHANGELOG.md
require_file billing/lifecycle_nudges.py
require_file billing/checkout_recovery.py
require_file billing/setup_pilot_price.sh
require_file billing/gtm_revenue_report.py
require_file billing/stripe_revenue_ops_audit.py
require_file billing/usage_pg_tools.py
require_file billing/tenant_pg_tools.py
require_file crates/hc-server/sql/tenant_auth_pg.sql
require_file docs/governance/release_policy.md
require_file docs/runbooks/incident_response.md
require_file docs/runbooks/release_provenance.md
require_file docs/strategy/reconciliation_roadmap.md
require_file docs/runbooks/2026-06-23-reconciliation-deploy.md
require_file site/analytics.js
require_file site/.well-known/tinyzkp-offers.json
require_file site/.well-known/tinyzkp-receipt-share.json
require_file site/.well-known/tinyzkp-badge.json
require_file site/schemas/tinyzkp-offers.schema.json
require_file site/schemas/tinyzkp-receipt-share.schema.json
require_file site/schemas/tinyzkp-badge.schema.json
require_file site/apps/tinyzkp-receipt-widget.html
require_file site/functions/api/create-pilot-checkout.js
require_file site/functions/api/events.js
require_file server.json
require_file glama.json
require_file plugins/tinyzkp-cursor/.plugin/plugin.json
require_file plugins/tinyzkp-cursor/.cursor-plugin/plugin.json
require_file plugins/tinyzkp-cursor/.mcp.json
require_file plugins/tinyzkp-cursor/README.md
require_file plugins/tinyzkp-cursor/rules/tinyzkp-proof-receipts.mdc
require_file plugins/tinyzkp-cursor/CHANGELOG.md
require_file marketing/OPENAI_CHATGPT_APP_PROTOTYPE.md
require_file marketing/openai_chatgpt_app_submission.json
require_file marketing/MCP_DISTRIBUTION_PACK.md
require_file marketing/mcp_distribution_targets.json
require_file marketing/gtm_pipeline_state.json
require_file marketing/generated/mcp_submissions/index.md
require_file marketing/generated/outbound_targets.json
require_file marketing/generated/outbound_targets.md
require_file marketing/generated/outbound_send_queue.json
require_file marketing/generated/outbound_send_queue.csv
require_file marketing/generated/outbound_send_queue.md
require_file marketing/generated/outbound_research_packets.json
require_file marketing/generated/outbound_research_packets.md
require_file marketing/generated/gtm_execution_ledger.json
require_file marketing/generated/gtm_execution_ledger.csv
require_file marketing/generated/gtm_execution_ledger.md
require_file marketing/generated/gtm_pipeline_ledger.json
require_file marketing/generated/gtm_pipeline_ledger.csv
require_file marketing/generated/gtm_pipeline_ledger.md
require_file site/indexnow-key.txt
require_file scripts/monitoring/gtm_distribution_monitor.py
require_file scripts/monitoring/gtm_growth_monitor.py
require_file scripts/monitoring/host_cron_env.sh
require_file scripts/monitoring/daily_growth_decision_cron.sh
require_file scripts/monitoring/stripe_checkout_canary.py
require_file scripts/marketing/generate_outbound_targets.py
require_file scripts/marketing/render_outbound_send_queue.py
require_file scripts/marketing/enrich_outbound_research.py
require_file scripts/marketing/render_gtm_execution_ledger.py
require_file scripts/marketing/render_gtm_pipeline_ledger.py
require_file scripts/marketing/render_mcp_submissions.py
require_file scripts/marketing/indexnow_submit.py
require_file scripts/marketing/sync_stripe_checkout_pipeline.py
require_file scripts/marketing/sync_outbound_research_pipeline.py
require_file scripts/monitoring/shared_dispatch_smoke.sh
require_file scripts/ci/site_route_check.py
require_file scripts/ci/site_deploy_check.py
require_file scripts/ci/site_worker_dispatch_test.mjs
require_file scripts/ci/test_analytics_attribution.mjs
require_file scripts/ci/compose_config_check.py
require_file scripts/ci/launch_gate_audit.py
require_file scripts/ci/production_launch_preflight.py
require_file scripts/ci/cloudflare_pages_secret_check.py
require_file scripts/ci/release_identity_check.py
require_file scripts/ci/offer_metadata_check.py
require_file scripts/ci/receipt_share_contract_check.py
require_file scripts/ci/test_receipt_share_contract_check.py
require_file scripts/ci/badge_embed_check.py
require_file scripts/ci/test_badge_embed_check.py
require_file scripts/ci/openai_chatgpt_app_check.py
require_file scripts/ci/package_distribution_check.py
require_file scripts/ci/seo_conversion_check.py
require_file scripts/ci/test_seo_conversion_check.py
require_file scripts/ci/test_gtm_growth_monitor.py
require_file scripts/ci/manual_distribution_assets_check.py
require_file scripts/ci/test_manual_distribution_assets_check.py
require_file scripts/ci/outbound_targets_check.py
require_file scripts/ci/test_outbound_target_pipeline.py
require_file scripts/ci/outbound_send_queue_check.py
require_file scripts/ci/test_outbound_send_queue.py
require_file scripts/ci/cursor_plugin_check.py
require_file scripts/ci/test_cursor_plugin_check.py
require_file scripts/ci/gtm_execution_ledger_check.py
require_file scripts/ci/test_gtm_execution_ledger.py
require_file scripts/ci/gtm_pipeline_ledger_check.py
require_file scripts/ci/test_gtm_pipeline_ledger.py
require_file scripts/ci/server_card_check.py
require_file scripts/ci/backup_restore_check.py
require_file scripts/ci/deploy_readiness_check.py
require_file deploy/hetzner/install_billing_runtime.sh

require_contains site/research.html "One company, one thesis: space-efficient proving." "research page states the unified thesis"
require_contains site/research.html "space-efficient-zero-knowledge-proofs" "research page names the legacy repo"
require_contains site/research.html "not the hosted production engine" "research page excludes legacy repo from hosted production"
require_contains site/research.html "Why the product moved to STARKs" "research page explains current product direction"

require_contains site/security.html "Current production scope" "security page documents production scope"
require_contains site/security.html "accumulator_step" "security page names current live template"
require_contains site/security.html "Responsible disclosure" "security page includes disclosure channel"

require_contains site/docs.html "Template Lifecycle" "docs include lifecycle section"
require_contains site/docs.html "<h1>Documentation</h1>" "docs include primary page heading"
require_contains site/docs.html "Research Lineage" "docs include research-lineage section"
require_contains site/docs.html "WASM-First Verification" "docs include client-side verification section"
require_contains site/docs.html "Interactive API Reference" "docs include API reference section"
require_contains site/docs.html "SDK &amp; Verifier Compatibility" "docs include SDK compatibility section"
require_contains site/docs.html "API Versioning &amp; Deprecation" "docs include API versioning and deprecation section"
require_contains site/docs.html "GET https://api.tinyzkp.com/version" "docs expose API release identity endpoint"
require_contains site/docs.html "Local Development &amp; Self-Hosting" "docs include local development section"
require_contains site/docs.html "Template discovery includes a machine-readable <code>lifecycle</code> field." "docs describe lifecycle API field"
require_contains site/docs.html "data-copy-code" "docs wire code-copy controls"
require_contains site/docs.html "docs_copy" "docs track code-copy activation"
require_contains site/docs.html "allow_legacy_v2</code> exists only for explicit legacy verification" "docs scope legacy proof verification"
require_contains site/docs.html "HC_SERVER_API_KEYS=dev:tzk_dev" "docs include local API run command"
require_contains site/docs.html "no API key required for the public lane" "docs describe hosted MCP anonymous lane"
require_contains site/docs.html "Optional <code>Authorization: Bearer tzk_...</code>" "docs describe optional MCP Bearer auth"
require_contains site/docs.html "list_templates" "docs list current MCP tool names"
require_contains site/docs.html "verify_proof" "docs list MCP verification tool"
require_contains site/status.html "mcp.tinyzkp.com/.well-known/mcp/server-card.json" "status page checks MCP server card"
require_contains deploy/server-card.json "accumulator_step available now" "MCP server-card states the live template"
require_contains site/mcp.json "source=receipt_share and medium=mcp" "MCP metadata documents receipt-share attribution"
require_contains crates/hc-mcp/src/tools/output.rs "source={RECEIPT_SHARE_SOURCE}&medium={RECEIPT_SHARE_MEDIUM}" "MCP get_proof builds tracked verifier URLs"
require_contains crates/hc-mcp/src/tools/output.rs "MAX_RECEIPT_SHARE_ENCODED_CHARS: usize = 120_000" "MCP receipt URLs honor public share-link size limit"
require_contains site/status.html "Incident categories and response targets" "status page documents incident categories"
require_contains site/status.html "Billing and account" "status page includes billing incident category"
require_contains site/privacy.html "Product analytics" "privacy policy documents product analytics"
require_contains site/privacy.html "do not include proof bytes, API keys, email addresses, or form contents" "privacy policy bounds analytics collection"
require_contains site/account.html "status:         data.status" "account dashboard preserves server-reported session status"
require_contains site/account.html 'id="nav-cta-btn"' "account dashboard exposes nav CTA hook for signed-in state"
require_contains site/account.html "first-proof-panel" "account dashboard includes zero-proof activation panel"
require_contains site/account.html "account_first_proof_panel_seen" "account dashboard tracks zero-proof activation panel"
require_contains site/account.html ".login-view::before{width:320px;height:320px;top:-120px}" "account mobile glow stays within viewport"
require_contains site/_worker.js "SECURITY_HEADERS" "Pages worker applies baseline browser security headers"
require_contains site/_worker.js "releaseInfo" "Pages worker exposes release identity for deploy skew checks"
require_contains site/_worker.js "CANONICAL_HOST" "Pages worker defines canonical host"
require_contains site/_worker.js "TYPO_HOSTS" "Pages worker handles typo-domain redirects"
require_contains scripts/ci/site_worker_dispatch_test.mjs "assertSecurityHeaders" "Pages worker dispatch test validates browser security headers"
require_contains scripts/ci/site_worker_dispatch_test.mjs "utm_source=old-card" "Pages worker dispatch test validates typo-domain redirect"
require_contains crates/hc-mcp/src/bin/hc-mcp-http.rs "HC_RELEASE_SHA" "MCP HTTP server exposes release identity for deploy skew checks"
require_contains crates/hc-mcp/src/bin/hc-mcp-http.rs "HC_MCP_ALLOWED_HOSTS" "MCP HTTP server supports explicit Host allowlist"
require_contains crates/hc-mcp/src/bin/hc-mcp-http.rs "mcp.tinyzkp.com" "MCP HTTP server default Host allowlist includes production host"
require_contains site/functions/api/events.js "ALLOWED_EVENTS" "analytics endpoint allowlists events"
require_contains site/functions/api/events.js "ALLOWED_PROPS" "analytics endpoint allowlists properties"
require_contains site/functions/api/events.js "redactSensitiveText" "analytics endpoint redacts sensitive string values"
require_contains site/functions/api/events.js "account_first_proof_panel_seen" "analytics allowlist tracks account activation funnel"
require_contains site/analytics.js "navigator.sendBeacon" "analytics client uses beacon delivery"
require_contains site/analytics.js "decorateConversionLink" "analytics client decorates conversion links with attribution"
require_contains site/analytics.js "writeClickAttribution" "analytics client persists direct-click CTA source when first touch is absent"
require_contains site/analytics.js "CONVERSION_INTENTS" "analytics client maps conversion paths to intent"
require_contains site/.well-known/tinyzkp-offers.json "source=agent_offer" "agent-readable offers include tracked signup URLs"
require_contains site/.well-known/tinyzkp-offers.json "human_confirmation_required" "agent-readable offers require human confirmation"
require_contains scripts/ci/offer_metadata_check.py "validate_plan_checkout_urls" "agent offer check validates metadata checkout attribution"
require_contains site/pricing.json "source=pricing_json" "pricing metadata checkout URLs are source-tagged"
require_contains site/limits.json "source=limits_metadata" "limits metadata checkout URLs are source-tagged"
require_contains site/.well-known/tinyzkp-receipt-share.json "source=receipt_share" "receipt-share contract preserves source attribution"
require_contains site/.well-known/tinyzkp-receipt-share.json "base64url_json_proof" "receipt-share contract documents verifier fragment format"
require_contains site/.well-known/tinyzkp-receipt-share.json "Do not put secrets" "receipt-share contract documents data boundaries"
require_contains site/.well-known/tinyzkp-badge.json "source=verified_badge" "badge contract preserves verifier attribution"
require_contains site/.well-known/tinyzkp-badge.json "do_not_link_directly_to_asset_only" "badge contract forbids asset-only links"
require_contains site/badges.html "source=verified_badge" "badge page embed snippet is source-tagged"
require_contains site/recipes.html "source=verified_badge" "recipes badge embed snippet is source-tagged"
require_contains site/try.html "MAX_SHARE_FRAGMENT_CHARS" "playground enforces receipt-share URL size ceiling"
require_contains site/verify.html "MAX_SHARE_FRAGMENT_CHARS" "verifier enforces receipt-share URL size ceiling"
require_contains marketing/OPENAI_CHATGPT_APP_PROTOTYPE.md "source=openai_chatgpt_app" "ChatGPT app prototype uses source-tagged signup"
require_contains marketing/openai_chatgpt_app_submission.json "https://mcp.tinyzkp.com/mcp" "ChatGPT app submission targets streamable MCP endpoint"
require_contains marketing/openai_chatgpt_app_submission.json "human_confirmation_required" "ChatGPT app submission requires human confirmation"
require_contains site/apps/tinyzkp-receipt-widget.html "tools/call" "ChatGPT app widget calls MCP tools through the app bridge"
require_contains site/apps/tinyzkp-receipt-widget.html "noindex,follow" "ChatGPT app widget is noindex app infrastructure"
require_contains site/discovery.json ".well-known/tinyzkp-offers.json" "discovery metadata links agent-readable offers"
require_contains site/discovery.json ".well-known/tinyzkp-receipt-share.json" "discovery metadata links receipt-share contract"
require_contains site/discovery.json ".well-known/tinyzkp-badge.json" "discovery metadata links badge contract"
require_contains site/llms.txt ".well-known/tinyzkp-offers.json" "llms.txt links agent-readable offers"
require_contains site/llms.txt ".well-known/tinyzkp-receipt-share.json" "llms.txt links receipt-share contract"
require_contains site/llms.txt ".well-known/tinyzkp-badge.json" "llms.txt links badge contract"
require_contains site/robots.txt ".well-known/tinyzkp-offers.json" "robots.txt advertises agent-readable offers"
require_contains site/robots.txt ".well-known/tinyzkp-receipt-share.json" "robots.txt advertises receipt-share contract"
require_contains site/robots.txt ".well-known/tinyzkp-badge.json" "robots.txt advertises badge contract"
require_contains marketing/MCP_DISTRIBUTION_PACK.md "source-tagged signup URL" "MCP distribution pack requires tracked CTAs"
require_contains server.json "io.github.logannye/tinyzkp" "official MCP Registry manifest uses the published GitHub namespace"
require_contains server.json "https://mcp.tinyzkp.com" "official MCP Registry manifest points at hosted MCP endpoint"
require_contains marketing/mcp_distribution_targets.json "source=smithery_mcp" "MCP distribution targets preserve Smithery attribution"
require_contains marketing/mcp_distribution_targets.json "source=official_mcp_registry" "MCP distribution targets preserve official registry attribution"
require_contains marketing/mcp_distribution_targets.json "source=cursor_directory" "MCP distribution targets preserve Cursor Directory attribution"
require_contains marketing/mcp_distribution_targets.json "https://cursor.directory/plugins/new" "MCP distribution targets point Cursor submissions at Cursor Directory"
require_contains marketing/generated/mcp_submissions/index.md "source=anthropic_connector" "generated MCP submissions include source-tagged Anthropic CTA"
require_contains glama.json "https://glama.ai/mcp/schemas/server.json" "Glama MCP manifest declares the official schema"
require_contains marketing/mcp_distribution_targets.json "Repo-level glama.json manifest is present" "Glama distribution target tracks repo-level manifest readiness"
require_contains plugins/tinyzkp-cursor/.plugin/plugin.json "\"mcpServers\": \"./.mcp.json\"" "Cursor plugin vendor-neutral manifest points at MCP config"
require_contains plugins/tinyzkp-cursor/.cursor-plugin/plugin.json "\"mcpServers\": \"./.mcp.json\"" "Cursor plugin vendor manifest points at MCP config"
require_contains plugins/tinyzkp-cursor/.mcp.json "mcp-remote" "Cursor plugin MCP config uses remote MCP bridge"
require_contains plugins/tinyzkp-cursor/.mcp.json "https://mcp.tinyzkp.com/mcp" "Cursor plugin MCP config targets hosted TinyZKP MCP"
require_contains plugins/tinyzkp-cursor/README.md "source=cursor_directory" "Cursor plugin README uses source-tagged CTA"
require_contains plugins/tinyzkp-cursor/rules/tinyzkp-proof-receipts.mdc "Never put secrets" "Cursor plugin rule preserves transparent receipt data boundary"
require_contains scripts/monitoring/gtm_distribution_monitor.py "mcp_distribution_targets.json" "GTM distribution monitor reads target catalog"
require_contains scripts/marketing/render_mcp_submissions.py "--check" "MCP submission renderer supports freshness checks"
require_contains scripts/marketing/indexnow_submit.py "api.indexnow.org/indexnow" "IndexNow submitter targets the official API endpoint"
require_contains site/indexnow-key.txt "51c0bb9fc11678e9ceab12b9214816dd" "IndexNow ownership key is hosted at site root"
require_contains marketing/GTM_DISTRIBUTION_PLAN.md "HTTP 200 from \`api.indexnow.org\` for 51 TinyZKP" "GTM plan records live IndexNow submission evidence"
require_contains marketing/GTM_DISTRIBUTION_PLAN.md "stripe_checkout_canary.py --json" "GTM plan documents positive Stripe checkout canary"
require_contains marketing/GTM_DISTRIBUTION_PLAN.md "customer pipeline evidence" "GTM plan documents synthetic checkout exclusion policy"
require_contains marketing/GTM_DISTRIBUTION_PLAN.md "--verify-stripe-cli --stripe-bin /opt/homebrew/bin/stripe" "GTM plan documents checkout canary CLI visibility check"
require_contains marketing/HN_LAUNCH.md "source=hn_launch" "HN launch asset has source-tagged CTA"
require_contains marketing/X_THREAD.md "source=x_launch_thread" "X thread asset has source-tagged CTA"
require_contains marketing/OUTBOUND_EMAIL.md "source=founder_outbound" "outbound email asset has source-tagged CTA"
require_contains marketing/generated/outbound_targets.json "source=founder_outbound" "generated founder outbound catalog preserves source-tagged CTAs"
require_contains marketing/generated/outbound_targets.json "needs_manual_founder_or_engineering_contact" "generated founder outbound catalog requires manual contact research"
require_contains marketing/generated/outbound_targets.md "## Operating Rules" "generated founder outbound markdown includes operating rules"
require_contains scripts/ci/outbound_targets_check.py "MIN_TARGETS = 25" "outbound target check enforces minimum catalog size"
require_contains scripts/marketing/generate_outbound_targets.py "User-Agent" "outbound target generator identifies itself in public directory requests"
require_contains marketing/generated/outbound_send_queue.json "ready_after_manual_contact_research" "generated founder outbound send queue stays manual before contact research"
require_contains marketing/generated/outbound_send_queue.json "\"contact_email\": \"\"" "generated founder outbound send queue leaves contact email blank"
require_contains marketing/generated/outbound_send_queue.md "## Manual Send Rules" "generated founder outbound send queue includes manual send rules"
require_contains marketing/generated/outbound_send_queue.md "Do not use automated cold-email sending tools." "generated founder outbound send queue forbids automated sending"
require_contains scripts/marketing/render_outbound_send_queue.py "--check" "outbound send queue renderer supports freshness checks"
require_contains scripts/ci/outbound_send_queue_check.py "MIN_QUEUE_TARGETS = 10" "outbound send queue check enforces first-wave size"
require_contains scripts/ci/outbound_send_queue_check.py "must not include personal email addresses" "outbound send queue check rejects personal emails"
require_contains marketing/generated/outbound_research_packets.json "No personal emails" "generated founder outbound research packets preserve no-PII policy"
require_contains marketing/generated/outbound_research_packets.md "Company-level public pages only." "generated founder outbound research packets document public-page scope"
require_contains scripts/marketing/enrich_outbound_research.py "mailto:" "outbound research enrichment filters mailto links"
require_contains scripts/ci/outbound_research_packets_check.py "must not include email addresses" "outbound research packet check rejects personal emails"
require_contains scripts/marketing/sync_outbound_research_pipeline.py "company_research_ready" "outbound research sync advances company-level research stage"
require_contains marketing/generated/gtm_execution_ledger.json "\"status\": \"completed\"" "generated GTM execution ledger tracks pilot checkout verification"
require_contains marketing/generated/gtm_execution_ledger.json "revenue.stripe_catalog_hygiene" "generated GTM execution ledger tracks Stripe catalog hygiene"
require_contains marketing/generated/gtm_execution_ledger.json "--strict-catalog" "generated GTM execution ledger tracks strict Stripe catalog audit"
require_contains marketing/generated/gtm_execution_ledger.json "ready_for_manual_submission" "generated GTM execution ledger tracks manual submission work"
require_contains marketing/generated/gtm_execution_ledger.json "ready_after_manual_contact_research" "generated GTM execution ledger tracks manual outbound work"
require_contains marketing/generated/gtm_execution_ledger.md "## Revenue Binding" "generated GTM execution ledger includes revenue binding section"
require_contains marketing/generated/gtm_execution_ledger.md "inline price_data" "generated GTM execution ledger documents pilot inline price fallback"
require_contains marketing/generated/gtm_execution_ledger.md "Do not automate cold outbound email sends." "generated GTM execution ledger forbids automated outbound sends"
require_contains scripts/marketing/render_gtm_execution_ledger.py "--check" "GTM execution ledger renderer supports freshness checks"
require_contains scripts/ci/gtm_execution_ledger_check.py "MIN_OUTBOUND_TASKS = 10" "GTM execution ledger check enforces first-wave outbound size"
require_contains scripts/ci/gtm_execution_ledger_check.py "must include source" "GTM execution ledger check enforces source-tagged CTAs"
require_contains marketing/gtm_pipeline_state.json "Do not commit personal email addresses" "GTM pipeline state forbids personal contact details"
require_contains marketing/generated/gtm_pipeline_ledger.json "weighted_pipeline_cents" "generated GTM pipeline ledger computes weighted pipeline"
require_contains marketing/generated/gtm_pipeline_ledger.json "live_monitoring" "generated GTM pipeline ledger tracks pilot checkout verification"
require_contains marketing/generated/gtm_pipeline_ledger.json "blocked_external_secret" "generated GTM pipeline ledger tracks Stripe catalog access blocker"
require_contains marketing/generated/gtm_pipeline_ledger.json "company_research_ready" "generated GTM pipeline ledger tracks company-level outbound research stage"
require_contains marketing/generated/gtm_pipeline_ledger.md "Gross pipeline" "generated GTM pipeline ledger summarizes gross pipeline"
require_contains marketing/generated/gtm_pipeline_ledger.md "Actual revenue recorded" "generated GTM pipeline ledger summarizes actual revenue"
require_contains scripts/marketing/render_gtm_pipeline_ledger.py "--sync-state" "GTM pipeline ledger renderer preserves manual state"
require_contains scripts/marketing/render_gtm_pipeline_ledger.py "--check" "GTM pipeline ledger renderer supports freshness checks"
require_contains scripts/marketing/sync_stripe_checkout_pipeline.py "Stripe Checkout evidence" "Stripe checkout pipeline sync records live revenue evidence"
require_contains scripts/marketing/sync_stripe_checkout_pipeline.py "No buyer PII" "Stripe checkout pipeline sync documents no-PII ledger policy"
require_contains scripts/marketing/sync_stripe_checkout_pipeline.py "max(previous_revenue" "Stripe checkout pipeline sync never lowers recorded revenue from a narrow lookback"
require_contains scripts/ci/gtm_pipeline_ledger_check.py "MIN_RECORDS = 20" "GTM pipeline ledger check enforces task coverage"
require_contains scripts/ci/gtm_pipeline_ledger_check.py "won stage requires actual_revenue_cents" "GTM pipeline ledger check requires revenue evidence for wins"
require_contains marketing/INTEGRATION_CURSOR.md "prove_template" "Cursor integration asset uses current MCP prove tool"
require_contains marketing/INTEGRATION_CURSOR.md "source=cursor_community_post" "Cursor integration asset has source-tagged CTA"
require_contains marketing/INTEGRATION_LANGCHAIN.md "source=langchain_integration_post" "LangChain integration asset has source-tagged CTA"
require_contains scripts/ci/manual_distribution_assets_check.py "BARE_CONVERSION_URL_RE" "manual distribution asset check rejects untagged conversion URLs"
require_contains scripts/ci/badge_embed_check.py "source=verified_badge" "badge embed check validates source-tagged verifier links"
require_contains scripts/ci/package_distribution_check.py "source-tagged conversion links" "package distribution check validates source-tagged registry CTAs"
require_contains scripts/ci/package_distribution_check.py "Default receipts are transparent" "package distribution check requires transparent receipt caveat"
require_contains scripts/ci/package_distribution_check.py "npm_wasm_verifier" "package distribution check covers WASM verifier package"
require_contains scripts/ci/seo_conversion_check.py "PRIORITY_SURFACES" "SEO conversion check tracks priority acquisition pages"
require_contains scripts/ci/seo_conversion_check.py "CONVERSION_PATHS" "SEO conversion check validates measurable CTA routes"
require_contains site/agents.html "source=agents_hero" "agents SEO page has source-tagged CTA"
require_contains site/verifiable-agent-output.html "source=verifiable_agent_output" "verifiable-agent-output SEO page has source-tagged CTA"
require_contains site/agent-audit-trails.html "source=agent_audit_trails" "agent-audit-trails SEO page has source-tagged CTA"
require_contains site/receipts.html "source=receipts_page" "receipts SEO page has source-tagged CTA"
require_contains site/use-cases/offline-proof-verification.html "source=offline_verification" "offline-verification SEO page has source-tagged CTA"
require_contains site/use-cases/post-quantum-stark-proving.html "source=post_quantum_stark" "post-quantum STARK SEO page has source-tagged CTA"
require_contains site/compare/self-hosted-stark-prover.html "source=self_hosted_compare" "self-hosted comparison page has source-tagged CTA"
require_contains site/integrations/openai-agents.html "source=integration_openai_agents" "OpenAI agents integration page has source-tagged CTA"
require_contains site/contact.html "Project fit" "contact page captures structured qualification"
require_contains site/contact.html "Do not paste API keys, private inputs, proofs, or customer data." "contact page warns against sensitive submissions"
require_contains site/contact.html "Support expectations" "contact page publishes support expectations"
require_contains site/status.html "Direct fallback email" "status page publishes support fallback channel"
require_contains site/terms.html "support expectations" "terms page links support expectations"
require_contains site/functions/api/contact.js "QUALIFICATION_FIELDS" "contact function allowlists qualification fields"
require_contains site/functions/api/create-checkout.js "creating a partial paid subscription" "checkout function documents fail-closed paid-plan billing"
require_contains site/functions/api/create-pilot-checkout.js 'params.append("mode", "payment")' "pilot checkout uses one-time Stripe Checkout payment mode"
require_contains site/functions/api/create-pilot-checkout.js "line_items[0][price_data][unit_amount]" "pilot checkout supports server-defined inline price data"
require_contains site/functions/api/create-pilot-checkout.js "payment_intent_data[metadata]" "pilot checkout copies attribution to payment intent metadata"
require_contains site/functions/api/create-pilot-checkout.js "onRequestGet" "pilot checkout exposes non-sensitive capability check"
require_contains site/pilot.html "Checking checkout" "pilot page does not enable paid checkout before capability check"
require_contains site/pilot.html "Scope by contact" "pilot page converts unavailable checkout into contact fallback"
require_contains site/pilot.html "pilot_contact_fallback_click" "pilot contact fallback is tracked"
require_contains site/pilot.html "/api/create-pilot-checkout" "pilot page offers direct paid pilot checkout"
require_contains site/contact.html "form.elements.namedItem" "contact form uses stable field lookup for lead payloads"
require_contains site/contact.html "leadContext.medium" "contact form preserves medium attribution"
require_contains site/contact.html "leadContext.campaign" "contact form preserves campaign attribution"
require_contains marketing/README.md "Production Pilot one-time checkout | **Live**" "marketing status keeps pilot checkout launch verification visible"
require_contains marketing/README.md "inline price_data" "marketing launch sequence documents inline pilot checkout fallback"
require_contains site/functions/api/events.js "pilot_checkout_started" "analytics allowlist tracks pilot checkout starts"
require_contains scripts/monitoring/api_health_audit.sh "POST /api/create-pilot-checkout" "production health audit canaries pilot checkout"
require_contains scripts/monitoring/api_health_audit.sh "pilot_capability_available" "production health audit gates pilot checkout canary on live capability"
require_contains scripts/monitoring/api_health_audit.sh '\"source\":\"api_health_audit\"' "production checkout canaries are tagged for revenue exclusion"
require_contains scripts/monitoring/gtm_growth_monitor.py "pilot checkout endpoint" "GTM live monitor probes pilot checkout endpoint"
require_contains site/functions/api/verify-magic-link.js "explicit allowlist" "magic-link verifier allowlists browser-visible metadata"
require_contains site/functions/api/verify-magic-link.js "api_key" "magic-link verifier documents raw API-key exclusion"
require_contains billing/provision_tenant.py "CONTACT_QUALIFICATION_FIELDS" "billing webhook renders qualification fields"
require_contains .github/workflows/ci.yml "clients/python[test]" "CI installs Python SDK test dependencies"
require_contains .github/workflows/ci.yml "billing/requirements.txt" "CI installs billing runtime test dependencies"
require_contains .github/workflows/ci.yml "billing/tests/test_tenant_pg_tools.py" "CI covers tenant Postgres migration helper"
require_contains .github/workflows/ci.yml "billing/tests/test_tenant_store.py" "CI covers tenant store Postgres mirror behavior"
require_contains .github/workflows/ci.yml "billing/tests/test_provision_free.py" "CI covers free signup provisioning"
require_contains .github/workflows/ci.yml "billing/tests/test_session_endpoints.py" "CI covers billing session endpoints"
require_contains .github/workflows/ci.yml "billing/tests/test_sessions.py" "CI covers tenant session lifecycle"
require_contains .github/workflows/ci.yml "billing/tests/test_lifecycle_nudges.py" "CI covers lifecycle nudges"
require_contains .github/workflows/ci.yml "billing/tests/test_checkout_recovery.py" "CI covers checkout recovery"
require_contains .github/workflows/ci.yml "billing/tests/test_gtm_revenue_report.py" "CI covers GTM revenue report"
require_contains .github/workflows/ci.yml "npm run build" "CI builds TypeScript SDK"
require_contains .github/workflows/ci.yml "cargo test --manifest-path clients/rust/Cargo.toml" "CI tests standalone Rust SDK"
require_contains .github/workflows/ci.yml "node --check site/_worker.js" "CI syntax-checks site JavaScript"
require_contains .github/workflows/ci.yml "scripts/monitoring/shared_dispatch_smoke.sh" "CI syntax-checks shared-dispatch smoke script"
require_contains .github/workflows/ci.yml "bash -n scripts/monitoring/host_cron_env.sh" "CI syntax-checks host cron env wrapper"
require_contains .github/workflows/ci.yml "bash -n scripts/monitoring/daily_growth_decision_cron.sh" "CI syntax-checks daily growth cron wrapper"
require_contains .github/workflows/ci.yml "bash -n scripts/monitoring/verify_growth_data_wiring.sh" "CI syntax-checks growth data wiring verifier"
require_contains .github/workflows/ci.yml "scripts/ci/test_growth_data_wiring_verify.py" "CI tests growth data wiring verifier"
require_contains scripts/monitoring/daily_growth_decision.py "growth_experiment_ledger.json" "daily growth decision writes no-PII experiment ledger"
require_contains scripts/monitoring/daily_growth_decision.py "safe_action_queue" "daily growth decision emits a safe action queue"
require_contains scripts/monitoring/daily_growth_decision.py "requires_explicit_approval" "daily growth decision preserves explicit-approval guardrails"
require_contains .github/workflows/ci.yml "deploy/hetzner/install_billing_runtime.sh" "CI syntax-checks billing runtime installer"
require_contains .github/workflows/ci.yml "scripts/ci/site_route_check.py" "CI checks static site routes"
require_contains .github/workflows/ci.yml "scripts/ci/test_site_route_check.py" "CI tests static site route policy"
require_contains .github/workflows/ci.yml "test_analytics_attribution.mjs" "CI tests analytics attribution handoff"
require_contains .github/workflows/ci.yml "scripts/ci/site_deploy_check.py" "CI checks Cloudflare Pages deploy config"
require_contains .github/workflows/ci.yml "scripts/ci/site_worker_dispatch_test.mjs" "CI tests Cloudflare Pages worker dispatch"
require_contains .github/workflows/ci.yml "scripts/ci/compose_config_check.py" "CI checks Docker Compose render paths"
require_contains .github/workflows/ci.yml "scripts/ci/launch_gate_audit.py" "CI checks launch-gate evidence"
require_contains .github/workflows/ci.yml "scripts/ci/production_launch_preflight.py" "CI runs aggregate production launch preflight"
require_contains .github/workflows/ci.yml "scripts/ci/test_production_launch_preflight.py" "CI tests production launch preflight"
require_contains .github/workflows/ci.yml "scripts/ci/test_release_identity_check.py" "CI tests release identity policy"
require_contains .github/workflows/ci.yml "cloudflare_pages_secret_check.py" "CI syntax-checks live Cloudflare secret checker"
require_contains .github/workflows/ci.yml "scripts/ci/offer_metadata_check.py" "CI checks agent-readable offer metadata"
require_contains .github/workflows/ci.yml "scripts/ci/receipt_share_contract_check.py" "CI checks receipt-share contract"
require_contains .github/workflows/ci.yml "scripts/ci/badge_embed_check.py" "CI checks badge embed contract"
require_contains .github/workflows/ci.yml "scripts/ci/test_badge_embed_check.py" "CI tests badge embed contract"
require_contains .github/workflows/ci.yml "scripts/ci/openai_chatgpt_app_check.py" "CI checks ChatGPT app prototype"
require_contains .github/workflows/ci.yml "scripts/ci/test_openai_chatgpt_app_check.py" "CI tests ChatGPT app prototype policy"
require_contains .github/workflows/ci.yml "gtm_distribution_monitor.py --offline" "CI checks GTM distribution targets offline"
require_contains .github/workflows/ci.yml "scripts/ci/test_gtm_distribution_monitor.py" "CI tests GTM distribution monitor policy"
require_contains .github/workflows/ci.yml "gtm_growth_monitor.py --offline" "CI checks aggregate GTM growth monitor offline"
require_contains .github/workflows/ci.yml "scripts/ci/test_gtm_growth_monitor.py" "CI tests GTM growth monitor policy"
require_contains .github/workflows/ci.yml "render_gtm_execution_ledger.py --check" "CI checks GTM execution ledger freshness"
require_contains .github/workflows/ci.yml "scripts/ci/gtm_execution_ledger_check.py" "CI checks GTM execution ledger"
require_contains .github/workflows/ci.yml "scripts/ci/test_gtm_execution_ledger.py" "CI tests GTM execution ledger policy"
require_contains .github/workflows/ci.yml "render_gtm_pipeline_ledger.py --check" "CI checks GTM pipeline ledger freshness"
require_contains .github/workflows/ci.yml "scripts/ci/gtm_pipeline_ledger_check.py" "CI checks GTM pipeline ledger"
require_contains .github/workflows/ci.yml "scripts/ci/test_gtm_pipeline_ledger.py" "CI tests GTM pipeline ledger policy"
require_contains .github/workflows/ci.yml "scripts/ci/test_stripe_checkout_pipeline_sync.py" "CI tests Stripe checkout pipeline sync"
require_contains .github/workflows/ci.yml "billing/tests/test_stripe_account_context_check.py" "CI tests Stripe account context check"
require_contains .github/workflows/ci.yml "billing/tests/test_stripe_revenue_readiness.py" "CI tests Stripe revenue readiness runner"
require_contains .github/workflows/ci.yml "billing/tests/test_stripe_revenue_ops_audit.py" "CI tests Stripe revenue ops audit"
require_contains .github/workflows/ci.yml "billing/tests/test_stripe_catalog_write_preflight.py" "CI tests Stripe catalog write preflight"
require_contains .github/workflows/ci.yml "manual_distribution_assets_check.py" "CI checks manual GTM launch assets"
require_contains .github/workflows/ci.yml "scripts/ci/outbound_targets_check.py" "CI checks founder outbound target catalog"
require_contains .github/workflows/ci.yml "scripts/ci/test_outbound_target_pipeline.py" "CI tests founder outbound target policy"
require_contains .github/workflows/ci.yml "scripts/marketing/generate_outbound_targets.py" "CI syntax-checks founder outbound target generator"
require_contains .github/workflows/ci.yml "render_outbound_send_queue.py --check" "CI checks founder outbound send queue freshness"
require_contains .github/workflows/ci.yml "scripts/ci/outbound_send_queue_check.py" "CI checks founder outbound send queue"
require_contains .github/workflows/ci.yml "scripts/ci/test_outbound_send_queue.py" "CI tests founder outbound send queue policy"
require_contains .github/workflows/ci.yml "enrich_outbound_research.py --check" "CI checks founder outbound research packet freshness"
require_contains .github/workflows/ci.yml "scripts/ci/outbound_research_packets_check.py" "CI checks founder outbound research packets"
require_contains .github/workflows/ci.yml "sync_outbound_research_pipeline.py --check" "CI checks founder outbound research pipeline sync"
require_contains .github/workflows/ci.yml "scripts/ci/test_outbound_research_packets.py" "CI tests founder outbound research packets"
require_contains .github/workflows/ci.yml "scripts/ci/gtm_execution_ledger_check.py" "CI syntax-checks GTM execution ledger checker"
require_contains .github/workflows/ci.yml "scripts/marketing/render_gtm_execution_ledger.py" "CI syntax-checks GTM execution ledger renderer"
require_contains .github/workflows/ci.yml "scripts/ci/gtm_pipeline_ledger_check.py" "CI syntax-checks GTM pipeline ledger checker"
require_contains .github/workflows/ci.yml "scripts/marketing/render_gtm_pipeline_ledger.py" "CI syntax-checks GTM pipeline ledger renderer"
require_contains .github/workflows/ci.yml "scripts/marketing/sync_stripe_checkout_pipeline.py" "CI syntax-checks Stripe checkout pipeline sync"
require_contains .github/workflows/ci.yml "scripts/marketing/sync_outbound_research_pipeline.py" "CI syntax-checks outbound research pipeline sync"
require_contains .github/workflows/ci.yml "scripts/marketing/enrich_outbound_research.py" "CI syntax-checks outbound research enrichment"
require_contains .github/workflows/ci.yml "scripts/ci/outbound_research_packets_check.py" "CI syntax-checks outbound research packet checker"
require_contains .github/workflows/ci.yml "render_mcp_submissions.py --check" "CI checks generated MCP submission drafts"
require_contains .github/workflows/ci.yml "scripts/ci/test_mcp_submission_renderer.py" "CI tests MCP submission renderer"
require_contains .github/workflows/ci.yml "scripts/marketing/indexnow_submit.py" "CI checks IndexNow submission dry-run"
require_contains .github/workflows/ci.yml "scripts/ci/test_stripe_checkout_canary.py" "CI tests Stripe checkout canary policy"
require_contains .github/workflows/ci.yml "scripts/monitoring/stripe_checkout_canary.py" "CI syntax-checks Stripe checkout canary"
require_contains .github/workflows/ci.yml "scripts/ci/package_distribution_check.py" "CI checks package distribution surfaces"
require_contains .github/workflows/ci.yml "scripts/ci/test_package_distribution_check.py" "CI tests package distribution surface policy"
require_contains .github/workflows/ci.yml "scripts/ci/seo_conversion_check.py" "CI checks SEO conversion surfaces"
require_contains .github/workflows/ci.yml "scripts/ci/server_card_check.py" "CI checks MCP server-card policy"
require_contains .github/workflows/ci.yml "scripts/ci/backup_restore_check.py" "CI checks backup/restore drift"
require_contains .github/workflows/ci.yml "billing/tests/test_backup_script.py" "CI smoke-runs backup script"
require_contains .github/workflows/ci.yml "xargs -0 -n1 node --check" "CI syntax-checks all Pages API modules"
require_contains .github/workflows/ci.yml "bash -n billing/backup.sh" "CI syntax-checks backup script"
require_contains .github/workflows/ci.yml "bash -n billing/setup_stripe_products.sh" "CI syntax-checks full Stripe setup script"
require_contains .github/workflows/ci.yml "bash -n billing/setup_pilot_price.sh" "CI syntax-checks pilot Stripe setup script"
require_contains .github/workflows/ci.yml "billing/lifecycle_nudges.py" "CI syntax-checks lifecycle nudge script"
require_contains .github/workflows/ci.yml "billing/checkout_recovery.py" "CI syntax-checks checkout recovery script"
require_contains .github/workflows/ci.yml "billing/gtm_revenue_report.py" "CI syntax-checks GTM revenue report"
require_contains .github/workflows/ci.yml "billing/stripe_account_context_check.py" "CI syntax-checks Stripe account context check"
require_contains .github/workflows/ci.yml "billing/stripe_revenue_readiness.py" "CI syntax-checks Stripe revenue readiness runner"
require_contains .github/workflows/ci.yml "billing/stripe_revenue_ops_audit.py" "CI syntax-checks Stripe revenue ops audit"
require_contains .github/workflows/ci.yml "billing/stripe_catalog_write_preflight.py" "CI syntax-checks Stripe catalog write preflight"
require_contains .github/workflows/ci.yml "scripts/monitoring/gtm_growth_monitor.py" "CI syntax-checks GTM growth monitor"
require_contains .github/workflows/ci.yml "scripts/ci/test_deploy_readiness_check.py" "CI covers deploy readiness policy"
require_contains scripts/ci/site_route_check.py "worker_api_routes" "static site route check validates Pages worker API routes"
require_contains scripts/ci/site_route_check.py "parse_literal_script_routes" "static site route check validates literal app-script routes"
require_contains scripts/ci/site_route_check.py "exactly one primary <h1>" "static site route check validates primary page headings"
require_contains scripts/ci/site_route_check.py "expected_canonical_url" "static site route check validates canonical URLs"
require_contains scripts/ci/site_route_check.py "REQUIRED_ROBOTS_SITEMAP" "static site route check validates robots sitemap declaration"
require_contains scripts/ci/site_route_check.py "sitemap_canonical_urls" "static site route check validates sitemap/canonical agreement"
require_contains scripts/ci/site_route_check.py "URL_META_PROPERTIES" "static site route check validates social preview URLs"
require_contains scripts/ci/site_route_check.py "json_ld_urls" "static site route check validates JSON-LD local URLs"
require_contains scripts/ci/site_deploy_check.py "REQUIRED_BINDINGS" "Cloudflare Pages deploy check documents required bindings"
require_contains scripts/ci/site_deploy_check.py "og-image.png" "Cloudflare Pages deploy check requires social preview assets"
require_contains scripts/ci/site_deploy_check.py "pages_build_output_dir" "Cloudflare Pages deploy check validates Pages output directory"
require_contains scripts/ci/site_worker_dispatch_test.mjs "extensionless" "Pages worker dispatch test covers extensionless HTML fallback"
require_contains scripts/ci/site_worker_dispatch_test.mjs "registeredPostRoutes" "Pages worker dispatch test covers registered account and billing API routes"
require_contains scripts/ci/site_worker_dispatch_test.mjs "tzk_should_not_reach_browser" "Pages worker dispatch test guards against raw API-key leakage"
require_contains scripts/ci/site_worker_dispatch_test.mjs "Stripe should not be called when a paid plan price binding is missing" "Pages worker dispatch test guards checkout fail-closed billing"
require_contains scripts/ci/site_worker_dispatch_test.mjs "Compute checkout should not create a partial session" "Pages worker dispatch test guards Compute checkout fail-closed billing"
require_contains scripts/ci/site_worker_dispatch_test.mjs "line_items[0][price_data][unit_amount]" "Pages worker dispatch test validates pilot inline price fallback"
require_contains scripts/ci/site_worker_dispatch_test.mjs "line_items[1][price]" "Pages worker dispatch test validates paid checkout line items"
require_contains scripts/ci/site_worker_dispatch_test.mjs "free@example.com" "Pages worker dispatch test validates free signup email normalization"
require_contains scripts/ci/site_worker_dispatch_test.mjs "/provision-free" "Pages worker dispatch test validates free signup webhook forwarding"
require_contains scripts/ci/site_worker_dispatch_test.mjs "cus_server_123" "Pages worker dispatch test validates portal server-side customer resolution"
require_contains scripts/ci/site_worker_dispatch_test.mjs "session/reveal-key" "Pages worker dispatch test validates reveal-key session forwarding"
require_contains scripts/ci/site_worker_dispatch_test.mjs "tzk_client_should_not_win" "Pages worker dispatch test validates rotate-key prefers session auth"
require_contains scripts/ci/site_worker_dispatch_test.mjs "tzk_currentabcdef" "Pages worker dispatch test validates rotate-key bearer forwarding"
require_contains scripts/ci/compose_config_check.py "production-shared-workers" "Docker Compose check validates shared-worker production profile"
require_contains scripts/ci/launch_gate_audit.py "Phase 10" "launch-gate audit tracks full production-grade posture"
require_contains scripts/ci/production_launch_preflight.py "Live canaries were not run" "production launch preflight keeps live gate explicit"
require_contains scripts/ci/production_launch_preflight.py "TINYZKP_SMOKE_PUBLIC_ONLY" "production launch preflight supports public live smoke"
require_contains scripts/ci/production_launch_preflight.py "cloudflare_pages_secret_check.py" "production launch preflight validates live Pages secrets"
require_contains scripts/ci/production_launch_preflight.py "test_site_route_check.py" "production launch preflight runs static route policy tests"
require_contains scripts/ci/production_launch_preflight.py "test_analytics_attribution.mjs" "production launch preflight validates analytics attribution handoff"
require_contains scripts/ci/production_launch_preflight.py "release_identity_check.py" "production launch preflight can validate live release identity"
require_contains scripts/ci/production_launch_preflight.py "offer_metadata_check.py" "production launch preflight validates agent-readable offers"
require_contains scripts/ci/production_launch_preflight.py "receipt_share_contract_check.py" "production launch preflight validates receipt-share contract"
require_contains scripts/ci/production_launch_preflight.py "badge_embed_check.py" "production launch preflight validates badge embed contract"
require_contains scripts/ci/production_launch_preflight.py "openai_chatgpt_app_check.py" "production launch preflight validates ChatGPT app prototype"
require_contains scripts/ci/production_launch_preflight.py "gtm_distribution_monitor.py" "production launch preflight validates GTM distribution targets"
require_contains scripts/ci/production_launch_preflight.py "gtm_growth_monitor.py" "production launch preflight validates aggregate GTM growth monitor"
require_contains scripts/ci/production_launch_preflight.py "render_gtm_execution_ledger.py" "production launch preflight validates GTM execution ledger freshness"
require_contains scripts/ci/production_launch_preflight.py "gtm_execution_ledger_check.py" "production launch preflight validates GTM execution ledger"
require_contains scripts/ci/production_launch_preflight.py "test_gtm_execution_ledger.py" "production launch preflight validates GTM execution ledger policy"
require_contains scripts/ci/production_launch_preflight.py "render_gtm_pipeline_ledger.py" "production launch preflight validates GTM pipeline ledger freshness"
require_contains scripts/ci/production_launch_preflight.py "gtm_pipeline_ledger_check.py" "production launch preflight validates GTM pipeline ledger"
require_contains scripts/ci/production_launch_preflight.py "test_gtm_pipeline_ledger.py" "production launch preflight validates GTM pipeline ledger policy"
require_contains scripts/ci/production_launch_preflight.py "manual_distribution_assets_check.py" "production launch preflight validates manual GTM launch assets"
require_contains scripts/ci/production_launch_preflight.py "outbound_targets_check.py" "production launch preflight validates founder outbound targets"
require_contains scripts/ci/production_launch_preflight.py "test_outbound_target_pipeline.py" "production launch preflight validates founder outbound target policy"
require_contains scripts/ci/production_launch_preflight.py "render_outbound_send_queue.py" "production launch preflight validates founder outbound send queue freshness"
require_contains scripts/ci/production_launch_preflight.py "outbound_send_queue_check.py" "production launch preflight validates founder outbound send queue"
require_contains scripts/ci/production_launch_preflight.py "test_outbound_send_queue.py" "production launch preflight validates founder outbound send queue policy"
require_contains scripts/ci/production_launch_preflight.py "enrich_outbound_research.py" "production launch preflight validates founder outbound research packet freshness"
require_contains scripts/ci/production_launch_preflight.py "outbound_research_packets_check.py" "production launch preflight validates founder outbound research packets"
require_contains scripts/ci/production_launch_preflight.py "sync_outbound_research_pipeline.py" "production launch preflight validates founder outbound research pipeline sync"
require_contains scripts/ci/production_launch_preflight.py "test_outbound_research_packets.py" "production launch preflight validates founder outbound research packet policy"
require_contains scripts/ci/production_launch_preflight.py "render_mcp_submissions.py" "production launch preflight validates generated MCP submission drafts"
require_contains scripts/ci/production_launch_preflight.py "cursor_plugin_check.py" "production launch preflight validates Cursor plugin package"
require_contains scripts/ci/production_launch_preflight.py "package_distribution_check.py" "production launch preflight validates package distribution surfaces"
require_contains scripts/ci/production_launch_preflight.py "seo_conversion_check.py" "production launch preflight validates SEO conversion surfaces"
require_contains scripts/ci/production_launch_preflight.py "test_gtm_revenue_report.py" "production launch preflight validates GTM revenue report"
require_contains scripts/ci/release_identity_check.py "mcp.tinyzkp.com" "release identity check validates deployed MCP commit SHA"
require_contains scripts/ci/production_launch_preflight.py "server_card_check.py" "production launch preflight validates MCP server-card"
require_contains scripts/monitoring/shared_dispatch_smoke.sh "MCP server-card advertises current public tool catalog" "shared-dispatch smoke validates MCP server-card"
require_contains scripts/ci/server_card_check.py "FORBIDDEN_PUBLIC_TEMPLATE_MARKERS" "MCP server-card check blocks gated template leakage"
require_contains scripts/ci/backup_restore_check.py "/v1/ping" "backup/restore check rejects stale auth verification path"
require_contains scripts/ci/backup_restore_check.py "HC_BACKUP_DATA_DIR" "backup/restore check preserves testable backup data-dir override"
require_contains scripts/ci/backup_restore_check.py "HC_BACKUP_DATE" "backup/restore check preserves deterministic backup timestamp override"
require_contains scripts/ci/backup_restore_check.py "HC_BACKUP_REMOTE_DATE" "backup/restore check preserves deterministic remote date override"
require_contains scripts/ci/deploy_readiness_check.py "HC_SERVER_PROVE_DISPATCH=shared requires HC_SERVER_JOB_INDEX_SOURCE=postgres" "deploy readiness enforces shared dispatch state"
require_contains .github/workflows/sdks-ci.yml "pip install -e \".[test]\"" "SDK CI installs Python SDK test extra"
require_contains .github/workflows/sdks-ci.yml "npm ci" "SDK CI uses deterministic TypeScript installs"
require_contains .github/workflows/sdks-ci.yml "npm test" "SDK CI runs current TypeScript tests"
require_contains .github/workflows/publish-sdks.yml "actions/attest@v4" "publish workflow creates artifact attestations"
require_contains .github/workflows/publish-sdks.yml "npm publish --provenance --access public" "publish workflow enables npm provenance"
require_contains .github/workflows/publish-sdks.yml "subject-checksums" "publish workflow attests MCP checksum subjects"
require_contains .github/workflows/publish-sdks.yml "shasum -a 256 -b" "publish workflow emits binary checksums"
require_contains .github/workflows/publish-sdks.yml "twine check dist/*" "publish workflow validates Python distributions"
require_contains .github/workflows/publish-sdks.yml "cargo package" "publish workflow packages Rust crate before publish"

require_contains site/index.html 'href="/research">Research</a>' "homepage links to research page"
require_contains site/index.html 'href="/security">Security</a>' "homepage links to security page"
require_contains site/index.html 'href="https://tinyzkp.com/.well-known/tinyzkp-offers.json"' "homepage advertises agent-readable offers"
require_contains site/index.html 'src="/analytics.js"' "homepage loads analytics client"
require_contains site/index.html "mobile-break" "homepage mobile hero has explicit line wrapping"
require_contains site/index.html "memory-note" "homepage mobile memory note wraps cleanly"
require_contains site/index.html ".code-tabs{justify-content:flex-start;overflow-x:auto" "homepage mobile code tabs stay within viewport"
require_contains site/index.html ".code-block{max-width:100%;padding:20px 18px}" "homepage mobile code blocks stay within viewport"
require_contains site/try.html "playground_prove_succeeded" "playground tracks proof completion"
require_contains site/try.html "receipt_share" "playground share links preserve receipt-share attribution"
require_contains site/try.html "first_verify_share_created" "playground tracks first verifier-share creation"
require_contains site/signup.html "checkout_started" "signup page tracks checkout starts"
require_contains site/signup.html "pypi_tinyzkp: 'Python SDK'" "signup labels PyPI source attribution"
require_contains site/signup.html "npm_cli: 'TinyZKP CLI'" "signup labels CLI source attribution"
require_contains site/signup.html "github_mcp_readme: 'MCP README'" "signup labels MCP README source attribution"
require_contains site/signup.html "main::before{width:320px;height:320px;top:-120px}" "signup mobile glow stays within viewport"
require_contains site/verify.html "client_verify_succeeded" "verifier page tracks local verification success"
require_contains site/verify.html "verifier_opened" "verifier tracks shared receipt opens"
require_contains site/verify.html "source=receipt_share" "verifier CTAs preserve receipt-share attribution"
require_contains site/research.html "research_outbound_click" "research page tracks outbound research clicks"
require_contains site/compute.html 'href="/research">Research</a>' "compute page links to research page"
require_contains site/compute.html 'href="/security">Security</a>' "compute page links to security page"
require_contains site/compute.html "What is live now on Compute" "compute page separates live scope from early-access work"
require_contains site/compute.html ".content{padding-left:20px;padding-right:20px;overflow-x:hidden}" "compute page mobile content stays within viewport"
require_contains site/contact.html ".contact-wrap::before{width:320px;height:320px;top:-120px}" "contact mobile glow stays within viewport"

require_contains site/sitemap.xml "https://tinyzkp.com/research" "sitemap includes research page"
require_contains site/sitemap.xml "https://tinyzkp.com/security" "sitemap includes security page"

require_contains README.md "Research lineage:" "README points to research lineage"
require_contains README.md "space-efficient-zero-knowledge-proofs" "README names the legacy repo"
require_contains README.md "anonymous public lane with a global concurrency cap" "README clarifies anonymous MCP lane"
require_contains README.md "docs/governance/release_policy.md" "README links release policy"
require_contains README.md "CHANGELOG.md" "README links changelog"
require_contains README.md "docs/runbooks/release_provenance.md" "README links release provenance runbook"
require_contains clients/python/README.md "accumulator_step" "Python SDK README uses live canonical template"
require_contains clients/python/README.md "source=pypi_tinyzkp" "Python SDK README has source-tagged PyPI CTA"
require_contains clients/typescript/README.md "accumulator_step" "TypeScript SDK README uses live canonical template"
require_contains clients/typescript/README.md "source=npm_tinyzkp" "TypeScript SDK README has source-tagged npm CTA"
require_contains clients/cli/README.md "source=npm_cli" "CLI README has source-tagged npm CTA"
require_contains clients/rust/README.md "source=crates_tinyzkp" "Rust SDK README has source-tagged crates.io CTA"
require_contains crates/hc-wasm/pkg/README.md "source=npm_wasm_verifier" "WASM verifier README has source-tagged npm CTA"
require_contains crates/hc-mcp/README.md "source=github_mcp_readme" "MCP README has source-tagged install CTA"
require_contains clients/rust/src/lib.rs "accumulator_step" "Rust SDK docs use live canonical template"
require_contains clients/python/tinyzkp/client.py "lifecycle: str" "Python SDK exposes template lifecycle"
require_contains clients/typescript/src/client.ts "lifecycle: string" "TypeScript SDK exposes template lifecycle"
require_contains clients/rust/src/lib.rs "pub lifecycle: String" "Rust SDK exposes template lifecycle"
require_contains BUSINESS_GUIDE.md "Legacy research repo:" "business guide defines legacy repo"
require_contains BUSINESS_GUIDE.md "tinyzkp.com/security" "business guide points to public security page"
require_contains BUSINESS_GUIDE.md "docs/governance/release_policy.md" "business guide links release policy"
require_contains BUSINESS_GUIDE.md "CHANGELOG.md" "business guide links changelog"
require_contains BUSINESS_GUIDE.md "docs/runbooks/release_provenance.md" "business guide links release provenance runbook"
require_contains docs/governance/release_policy.md "Release surfaces" "release policy defines release surfaces"
require_contains docs/governance/release_policy.md "release_provenance.md" "release policy links release provenance runbook"
require_contains docs/runbooks/incident_response.md "SEV1" "incident runbook defines severity levels"
require_contains docs/runbooks/release_provenance.md "gh attestation verify" "release provenance runbook documents attestation verification"
require_contains docs/runbooks/release_provenance.md "npm publish --provenance" "release provenance runbook documents npm provenance"
require_contains docs/strategy/reconciliation_roadmap.md "Launch gate matrix" "strategy roadmap includes launch-gate matrix"
require_contains docs/strategy/reconciliation_roadmap.md "hc-job-worker" "strategy roadmap tracks shared worker loop"
require_contains docs/strategy/reconciliation_roadmap.md "scripts/monitoring/shared_dispatch_smoke.sh" "strategy roadmap includes shared-dispatch smoke gate"
require_contains docs/operations.md "docs/runbooks/incident_response.md" "operations guide links incident response runbook"
require_contains docs/operations.md "HC_SERVER_PG_TLS" "operations guide documents Postgres TLS mode"
require_contains docs/operations.md "HC_SERVER_USAGE_READ_FROM" "operations guide documents Postgres usage read cutover"
require_contains docs/operations.md "HC_USAGE_SOURCE" "operations guide documents billing usage source cutover"
require_contains docs/operations.md "HC_SERVER_AUTH_PG_URL" "operations guide documents Postgres tenant/auth source"
require_contains docs/operations.md "HC_TENANT_PG_URL" "operations guide documents tenant auth Postgres mirror"
require_contains docs/operations.md "deploy_readiness_check.py" "operations guide documents deploy readiness gate"
require_contains docs/operations.md "site_deploy_check.py" "operations guide documents Cloudflare Pages deploy gate"
require_contains docs/operations.md "site_worker_dispatch_test.mjs" "operations guide documents Pages worker dispatch test"
require_contains docs/operations.md "baseline browser security headers" "operations guide documents Pages security header coverage"
require_contains docs/operations.md "compose_config_check.py" "operations guide documents Compose render gate"
require_contains docs/operations.md "launch_gate_audit.py" "operations guide documents launch-gate audit"
require_contains docs/operations.md "production_launch_preflight.py" "operations guide documents aggregate launch preflight"
require_contains docs/operations.md "backup_restore_check.py" "operations guide documents backup/restore gate"
require_contains docs/operations.md "billing/tests/test_backup_script.py" "operations guide documents executable backup smoke test"
require_contains docs/operations.md "HC_BACKUP_REMOTE=tinyzkp-backups-crypt:prod-sqlite" "operations guide documents off-box backup remote"
require_contains docs/operations.md "billing/lifecycle_nudges.py" "operations guide documents lifecycle nudge cron"
require_contains docs/operations.md "billing/checkout_recovery.py" "operations guide documents checkout recovery cron"
require_contains docs/operations.md "TINYZKP_CUSTOMER_EMAILS_ENABLED" "operations guide documents customer email kill switch"
require_contains docs/operations.md "growth_experiment_ledger.json" "operations guide documents daily experiment ledger"
require_contains docs/operations.md "business-copilot autonomy policy" "operations guide documents daily business copilot permissions"
require_contains docs/operations.md "gtm_distribution_monitor.py --offline" "operations guide documents GTM distribution monitor"
require_contains docs/operations.md "gtm_growth_monitor.py --offline" "operations guide documents GTM growth monitor"
require_contains docs/operations.md "badge_embed_check.py" "operations guide documents badge embed contract gate"
require_contains docs/operations.md "/opt/hc-stark/.venv" "operations guide documents host billing virtualenv"
require_contains docs/operations.md "HC_RATE_LIMIT_PG_URL" "operations guide documents shared rate-limit store"
require_contains docs/operations.md "HC_SERVER_JOB_INDEX_SOURCE" "operations guide documents Postgres job-index store"
require_contains docs/operations.md "scripts/monitoring/shared_dispatch_smoke.sh" "operations guide documents shared-dispatch smoke gate"
require_contains docs/operations.md "hc-job-worker --check-config" "operations guide documents worker config preflight"
require_contains docs/operations.md "hc-job-worker --once" "operations guide documents worker one-shot rehearsal"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "scripts/monitoring/shared_dispatch_smoke.sh" "reconciliation deploy runbook includes shared-dispatch smoke gate"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "scripts/ci/site_route_check.py" "reconciliation deploy runbook includes static site route gate"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "test_site_route_check.py" "reconciliation deploy runbook includes static route policy tests"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "scripts/ci/site_deploy_check.py" "reconciliation deploy runbook includes Pages deploy gate"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "site_worker_dispatch_test.mjs" "reconciliation deploy runbook includes Pages worker dispatch test"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "compose_config_check.py" "reconciliation deploy runbook includes Compose render gate"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "launch_gate_audit.py" "reconciliation deploy runbook includes launch-gate audit"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "production_launch_preflight.py" "reconciliation deploy runbook includes aggregate production launch preflight"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "backup_restore_check.py" "reconciliation deploy runbook includes backup/restore gate"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "test_deploy_readiness_check.py" "reconciliation deploy runbook includes readiness policy test"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "test_site_deploy_check.py" "reconciliation deploy runbook includes Pages deploy policy test"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "billing/tests/test_tenant_pg_tools.py" "reconciliation deploy runbook includes tenant Postgres helper test"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "billing/tests/test_tenant_store.py" "reconciliation deploy runbook includes tenant mirror test"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "billing/tests/test_provision_free.py" "reconciliation deploy runbook includes free signup provisioning test"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "billing/tests/test_session_endpoints.py" "reconciliation deploy runbook includes billing session endpoint test"
require_contains docs/runbooks/2026-06-23-reconciliation-deploy.md "billing/tests/test_sessions.py" "reconciliation deploy runbook includes tenant session lifecycle test"
require_contains CHANGELOG.md "Reconciliation and positioning" "changelog records reconciliation release work"
require_contains billing/usage_pg_tools.py "ON CONFLICT ({spec.conflict_column}) DO NOTHING" "Postgres usage helper backfills proof rows idempotently"
require_contains billing/sync_usage.py "class PostgresUsageSource" "billing sync supports Postgres usage source"
require_contains billing/sync_usage.py "HC_USAGE_SOURCE=postgres requires HC_SERVER_PG_URL" "billing sync validates Postgres source configuration"
require_contains docs/postgres_migration.md "billing/usage_pg_tools.py compare" "Postgres migration doc includes parity helper"
require_contains docs/postgres_migration.md "PgUsageRecorder" "Postgres migration doc reflects implemented server recorder"
require_contains docs/postgres_migration.md "HC_SERVER_USAGE_READ_FROM=postgres" "Postgres migration doc includes usage read cutover switch"
require_contains docs/postgres_migration.md "HC_USAGE_SOURCE=postgres" "Postgres migration doc includes billing source cutover switch"
require_contains docs/postgres_migration.md "billing/tenant_pg_tools.py" "Postgres migration doc includes tenant auth migration helper"
require_contains docs/postgres_migration.md "HC_TENANT_PG_URL" "Postgres migration doc includes tenant auth write mirror"
require_contains docs/postgres_migration.md "HC_SERVER_AUTH_PG_URL" "Postgres migration doc includes tenant auth cutover switch"
require_contains docs/postgres_migration.md "HC_RATE_LIMIT_PG_URL" "Postgres migration doc includes shared quota switch"
require_contains docs/postgres_migration.md "HC_SERVER_JOB_INDEX_SOURCE=postgres" "Postgres migration doc includes job-index cutover switch"
require_contains docs/postgres_migration.md "scripts/monitoring/shared_dispatch_smoke.sh" "Postgres migration doc includes shared-dispatch smoke gate"
require_contains README.md "Phase 1 usage dual-write is wired today" "README reflects implemented Postgres usage dual-write"
require_contains README.md "HC_SERVER_USAGE_READ_FROM=postgres" "README reflects implemented Postgres usage read switch"
require_contains README.md "HC_SERVER_AUTH_PG_URL" "README reflects implemented Postgres tenant auth switch"
require_contains README.md "HC_RATE_LIMIT_PG_URL" "README reflects implemented shared quota switch"
require_contains README.md "HC_SERVER_JOB_INDEX_SOURCE=postgres" "README reflects implemented Postgres job-index switch"
require_contains README.md "HC_SERVER_PROVE_DISPATCH" "README documents shared prove dispatch switch"
require_contains BUSINESS_GUIDE.md "Phase 1 Postgres usage dual-write can mirror" "business guide reflects implemented Postgres usage dual-write"
require_contains BUSINESS_GUIDE.md "HC_USAGE_SOURCE=postgres" "business guide reflects implemented billing Postgres switch"
require_contains BUSINESS_GUIDE.md "HC_SERVER_AUTH_PG_URL" "business guide reflects implemented tenant auth Postgres switch"
require_contains BUSINESS_GUIDE.md "HC_RATE_LIMIT_PG_URL" "business guide reflects implemented shared quota switch"
require_contains BUSINESS_GUIDE.md "HC_SERVER_JOB_INDEX_SOURCE=postgres" "business guide reflects implemented Postgres job-index switch"
require_contains crates/hc-server/Cargo.toml 'postgres = "0.19"' "hc-server includes Postgres client dependency"
require_contains crates/hc-server/src/usage_log.rs "pub struct PgUsageRecorder" "hc-server implements Postgres usage recorder"
require_contains crates/hc-server/src/lib.rs "HC_SERVER_PG_URL requires SQLite usage tracking enabled" "hc-server wires Postgres dual-write behind SQLite primary"
require_contains crates/hc-server/src/lib.rs "HC_SERVER_USAGE_READ_FROM=postgres requires HC_SERVER_PG_URL" "hc-server validates Postgres usage read configuration"
require_contains crates/hc-server/src/usage_log.rs "pub trait UsageReader" "hc-server implements usage read abstraction"
require_contains crates/hc-server/src/shared_rate_limit.rs "pub struct SharedRateLimiter" "hc-server exports shared Postgres rate limiter"
require_contains crates/hc-server/src/auth/db.rs "connect_postgres" "hc-server implements Postgres tenant auth source"
require_contains crates/hc-server/src/auth/db.rs "PG_TENANT_AUTH_SCHEMA_SQL" "hc-server ships Postgres tenant auth schema"
require_contains crates/hc-server/src/lib.rs "HC_SERVER_AUTH_PG_URL" "hc-server wires Postgres tenant auth source"
require_contains crates/hc-mcp/src/bin/hc-mcp-http.rs "HC_SERVER_AUTH_PG_URL" "MCP HTTP server wires Postgres tenant auth source"
require_contains billing/tenant_pg_tools.py "tenant_auth_pg.sql" "tenant Postgres helper uses shared schema"
require_contains billing/tests/test_tenant_pg_tools.py "test_backfill_script_is_idempotent" "tenant Postgres helper tests idempotent backfill"
require_contains billing/tenant_store.py "HC_TENANT_PG_URL" "tenant store supports Postgres mirror"
require_contains billing/tenant_store.py "lifecycle_emails" "tenant store records lifecycle email ledger"
require_contains billing/tenant_store.py "checkout_recovery_emails" "tenant store records checkout recovery ledger"
require_contains billing/lifecycle_nudges.py "KIND_FREE_QUOTA" "lifecycle nudges include free quota upgrade path"
require_contains billing/lifecycle_nudges.py "KIND_IDLE_WINBACK" "lifecycle nudges include idle win-back path"
require_contains billing/lifecycle_nudges.py "TINYZKP_CUSTOMER_EMAILS_ENABLED" "lifecycle nudges default to customer-email kill switch"
require_contains billing/lifecycle_nudges.py "recipient_ref" "lifecycle nudge logs avoid raw buyer emails"
require_contains billing/tests/test_lifecycle_nudges.py "test_lifecycle_dry_run_logs_recipient_ref_not_email" "lifecycle nudge tests cover dry-run email redaction"
require_contains billing/checkout_recovery.py "stripe.checkout.Session.list" "checkout recovery scans Stripe Checkout Sessions"
require_contains billing/checkout_recovery.py "PRODUCTION_PILOT_PLAN" "checkout recovery follows up paid pilot checkout"
require_contains billing/checkout_recovery.py "TINYZKP_CUSTOMER_EMAILS_ENABLED" "checkout recovery defaults to customer-email kill switch"
require_contains billing/checkout_recovery.py "log_recovery" "checkout recovery logs use sanitized recovery refs"
require_contains billing/checkout_recovery.py "recipient_ref" "checkout recovery logs avoid raw buyer emails"
require_file billing/stripe_checkout_monitor.py
require_file billing/stripe_account_context_check.py
require_file billing/tests/test_stripe_account_context_check.py
require_file billing/stripe_revenue_readiness.py
require_file billing/tests/test_stripe_revenue_readiness.py
require_contains billing/stripe_account_context_check.py "stripe config" "Stripe account context check reads local CLI profile"
require_contains billing/stripe_account_context_check.py "display_name" "Stripe account context check validates display name"
require_contains billing/stripe_account_context_check.py "stripe-project-name" "Stripe account context check supports named CLI profiles"
require_contains billing/stripe_account_context_check.py "TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME" "Stripe account context check supports explicit expected account name"
require_contains billing/stripe_account_context_check.py "TINYZKP_STRIPE_API_KEY_ENV" "Stripe account context check supports API-key account validation"
require_contains billing/stripe_account_context_check.py "LN Holdings" "Stripe account context defaults to the LN Holdings legal account"
require_contains billing/stripe_revenue_readiness.py "Stripe revenue-readiness sequence" "Stripe readiness runner documents end-to-end revenue sequence"
require_contains billing/stripe_revenue_readiness.py "setup-catalog" "Stripe readiness runner can orchestrate catalog setup"
require_contains billing/stripe_revenue_readiness.py "sync-pipeline" "Stripe readiness runner can orchestrate pipeline sync"
require_contains billing/stripe_revenue_readiness.py "plan-only" "Stripe readiness runner supports dry-run planning"
require_contains billing/stripe_revenue_readiness.py "stripe-project-name" "Stripe readiness runner supports named CLI profiles"
require_contains billing/stripe_checkout_monitor.py "Summarize live Stripe Checkout revenue signals" "Stripe checkout monitor summarizes live revenue signals"
require_contains billing/stripe_checkout_monitor.py "SAFE_METADATA_KEYS" "Stripe checkout monitor restricts metadata output"
require_contains billing/stripe_checkout_monitor.py "production_pilot_paid" "Stripe checkout monitor counts paid pilot sessions"
require_contains billing/stripe_checkout_monitor.py "excluded_monitoring_sessions" "Stripe checkout monitor excludes synthetic canaries by default"
require_contains billing/stripe_checkout_monitor.py "stripe_account_context_check" "Stripe checkout monitor validates local Stripe account context"
require_contains billing/stripe_checkout_monitor.py "load_sessions_from_stripe_api" "Stripe checkout monitor supports API-key read path"
require_contains billing/stripe_checkout_monitor.py "stripe_project_name" "Stripe checkout monitor supports named CLI profiles"
require_file billing/stripe_catalog_write_preflight.py
require_file billing/tests/test_stripe_catalog_write_preflight.py
require_contains billing/stripe_catalog_write_preflight.py "intentionally invalid create requests" "Stripe catalog write preflight uses non-creating probes"
require_contains billing/stripe_catalog_write_preflight.py "products create" "Stripe catalog write preflight checks product create access"
require_contains billing/stripe_catalog_write_preflight.py "billing meters create" "Stripe catalog write preflight checks meter create access"
require_contains billing/stripe_catalog_write_preflight.py "prices create" "Stripe catalog write preflight checks price create access"
require_contains billing/stripe_catalog_write_preflight.py "stripe_account_context_check" "Stripe catalog write preflight validates local Stripe account context"
require_contains billing/stripe_catalog_write_preflight.py "stripe_project_name" "Stripe catalog write preflight supports named CLI profiles"
require_contains billing/stripe_revenue_ops_audit.py "Read-only Stripe and Cloudflare revenue-ops audit" "Stripe revenue ops audit is read-only"
require_contains billing/stripe_revenue_ops_audit.py "billing meters list" "Stripe revenue ops audit checks billing meters"
require_contains billing/stripe_revenue_ops_audit.py "strict-catalog" "Stripe revenue ops audit supports strict catalog enforcement"
require_contains billing/stripe_revenue_ops_audit.py "inline price fallback" "Stripe revenue ops audit recognizes pilot inline price fallback"
require_contains billing/stripe_revenue_ops_audit.py "stripe_account_context_check" "Stripe revenue ops audit validates local Stripe account context"
require_contains billing/stripe_revenue_ops_audit.py "stripe_project_name" "Stripe revenue ops audit supports named CLI profiles"
require_contains scripts/marketing/sync_stripe_checkout_pipeline.py "expected-stripe-display-name" "Stripe checkout pipeline sync validates local Stripe account context"
require_contains scripts/marketing/sync_stripe_checkout_pipeline.py "account-source" "Stripe checkout pipeline sync supports API account source"
require_contains scripts/marketing/sync_stripe_checkout_pipeline.py "stripe-project-name" "Stripe checkout pipeline sync supports named CLI profiles"
require_contains billing/provision_tenant.py "production_pilot" "billing webhook routes one-time paid pilot checkout"
require_contains billing/setup_stripe_products.sh "STRIPE_PRICE_ID_PILOT" "Stripe setup emits pilot price binding"
require_contains billing/setup_stripe_products.sh "stripe_catalog_write_preflight.py" "Stripe setup preflights catalog write permissions"
require_contains billing/setup_stripe_products.sh "stripe_account_context_check.py" "Stripe setup validates local Stripe account context"
require_contains billing/setup_stripe_products.sh "--stripe-project-name" "Stripe setup supports named CLI profiles"
require_contains billing/setup_stripe_products.sh "--stripe-cli" "Stripe setup supports authenticated local CLI profile"
require_contains billing/setup_stripe_products.sh "--push-cloudflare" "Stripe setup can push Pages secrets"
require_contains billing/setup_pilot_price.sh "STRIPE_PRICE_ID_PILOT" "pilot-only Stripe setup emits pilot price binding"
require_contains billing/setup_pilot_price.sh "stripe_catalog_write_preflight.py" "pilot-only Stripe setup preflights catalog write permissions"
require_contains billing/setup_pilot_price.sh "stripe_account_context_check.py" "pilot-only Stripe setup validates local Stripe account context"
require_contains billing/setup_pilot_price.sh "--stripe-project-name" "pilot-only Stripe setup supports named CLI profiles"
require_contains billing/setup_pilot_price.sh "--push-cloudflare" "pilot-only Stripe setup can push Pages secret"
require_contains billing/setup_pilot_price.sh "--stripe-bin" "pilot-only Stripe setup supports explicit local CLI path"
require_contains billing/setup_pilot_price.sh "redact_output" "pilot-only Stripe setup redacts CLI failures"
require_contains billing/setup_pilot_price.sh "redact(err.get" "pilot-only Stripe setup redacts Stripe error payloads"
require_contains billing/STRIPE_SETUP.md "STRIPE_PRICE_ID_PILOT" "Stripe setup documents pilot price binding"
require_contains billing/STRIPE_SETUP.md "setup_stripe_products.sh --stripe-cli --push-cloudflare" "Stripe setup documents full CLI catalog command"
require_contains billing/STRIPE_SETUP.md "setup_pilot_price.sh --push-cloudflare" "Stripe setup documents pilot-only Pages secret command"
require_contains billing/STRIPE_SETUP.md "setup_pilot_price.sh --stripe-cli --stripe-bin /opt/homebrew/bin/stripe --push-cloudflare" "Stripe setup documents explicit pilot CLI path"
require_contains billing/gtm_revenue_report.py "GTM attribution, activation, and paid-plan signals" "GTM revenue report summarizes acquisition and paid-plan signals"
require_contains billing/gtm_revenue_report.py "attribution_source" "GTM revenue report groups by stored attribution"
require_contains billing/gtm_revenue_report.py "paid_rate" "GTM revenue report computes paid conversion rate"
require_contains billing/gtm_revenue_report.py "estimated_base_mrr" "GTM revenue report estimates active base MRR"
require_contains billing/gtm_revenue_report.py "estimated_usage_revenue_cents" "GTM revenue report estimates usage revenue"
require_contains billing/gtm_revenue_report.py "paid_proofs" "GTM revenue report counts paid proofs"
require_contains billing/gtm_revenue_report.py "compute_trace_steps" "GTM revenue report summarizes Compute trace-step volume"
require_contains billing/gtm_revenue_report.py "avg_time_to_first_proof_hours" "GTM revenue report computes time-to-first-proof"
require_contains scripts/monitoring/gtm_growth_monitor.py "strict_revenue" "GTM growth monitor supports strict revenue thresholds"
require_contains scripts/monitoring/gtm_growth_monitor.py "min_paid_proofs" "GTM growth monitor supports paid-proof thresholds"
require_contains scripts/monitoring/gtm_growth_monitor.py "live public funnel" "GTM growth monitor supports live public funnel checks"
require_contains scripts/monitoring/gtm_growth_monitor.py "REGISTRY_TARGETS" "GTM growth monitor defines live package registry targets"
require_contains scripts/monitoring/gtm_growth_monitor.py "package registry live" "GTM growth monitor validates live package registry availability"
require_contains scripts/monitoring/gtm_growth_monitor.py "lifecycle ledgers" "GTM growth monitor summarizes lifecycle and checkout ledgers"
require_contains scripts/monitoring/gtm_growth_monitor.py "stripe_checkout" "GTM growth monitor can include Stripe checkout summary"
require_contains scripts/monitoring/stripe_checkout_canary.py "source=api_health_audit" "Stripe checkout canary documents synthetic source tagging"
require_contains scripts/monitoring/stripe_checkout_canary.py "cs_live_" "Stripe checkout canary requires live Checkout Session URLs by default"
require_contains scripts/monitoring/stripe_checkout_canary.py "--verify-stripe-cli" "Stripe checkout canary can verify local CLI visibility"
require_contains scripts/monitoring/stripe_checkout_canary.py "checkout.stripe.com/[redacted]" "Stripe checkout canary redacts hosted Checkout URLs"
require_contains scripts/monitoring/gtm_growth_monitor.py "badge embeds" "GTM growth monitor validates badge embed contract"
require_contains billing/tests/test_tenant_store.py "TestPostgresTenantMirror" "tenant store tests Postgres mirror behavior"
require_contains deploy/hetzner/Dockerfile.billing "tenant_auth_pg.sql" "billing image includes tenant auth schema"
require_contains deploy/hetzner/install_billing_runtime.sh "billing/requirements.txt" "billing runtime installer uses pinned requirements file"
require_contains deploy/hetzner/install_billing_runtime.sh "python3-venv" "billing runtime installer can provision venv support"
require_contains deploy/hetzner/deploy.sh "deploy_readiness_check.py" "Hetzner deploy runs readiness gate"
require_contains deploy/hetzner/deploy.sh "install_billing_runtime.sh" "Hetzner deploy refreshes billing runtime"
require_contains deploy/hetzner/deploy.sh "--host-python \"\$REPO/.venv/bin/python\"" "Hetzner deploy readiness checks billing virtualenv"
require_contains deploy/hetzner/deploy.sh "sync_host_billing_services" "Hetzner deploy syncs billing host service definitions"
require_contains deploy/hetzner/deploy.sh "/opt/hc-stark/.venv/bin/gunicorn" "Hetzner deploy writes venv-backed billing webhook unit"
require_contains deploy/hetzner/deploy.sh "scripts/monitoring/host_cron_env.sh billing/sync_usage.py" "Hetzner deploy writes env-loaded billing cron"
require_contains deploy/hetzner/deploy.sh "billing/lifecycle_nudges.py" "Hetzner deploy writes lifecycle nudge cron"
require_contains deploy/hetzner/deploy.sh "billing/checkout_recovery.py" "Hetzner deploy writes checkout recovery cron"
require_contains deploy/hetzner/deploy.sh "host_cron_env.sh scripts/monitoring/gtm_growth_monitor.py --offline" "Hetzner deploy writes env-loaded daily GTM growth monitor cron"
require_contains deploy/hetzner/deploy.sh "daily_growth_decision_cron.sh" "Hetzner deploy writes daily growth decision cron wrapper"
require_contains deploy/hetzner/deploy.sh "data/growth_snapshots" "Hetzner deploy prepares growth snapshot directory"
require_contains deploy/hetzner/setup.sh "/opt/hc-stark/.venv/bin/gunicorn" "Hetzner setup runs billing webhook from virtualenv"
require_contains deploy/hetzner/setup.sh "scripts/monitoring/host_cron_env.sh billing/sync_usage.py" "Hetzner setup runs env-loaded billing cron"
require_contains deploy/hetzner/setup.sh "billing/lifecycle_nudges.py" "Hetzner setup runs lifecycle nudge cron"
require_contains deploy/hetzner/setup.sh "host_cron_env.sh scripts/monitoring/gtm_growth_monitor.py --offline" "Hetzner setup writes env-loaded daily GTM growth monitor cron"
require_contains deploy/hetzner/setup.sh "daily_growth_decision_cron.sh" "Hetzner setup writes daily growth decision cron wrapper"
require_contains deploy/hetzner/setup.sh "data/growth_snapshots" "Hetzner setup prepares growth snapshot directory"
require_contains deploy/hetzner/setup.sh "billing/checkout_recovery.py" "Hetzner setup runs checkout recovery cron"
require_contains crates/hc-server/src/lib.rs "HC_RATE_LIMIT_PG_URL" "hc-server wires shared Postgres rate limiter"
require_contains crates/hc-mcp/src/bin/hc-mcp-http.rs "HC_RATE_LIMIT_PG_URL" "MCP HTTP server wires shared Postgres rate limiter"
require_contains crates/hc-mcp/src/bin/hc-mcp-http.rs "endpoint_name(\"mcp\")" "MCP authenticated lane shares prove quota window"
require_contains crates/hc-mcp/Cargo.toml 'rmcp = { version = "1.5"' "MCP crate uses rmcp release with Host-header guard fix"
require_contains .cargo/audit.toml "RUSTSEC-2026-0190" "cargo audit documents temporary anyhow advisory ignore"
require_contains deny.toml "RUSTSEC-2026-0190" "cargo deny documents temporary anyhow advisory ignore"
require_contains crates/hc-server/src/job_index.rs "pub struct PgJobIndex" "hc-server implements Postgres job index"
require_contains crates/hc-server/src/job_index.rs "pub trait JobStore" "hc-server abstracts job index storage"
require_contains crates/hc-server/src/job_index.rs "fn claim_next" "hc-server job store exposes worker claim primitive"
require_contains crates/hc-server/src/job_index.rs "FOR UPDATE SKIP LOCKED" "Postgres job claim avoids double-claiming workers"
require_contains crates/hc-server/src/lib.rs "HC_SERVER_JOB_INDEX_SOURCE=postgres requires" "hc-server validates Postgres job-index configuration"
require_contains crates/hc-server/src/lib.rs "status_to_proof_result" "hc-server can load completed proofs from shared job index"
require_contains crates/hc-server/src/lib.rs "cancel_updates_nonlocal_job_index_job" "hc-server can cancel non-local shared-index jobs"
require_contains crates/hc-server/src/lib.rs "HC_SERVER_PROVE_DISPATCH" "hc-server wires shared dispatch mode"
require_contains crates/hc-server/tests/api.rs "shared_dispatch_claimed_worker_completion_polls_and_verifies" "hc-server tests shared-dispatch claim/complete/poll/verify path"
require_contains crates/hc-server/src/bin/hc-job-worker.rs "claim_next" "hc-job-worker claims shared jobs"
require_contains crates/hc-server/src/bin/hc-job-worker.rs "renew_claim" "hc-job-worker renews leases while proving"
require_contains crates/hc-server/src/bin/hc-job-worker.rs "HC_JOB_WORKER_USAGE_DISABLED" "hc-job-worker fails closed on billing unless explicitly disabled"
require_contains crates/hc-server/src/bin/hc-job-worker.rs "shutdown_signal" "hc-job-worker handles deploy shutdown signals"
require_contains crates/hc-server/src/bin/hc-job-worker.rs "--check-config" "hc-job-worker supports config preflight mode"
require_contains crates/hc-server/src/bin/hc-job-worker.rs "--once" "hc-job-worker supports one-shot claim mode"
require_contains crates/hc-server/src/bin/hc-job-worker.rs "prove timeout after" "hc-job-worker records terminal failures on prove timeout"
require_contains crates/hc-server/src/bin/hc-job-worker.rs "execute_claimed_job_marks_timeout_failed" "hc-job-worker tests timeout failure recording"
require_contains crates/hc-server/src/bin/hc-job-worker.rs "usage recording failed after proof generation" "hc-job-worker fails closed if success usage recording fails"
require_contains crates/hc-server/src/bin/hc-job-worker.rs "execute_claimed_job_does_not_publish_success_when_usage_fails" "hc-job-worker tests usage failure fail-closed behavior"
require_contains Dockerfile "hc-job-worker" "Docker image includes shared job worker binary"
require_contains docker-compose.yml "shared-workers" "Compose defines opt-in shared worker profile"
require_contains deploy/hetzner/deploy.sh "HC_SERVER_PROVE_DISPATCH=shared detected" "Hetzner deploy enables worker profile for shared dispatch"
require_contains deploy/hetzner/deploy.sh "hc-job-worker --check-config" "Hetzner deploy preflights shared worker config"
require_contains crates/hc-server/src/bin/hc-worker.rs "--stdio" "hc-worker supports stdin/stdout request-proof handoff"
require_contains crates/hc-server/src/lib.rs ".arg(\"--stdio\")" "hc-server streams worker request/proof handoff"
require_contains docs/operations.md "Worker request/proof handoff streams over stdin/stdout" "operations guide documents streamed worker handoff"

require_contains crates/hc-workloads/src/templates/mod.rs "pub enum TemplateLifecycle" "workloads define template lifecycle enum"
require_contains crates/hc-workloads/src/templates/mod.rs "Self::AuditGated => \"audit_gated\"" "workloads serialize audit_gated lifecycle"
require_contains crates/hc-server/src/lib.rs "lifecycle: t.lifecycle.as_str().to_string()" "API template listing returns lifecycle"
require_contains crates/hc-mcp/src/tools/discovery.rs '"lifecycle": t.lifecycle.as_str()' "MCP all-template listing returns lifecycle"
require_contains crates/hc-sdk/src/types.rs "pub lifecycle: String" "SDK template summary accepts lifecycle"

require_no_regex 'TnyZKP|tnyzkp' "public product files avoid the TnyZKP typo" \
  README.md BUSINESS_GUIDE.md site
require_no_regex '^All endpoints require a Bearer token' "README avoids overbroad auth claim" README.md
require_no_regex 'requires your TinyZKP API key|mcp\.tinyzkp\.com/healthz|prove_status|submit_workload|workload_status|list_jobs|healthz</div>' "public docs avoid stale MCP claims and tool names" \
  site/docs.html site/status.html
require_no_regex 'range_proof|witness_steps|Six built-in templates|six built-in templates|without revealing' "client package docs avoid gated-template privacy claims" \
  clients/python/README.md clients/typescript/README.md clients/python/tinyzkp/client.py clients/typescript/src/client.ts clients/rust/src/lib.rs

if [ "$MODE" = "--live" ]; then
  require_url_contains "$SITE_URL/research" "One company, one thesis: space-efficient proving." "live /research serves reconciliation page"
  require_url_contains "$SITE_URL/security" "Responsible disclosure" "live /security serves security page"
  require_url_contains "$SITE_URL/docs" "Template Lifecycle" "live /docs serves lifecycle docs"

  api_body=$(curl -fsSL --max-time 30 "$API_URL/templates" 2>/dev/null || true)
  if [ -z "$api_body" ]; then
    fail "live /templates request failed"
  elif grep -Eq '"lifecycle"[[:space:]]*:[[:space:]]*"live"' <<<"$api_body"; then
    pass "live /templates exposes lifecycle=live"
  else
    fail "live /templates does not expose lifecycle=live"
    printf '%s\n' "$api_body" >&2
  fi
elif [ "$MODE" != "local" ]; then
  fail "unknown mode: $MODE"
fi

if [ "$failures" -gt 0 ]; then
  printf '\n%d reconciliation invariant(s) failed.\n' "$failures" >&2
  exit 1
fi

printf '\nAll reconciliation invariants passed.\n'
