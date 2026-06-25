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
  if printf '%s' "$body" | grep -Fq "$marker"; then
    pass "$label"
  else
    fail "$label (missing live marker: $marker)"
  fi
}

require_file site/research.html
require_file site/security.html
require_file .github/CODEOWNERS
require_file CHANGELOG.md
require_file billing/usage_pg_tools.py
require_file billing/tenant_pg_tools.py
require_file crates/hc-server/sql/tenant_auth_pg.sql
require_file docs/governance/release_policy.md
require_file docs/runbooks/incident_response.md
require_file docs/runbooks/release_provenance.md
require_file docs/strategy/reconciliation_roadmap.md
require_file docs/runbooks/2026-06-23-reconciliation-deploy.md
require_file site/analytics.js
require_file site/functions/api/events.js
require_file scripts/monitoring/shared_dispatch_smoke.sh
require_file scripts/ci/site_route_check.py
require_file scripts/ci/site_deploy_check.py
require_file scripts/ci/site_worker_dispatch_test.mjs
require_file scripts/ci/compose_config_check.py
require_file scripts/ci/launch_gate_audit.py
require_file scripts/ci/production_launch_preflight.py
require_file scripts/ci/release_identity_check.py
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
require_contains site/status.html "Incident categories and response targets" "status page documents incident categories"
require_contains site/status.html "Billing and account" "status page includes billing incident category"
require_contains site/privacy.html "Product analytics" "privacy policy documents product analytics"
require_contains site/privacy.html "do not include proof bytes, API keys, email addresses, or form contents" "privacy policy bounds analytics collection"
require_contains site/account.html "status:         data.status" "account dashboard preserves server-reported session status"
require_contains site/account.html ".login-view::before{width:320px;height:320px;top:-120px}" "account mobile glow stays within viewport"
require_contains site/_worker.js "SECURITY_HEADERS" "Pages worker applies baseline browser security headers"
require_contains site/_worker.js "releaseInfo" "Pages worker exposes release identity for deploy skew checks"
require_contains site/_worker.js "CANONICAL_HOST" "Pages worker defines canonical host"
require_contains site/_worker.js "TYPO_HOSTS" "Pages worker handles typo-domain redirects"
require_contains scripts/ci/site_worker_dispatch_test.mjs "assertSecurityHeaders" "Pages worker dispatch test validates browser security headers"
require_contains scripts/ci/site_worker_dispatch_test.mjs "utm_source=old-card" "Pages worker dispatch test validates typo-domain redirect"
require_contains crates/hc-mcp/src/bin/hc-mcp-http.rs "HC_RELEASE_SHA" "MCP HTTP server exposes release identity for deploy skew checks"
require_contains site/functions/api/events.js "ALLOWED_EVENTS" "analytics endpoint allowlists events"
require_contains site/functions/api/events.js "ALLOWED_PROPS" "analytics endpoint allowlists properties"
require_contains site/functions/api/events.js "redactSensitiveText" "analytics endpoint redacts sensitive string values"
require_contains site/analytics.js "navigator.sendBeacon" "analytics client uses beacon delivery"
require_contains site/contact.html "Project fit" "contact page captures structured qualification"
require_contains site/contact.html "Do not paste API keys, private inputs, proofs, or customer data." "contact page warns against sensitive submissions"
require_contains site/contact.html "Support expectations" "contact page publishes support expectations"
require_contains site/status.html "Direct fallback email" "status page publishes support fallback channel"
require_contains site/terms.html "support expectations" "terms page links support expectations"
require_contains site/functions/api/contact.js "QUALIFICATION_FIELDS" "contact function allowlists qualification fields"
require_contains site/functions/api/create-checkout.js "creating a partial paid subscription" "checkout function documents fail-closed paid-plan billing"
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
require_contains .github/workflows/ci.yml "npm run build" "CI builds TypeScript SDK"
require_contains .github/workflows/ci.yml "cargo test --manifest-path clients/rust/Cargo.toml" "CI tests standalone Rust SDK"
require_contains .github/workflows/ci.yml "node --check site/_worker.js" "CI syntax-checks site JavaScript"
require_contains .github/workflows/ci.yml "scripts/monitoring/shared_dispatch_smoke.sh" "CI syntax-checks shared-dispatch smoke script"
require_contains .github/workflows/ci.yml "deploy/hetzner/install_billing_runtime.sh" "CI syntax-checks billing runtime installer"
require_contains .github/workflows/ci.yml "scripts/ci/site_route_check.py" "CI checks static site routes"
require_contains .github/workflows/ci.yml "scripts/ci/test_site_route_check.py" "CI tests static site route policy"
require_contains .github/workflows/ci.yml "scripts/ci/site_deploy_check.py" "CI checks Cloudflare Pages deploy config"
require_contains .github/workflows/ci.yml "scripts/ci/site_worker_dispatch_test.mjs" "CI tests Cloudflare Pages worker dispatch"
require_contains .github/workflows/ci.yml "scripts/ci/compose_config_check.py" "CI checks Docker Compose render paths"
require_contains .github/workflows/ci.yml "scripts/ci/launch_gate_audit.py" "CI checks launch-gate evidence"
require_contains .github/workflows/ci.yml "scripts/ci/production_launch_preflight.py" "CI runs aggregate production launch preflight"
require_contains .github/workflows/ci.yml "scripts/ci/test_production_launch_preflight.py" "CI tests production launch preflight"
require_contains .github/workflows/ci.yml "scripts/ci/test_release_identity_check.py" "CI tests release identity policy"
require_contains .github/workflows/ci.yml "scripts/ci/server_card_check.py" "CI checks MCP server-card policy"
require_contains .github/workflows/ci.yml "scripts/ci/backup_restore_check.py" "CI checks backup/restore drift"
require_contains .github/workflows/ci.yml "billing/tests/test_backup_script.py" "CI smoke-runs backup script"
require_contains .github/workflows/ci.yml "xargs -0 -n1 node --check" "CI syntax-checks all Pages API modules"
require_contains .github/workflows/ci.yml "bash -n billing/backup.sh" "CI syntax-checks backup script"
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
require_contains scripts/ci/production_launch_preflight.py "test_site_route_check.py" "production launch preflight runs static route policy tests"
require_contains scripts/ci/production_launch_preflight.py "release_identity_check.py" "production launch preflight can validate live release identity"
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
require_contains site/index.html 'src="/analytics.js"' "homepage loads analytics client"
require_contains site/index.html "mobile-break" "homepage mobile hero has explicit line wrapping"
require_contains site/index.html "memory-note" "homepage mobile memory note wraps cleanly"
require_contains site/index.html ".code-tabs{justify-content:flex-start;overflow-x:auto" "homepage mobile code tabs stay within viewport"
require_contains site/index.html ".code-block{max-width:100%;padding:20px 18px}" "homepage mobile code blocks stay within viewport"
require_contains site/try.html "playground_prove_succeeded" "playground tracks proof completion"
require_contains site/signup.html "checkout_started" "signup page tracks checkout starts"
require_contains site/signup.html "main::before{width:320px;height:320px;top:-120px}" "signup mobile glow stays within viewport"
require_contains site/verify.html "client_verify_succeeded" "verifier page tracks local verification success"
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
require_contains clients/typescript/README.md "accumulator_step" "TypeScript SDK README uses live canonical template"
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
require_contains billing/tests/test_tenant_store.py "TestPostgresTenantMirror" "tenant store tests Postgres mirror behavior"
require_contains deploy/hetzner/Dockerfile.billing "tenant_auth_pg.sql" "billing image includes tenant auth schema"
require_contains deploy/hetzner/install_billing_runtime.sh "billing/requirements.txt" "billing runtime installer uses pinned requirements file"
require_contains deploy/hetzner/install_billing_runtime.sh "python3-venv" "billing runtime installer can provision venv support"
require_contains deploy/hetzner/deploy.sh "deploy_readiness_check.py" "Hetzner deploy runs readiness gate"
require_contains deploy/hetzner/deploy.sh "install_billing_runtime.sh" "Hetzner deploy refreshes billing runtime"
require_contains deploy/hetzner/deploy.sh "--host-python \"\$REPO/.venv/bin/python\"" "Hetzner deploy readiness checks billing virtualenv"
require_contains deploy/hetzner/deploy.sh "sync_host_billing_services" "Hetzner deploy syncs billing host service definitions"
require_contains deploy/hetzner/deploy.sh "/opt/hc-stark/.venv/bin/gunicorn" "Hetzner deploy writes venv-backed billing webhook unit"
require_contains deploy/hetzner/deploy.sh "/opt/hc-stark/.venv/bin/python billing/sync_usage.py" "Hetzner deploy writes venv-backed billing cron"
require_contains deploy/hetzner/setup.sh "/opt/hc-stark/.venv/bin/gunicorn" "Hetzner setup runs billing webhook from virtualenv"
require_contains deploy/hetzner/setup.sh "/opt/hc-stark/.venv/bin/python billing/sync_usage.py" "Hetzner setup runs billing cron from virtualenv"
require_contains crates/hc-server/src/lib.rs "HC_RATE_LIMIT_PG_URL" "hc-server wires shared Postgres rate limiter"
require_contains crates/hc-mcp/src/bin/hc-mcp-http.rs "HC_RATE_LIMIT_PG_URL" "MCP HTTP server wires shared Postgres rate limiter"
require_contains crates/hc-mcp/src/bin/hc-mcp-http.rs "endpoint_name(\"mcp\")" "MCP authenticated lane shares prove quota window"
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
  elif printf '%s' "$api_body" | grep -Eq '"lifecycle"[[:space:]]*:[[:space:]]*"live"'; then
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
