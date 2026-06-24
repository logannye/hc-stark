# Changelog

All notable user-visible changes to TinyZKP are tracked here.

The format follows Keep a Changelog-style sections, and the release policy lives
in [`docs/governance/release_policy.md`](docs/governance/release_policy.md).

## Unreleased

Release theme: Reconciliation and positioning across the production repo, the
legacy research repo, and TinyZKP.com.

### Added

- Public research-lineage page explaining why `hc-stark` is the production
  TinyZKP repo and `space-efficient-zero-knowledge-proofs` is legacy KZG/BN254
  research lineage.
- Public security/audit status page with template lifecycle vocabulary:
  `live`, `audit_gated`, and `preview`.
- Template lifecycle metadata across workload discovery, HTTP API responses,
  MCP template listings, and SDK template summaries.
- Reconciliation CI invariant script for public story, site markers, lifecycle
  schema, and typo/stale-MCP-copy guards.
- Coordinated reconciliation deploy runbook for API/MCP/site deployment.
- MCP synthetic monitoring in the production audit, with opt-in full
  `prove_template -> poll_job -> get_proof -> verify_proof` coverage.
- Release and compatibility policy plus CODEOWNERS for production surfaces.
- Release provenance runbook plus GitHub artifact attestations, npm
  provenance flags, and MCP checksum files for SDK/verifier/MCP release
  artifacts.
- Postgres usage-migration helper that compares SQLite/Postgres parity and
  idempotently backfills successful and failed proof rows.
- Phase 1 Postgres usage dual-write in `hc-server`: `HC_SERVER_PG_URL` mirrors
  prove success, verify, and prove failure rows while SQLite remains primary.
- Phase 2-ready Postgres usage read paths: `HC_SERVER_USAGE_READ_FROM=postgres`
  moves `/usage` and monthly cap checks to Postgres, and `HC_USAGE_SOURCE=postgres`
  moves Stripe usage sync to the same source after parity checks pass.
- Optional Postgres-backed shared rate limiter: `HC_RATE_LIMIT_PG_URL` lets
  `hc-server` and `hc-mcp-http` consume the same authenticated tenant RPM
  windows instead of multiplying quota across processes.
- Optional Postgres-backed tenant/auth read path: `HC_SERVER_AUTH_PG_URL` lets
  `hc-server` and `hc-mcp-http` resolve active tenant API keys from a shared
  `tenants` table during Postgres cutovers.
- Optional billing-webhook tenant/auth Postgres mirror: `HC_TENANT_PG_URL`
  continuously mirrors tenant, Stripe event, magic-link, and session mutations
  before API/MCP auth reads are cut over.
- Tenant-store Postgres migration helper for initializing, backfilling,
  comparing, and dry-running tenant/auth state from `tenant_store.sqlite`.
- Optional Postgres job index: `HC_SERVER_JOB_INDEX_SOURCE=postgres` stores
  request/status JSON and completed proof bytes in Postgres so polling and
  proof download are no longer tied to a single API process.
- Shared prove-dispatch path: `HC_SERVER_PROVE_DISPATCH=shared` lets the API
  enqueue jobs for `hc-job-worker`, which claims leases from the shared job
  index, renews while proving, watches cancellation, and records usage.
- Privacy-bounded website analytics endpoint and client instrumentation for
  activation events across docs, playground, signup, checkout, research, and
  client-side verification.
- Structured contact qualification workflow for Compute, enterprise, and
  design-partner inquiries.
- Public support expectations on the contact, status, and terms pages,
  including response targets for security, billing/account, incident, Compute,
  and enterprise inquiries.
- Incident-response runbook plus public status-page incident categories and
  response targets.
- Developer-experience docs for "when not to use TinyZKP", SDK/verifier
  compatibility, local development/self-hosting, Rust examples, and docs
  code-copy tracking.
- Public API versioning and deprecation guidance in the docs, including
  release-identity endpoints for site/API/MCP deploy-skew checks.
- Production deploy readiness checker for `.env` coherence, placeholder
  secrets, shared-dispatch Postgres prerequisites, and tenant-auth cutover
  safety before Hetzner deploys.
- Host-level billing webhook/cron runtime hardening: deploys now refresh an
  isolated `/opt/hc-stark/.venv`, sync billing cron/systemd definitions to use
  it, and verify the Postgres mirror driver before restarting the webhook.
- Cloudflare Pages deploy preflight for `site/wrangler.toml`, Advanced Mode
  `_worker.js` routing, Pages API handler exports, required production bindings,
  and all function-module JavaScript syntax.
- Functional Advanced Mode Pages worker dispatch test covering API routing,
  405 handling, static asset passthrough, and extensionless HTML fallback.
- Advanced Mode Pages worker now applies baseline browser security headers to
  static assets, API responses, and worker-generated error/method responses.
- Advanced Mode Pages worker now redirects alternate/typo site hostnames to
  the canonical `https://tinyzkp.com` origin before route dispatch.
- Docker Compose render preflight covering local, production, and shared-worker
  production profiles before deploys rely on those service graphs.
- Local launch-gate audit mapping the reconciliation roadmap phases to concrete
  repo evidence, with deploy/observation actions reported separately from local
  readiness.
- Aggregate production launch preflight for reconciliation releases. It runs
  the fast repo, site, Pages worker, Compose, backup/restore, deploy-readiness,
  route-policy, and launch-gate checks locally, with opt-in live and
  authenticated smoke canaries for the post-deploy announcement gate.
- Backup/restore drift check that keeps the G13 restore runbook aligned with
  current state files, SQLite tables, auth verification path, and off-box backup
  requirements.

### Changed

- README and business guide now position TinyZKP as one company with one current
  production repo and one research-lineage repo.
- Compute page now separates live long state-transition proving from
  design-partner and roadmap work.
- Public MCP docs now describe the hosted anonymous lane and optional Bearer
  lane consistently.
- Status page now checks the public MCP server card instead of a nonexistent
  `/healthz` route.
- External uptime probe now checks API template schema, MCP server card, and
  public page content markers instead of status codes alone.
- Billing docs now distinguish active monthly self-serve checkout from optional
  manual annual contract prices.
- Python, TypeScript, and Rust SDK package docs now use the live
  `accumulator_step` template and surface template lifecycle instead of stale
  gated-template/privacy examples.

### Fixed

- Removed public copy that could imply gated templates are part of the default
  production catalog.
- Removed stale public docs that implied the hosted MCP endpoint always requires
  an API key.
- Removed stale annual self-serve pricing language from the business guide.
- Simplified the homepage hero headline to one semantic `<h1>` instead of
  duplicated desktop/mobile text.
- Added missing canonical URLs to docs, Compute, contact, legal, and onboarding
  pages.
- Marked account-flow pages as `noindex` and extended the static route policy
  to enforce robots.txt plus sitemap/canonical agreement.
- Added API, MCP, and Pages release-identity endpoints plus an optional live
  preflight SHA check so coordinated launches can reject site/API/MCP version
  skew.
- Added a static MCP server-card policy check and live smoke validation so MCP
  directory discovery cannot drift from the current public tool catalog.
- Extended static site checks to validate social preview URLs, JSON-LD local
  URLs, and required OpenGraph/favicon assets.
- Redacted sensitive strings and stripped URL query/hash material from
  privacy-bounded analytics logs, with worker-dispatch coverage for the logged
  event record.

### Operations

- CI now runs reconciliation invariants and pricing copy parity checks before
  heavier Rust jobs.
- CI now installs the pinned billing runtime requirements before billing
  endpoint tests, matching the production webhook environment.
- CI now covers the Postgres usage-migration helper.
- CI now covers the Postgres tenant/auth migration helper.
- Daily production audit now catches Cloudflare fallback pages by validating
  expected content markers.
- Added a focused shared-dispatch smoke gate for release and Postgres worker
  cutovers: lifecycle metadata, site markers, prove, poll/download, inspect,
  verify, cancel route, and usage access.
- `hc-job-worker` now handles deploy shutdown signals by stopping claims and
  leaving an interrupted in-flight job to be reclaimed after lease expiry.
- `hc-job-worker` now records prove timeouts as terminal failed jobs with a
  failed-usage row instead of letting them loop through repeated lease reclaims.
- `hc-job-worker` now records successful-proof usage before publishing
  `Succeeded`; usage-write failures fail closed instead of exposing unmetered
  proofs.
- `hc-job-worker --check-config` and `hc-job-worker --once` give operators a
  preflight and controlled single-claim rehearsal mode for shared-dispatch
  cutovers.
- Hetzner deploys now run `hc-job-worker --check-config` before restarting
  containers when shared dispatch is enabled.
- Mobile website layout now contains code blocks, tabs, Compute content, and
  contact/signup decorative glows inside the viewport.
- Homepage mobile hero copy now uses explicit responsive line wrapping for the
  badge, headline, and O(sqrt(N)) memory note so first-viewport text is not
  clipped on narrow devices.
- Docs now expose a primary page heading, and the account login view clamps its
  mobile decorative glow inside the viewport.
- CI now covers Python, TypeScript, and Rust SDK package checks plus website
  JavaScript syntax checks; the dedicated SDK workflow now runs the current
  package test commands.
- CI now validates internal website routes, anchors, assets, Pages Function
  worker dispatch links, literal app-script routes, sitemap URLs, primary page
  headings, meta descriptions, titles, and canonical URLs before deploy.
- `backup.sh` now has deterministic data-dir, timestamp, retention, and remote-date
  overrides for restore drills, and CI smoke-runs it against temporary SQLite
  databases to verify readable snapshots and restrictive permissions.
- Cloudflare Pages worker dispatch tests now cover account and billing API
  routes, session-gated dashboard routes, logout cookie clearing, and
  magic-link metadata filtering so raw API keys or session tokens cannot leak
  to the browser through an upstream regression.
- Cloudflare Pages worker dispatch tests now assert baseline browser security
  headers on static assets, extensionless fallbacks, API responses, and 405s.
- Billing session endpoint tests are now part of CI and the reconciliation
  deploy runbook, including magic-link session creation, safe dashboard
  metadata, and tenant session lifecycle coverage.
- Paid checkout now fails closed when required price bindings are missing, and
  the Pages worker dispatch test verifies Developer, Compute, legacy Team-to-Pro,
  missing flat-price, and missing Compute trace-step-meter Stripe Checkout
  request shapes.
- Release test suites now use per-process scratch directories and log files so
  local stress/ladder/sanity runs cannot delete each other's temporary files.
- Height benchmark dashboard generation now uses timezone-aware UTC timestamps
  and runs cleanly on current Python.
- Free signup now normalizes email before provisioning and duplicate checks;
  CI covers the Pages-to-webhook payload, non-leakage of raw API keys, upstream
  error surfacing, and duplicate-email prevention.
