# TinyZKP release and compatibility policy

Status: active policy for the `hc-stark` production repo.

This document turns the unified company story into an operating model. The goal
is to let TinyZKP ship product, protocol, website, billing, and SDK changes
without mixing unrelated risk or surprising users who depend on proof formats,
API behavior, or pricing.

## Release surfaces

TinyZKP has five release surfaces. Every pull request should identify which
surface it changes.

| Surface | Examples | Primary risk |
|---|---|---|
| Protocol and verifier | `hc-prover`, `hc-verifier`, `hc-sdk` proof bytes, transcript domains, WASM verifier | Previously issued proofs stop verifying, or a weaker proof is accepted |
| API and MCP | `hc-server`, `hc-mcp`, OpenAPI, tool schemas, auth/rate limits | Integrations fail or quota/billing behavior changes |
| SDKs and CLI | Python, TypeScript, Rust SDKs, CLI, MCP binaries | Developer workflows break |
| Website and public docs | `site/`, README, business guide, security/research pages | Public claims drift from the live product |
| Billing and pricing | `pricing.json`, Stripe functions, webhook, tenant store, usage sync | Customers are charged incorrectly or plans behave differently than advertised |

## Release trains

Use separate release trains unless a change must be coordinated.

| Train | When to use | Required gates |
|---|---|---|
| Website copy/docs | Public positioning, docs, pricing copy, security/research pages | `scripts/ci/reconciliation_invariants.sh`, `python3 -m pytest billing/tests/test_site_pricing_parity.py`, sitemap XML check |
| API/MCP server | HTTP routes, MCP tools, auth, rate limits, template discovery | Rust tests for touched crates, API/MCP synthetic audit, deploy runbook |
| Protocol/verifier | Proof format, transcript, prover, verifier, WASM verifier | Soundness suite, SDK verifier tests, security docs, changelog compatibility entry |
| SDK/CLI | Published package behavior or examples | SDK CI, examples, changelog entry, package version bump if user-visible |
| Billing/pricing | Stripe, tenant plans, usage metering, pricing copy | Billing pytest suite, pricing parity tests, checkout canary, rollback note |

Coordinated releases are required when one surface makes a public claim that
depends on another surface. Example: the reconciliation release must deploy API
and MCP lifecycle fields before the website says lifecycle labels exist.

## Release provenance

Published SDK, verifier, and MCP release artifacts must be attributable to a
tagged GitHub Actions run. The `Publish SDKs` workflow uses npm provenance,
GitHub artifact attestations, and MCP SHA-256 checksum files; operators should
follow [`docs/runbooks/release_provenance.md`](../runbooks/release_provenance.md)
for verification and failure handling.

## Compatibility policy

### API

- Public routes must remain backward compatible unless the changelog marks a
  breaking change and the release notes include migration guidance.
- New response fields should be additive and optional for clients. SDK types
  should deserialize older servers conservatively.
- Auth and rate-limit behavior must be documented before deploy if it changes.
- Deprecated routes should receive at least one release cycle of warning unless
  they are disabled for security reasons.

### MCP

- Tool names, parameter names, and result fields are public API.
- Additive fields are allowed. Removing a tool or changing required parameters
  requires a changelog entry and MCP directory/server-card update.
- The hosted public lane and optional Bearer lane must stay documented together
  so users understand anonymous limits versus authenticated plan limits.

### Proof formats and verifier packages

- Proof bytes, transcript domains, security floors, and verifier acceptance
  rules are wire contracts.
- A verifier may accept older proof versions only when the current security
  policy explicitly allows that version.
- Any new production proof version must include:
  - verifier tests through `verify_proof_bytes`
  - documented security floor
  - changelog entry
  - SDK/WASM compatibility note
  - rollout/rollback plan
- Never market a proof mode as private or audited unless the exact template,
  configuration, and audit status are documented.

### Pricing and billing

- `pricing.json` is the single source of truth for plan limits and price tiers.
- Public pricing copy must not invent proof-count quotas for paid plans or
  included trace-step allotments.
- Self-serve annual checkout remains disabled until annual usage meters,
  reporting, and reconciliation are wired end to end.
- `team` is a legacy/admin alias for `pro`, not a storefront plan.

## Changelog policy

Maintain the root `CHANGELOG.md`.

Every user-visible change needs an entry under `Unreleased` before merge:

- API route behavior, response shape, auth, or rate limit changes
- MCP tool schemas, tool list, or server-card changes
- proof-format, transcript, security-floor, or verifier changes
- SDK/CLI behavior changes
- pricing, billing, or plan-limit changes
- public website claims around security, lifecycle, research lineage, or Compute

Use these sections: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
`Security`, and `Operations`.

Internal refactors with no user-visible effect may omit a changelog entry, but
the PR description should say why.

## Deployment gates

Before a production deploy:

```bash
cargo fmt --all --check
git diff --check
scripts/ci/reconciliation_invariants.sh
python3 -m pytest billing/tests/test_site_pricing_parity.py
xmllint --noout site/sitemap.xml
bash -n scripts/monitoring/api_health_audit.sh
```

Then add the train-specific gates from the table above. For the reconciliation
release, use `docs/runbooks/2026-06-23-reconciliation-deploy.md`.

## Rollback rules

- Website-only rollback is allowed when API/MCP contracts remain backward
  compatible.
- API/MCP rollback must consider jobs in flight and billing usage emitted during
  the bad deploy.
- Protocol/verifier rollback is a security decision, not just an operations
  decision. If a deployed verifier accepts a bad proof, publish an incident note
  and rotate the accepted proof floor where needed.
- Billing rollback must reconcile Stripe events, local tenant state, and usage
  rows before declaring recovery complete.

## Legacy research repo policy

`space-efficient-zero-knowledge-proofs` remains public research lineage. Changes
there should be limited to:

- paper support
- correctness/security caveats
- build/test hygiene
- links forward to `hc-stark` and TinyZKP.com

Do not move the old KZG/BN254 code into the production service unless a concrete
customer need justifies a trusted-SRS product line with a separate security and
commercial story.
