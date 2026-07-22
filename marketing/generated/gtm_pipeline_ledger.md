# TinyZKP Guard Revenue Readiness Pipeline

This pipeline is a canonical gate view with a date-only schedule overlay. It is not a sales forecast, customer ledger, payment ledger, or booked-revenue report.

## Summary

- Total records: 9
- Blocking records: 9
- Passed records: 0
- Sales open: `false`
- Checkout enabled: `false`
- Revenue evidence claimed: `false`
- Recorded revenue: `$0`

## Gate Records

| Gate | Category | Status | Evidence | Next action date | Next action |
|---|---|---|---:|---|---|
| [engine_release_ready](https://tinyzkp.com/releases#gate-engine-release-ready) | `release` | `blocked` | 0 |  | Publish digest-bound engine release evidence from the reviewed release commit. |
| [guard_artifact_published](https://tinyzkp.com/releases#gate-guard-artifact-published) | `release` | `blocked` | 0 |  | Publish the signed Guard artifact, checksum, provenance, and channel metadata. |
| [guard_release_ready](https://tinyzkp.com/releases#gate-guard-release-ready) | `release` | `blocked` | 0 |  | Publish the reviewed Guard release manifest and its bound source identity. |
| [hosted_infrastructure_decommissioned](https://tinyzkp.com/releases#gate-hosted-infrastructure-decommissioned) | `operations` | `blocked` | 0 |  | Decommission retained hosted infrastructure only after the obligation inventory is complete. |
| [legacy_obligations_resolved](https://tinyzkp.com/releases#gate-legacy-obligations-resolved) | `operations` | `blocked` | 0 |  | Resolve and record every retained customer, billing, data, and service obligation. |
| [legal_terms_approved](https://tinyzkp.com/releases#gate-legal-terms-approved) | `legal` | `blocked` | 0 |  | Record LN Holdings owner approval of the exact seller facts and digest-bound legal documents. |
| [merchant_live_owner_smoke_passed](https://tinyzkp.com/releases#gate-merchant-live-owner-smoke-passed) | `commerce` | `blocked` | 0 |  | Complete and record the owner-controlled Lemon Squeezy production smoke test. |
| [merchant_sandbox_lifecycle_passed](https://tinyzkp.com/releases#gate-merchant-sandbox-lifecycle-passed) | `commerce` | `blocked` | 0 |  | Complete and record the Lemon Squeezy sandbox purchase, renewal, cancellation, and access lifecycle. |
| [release_rehearsal_within_budget](https://tinyzkp.com/releases#gate-release-rehearsal-within-budget) | `operations` | `blocked` | 0 |  | Complete and bind the technical build, deploy, canary, artifact-identity, rollback, and recovery rehearsal. |
