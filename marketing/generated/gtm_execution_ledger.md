# TinyZKP Guard Revenue Readiness Ledger

Generated from the canonical Community/Guard launch contracts dated `2026-07-18`.

This is a fail-closed readiness ledger. It is not a customer, payment, or booked-revenue ledger.

## Current Business State

- Launch: `blocked`
- Sales: `closed`
- Checkout enabled: `false`
- Merchant of record: `lemon_squeezy` (`approval_pending`)
- Legal: `blocked_pending_owner_approval`
- Hosted proving: `false`
- Usage metering: `false`
- Revenue evidence claimed: `false`
- Recorded revenue: `$0`

## Guard Offer

- Availability: `blocked_until_all_launch_gates_pass`
- Monthly: `$499`
- Annual: `$4,990` (recommended)

## Gate Summary

- Total gates: 9
- Blocking gates: 9
- Passed gates: 0

## Guard Launch Gate Queue

| Gate | Category | Status | Evidence | Next action |
|---|---|---|---:|---|
| [engine_release_ready](https://tinyzkp.com/releases#gate-engine-release-ready) | `release` | `blocked` | 0 | Publish digest-bound engine release evidence from the reviewed release commit. |
| [guard_artifact_published](https://tinyzkp.com/releases#gate-guard-artifact-published) | `release` | `blocked` | 0 | Publish the signed Guard artifact, checksum, provenance, and channel metadata. |
| [guard_release_ready](https://tinyzkp.com/releases#gate-guard-release-ready) | `release` | `blocked` | 0 | Publish the reviewed Guard release manifest and its bound source identity. |
| [hosted_infrastructure_decommissioned](https://tinyzkp.com/releases#gate-hosted-infrastructure-decommissioned) | `operations` | `blocked` | 0 | Decommission retained hosted infrastructure only after the obligation inventory is complete. |
| [legacy_obligations_resolved](https://tinyzkp.com/releases#gate-legacy-obligations-resolved) | `operations` | `blocked` | 0 | Resolve and record every retained customer, billing, data, and service obligation. |
| [legal_terms_approved](https://tinyzkp.com/releases#gate-legal-terms-approved) | `legal` | `blocked` | 0 | Record LN Holdings owner approval of the exact seller facts and digest-bound legal documents. |
| [merchant_live_owner_smoke_passed](https://tinyzkp.com/releases#gate-merchant-live-owner-smoke-passed) | `commerce` | `blocked` | 0 | Complete and record the owner-controlled Lemon Squeezy production smoke test. |
| [merchant_sandbox_lifecycle_passed](https://tinyzkp.com/releases#gate-merchant-sandbox-lifecycle-passed) | `commerce` | `blocked` | 0 | Complete and record the Lemon Squeezy sandbox purchase, renewal, cancellation, and access lifecycle. |
| [release_rehearsal_within_budget](https://tinyzkp.com/releases#gate-release-rehearsal-within-budget) | `operations` | `blocked` | 0 | Complete and bind the technical build, deploy, canary, artifact-identity, rollback, and recovery rehearsal. |
