# TinyZKP Guard Revenue Readiness Ledger

Generated from the canonical Community/Guard launch contracts dated `2026-07-18`.

This is a fail-closed readiness ledger. It is not a customer, payment, or booked-revenue ledger.

## Current Business State

- Launch: `blocked`
- Sales: `closed`
- Checkout enabled: `false`
- Merchant of record: `lemon_squeezy` (`approval_pending`)
- Legal: `blocked_pending_owner_and_counsel`
- Hosted proving: `false`
- Usage metering: `false`
- Revenue evidence claimed: `false`
- Recorded revenue: `$0`

## Guard Offer

- Availability: `blocked_until_all_launch_gates_pass`
- Monthly: `$499`
- Annual: `$4,990` (recommended)

## Gate Summary

- Total gates: 12
- Blocking gates: 12
- Passed gates: 0

## Guard Launch Gate Queue

| Gate | Category | Status | Evidence | Next action |
|---|---|---|---:|---|
| [engine_release_ready](https://tinyzkp.com/releases#gate-engine-release-ready) | `release` | `blocked` | 0 | Publish digest-bound engine release evidence from the reviewed release commit. |
| [five_unaided_installs](https://tinyzkp.com/releases#gate-five-unaided-installs) | `qualification` | `blocked` | 0 | Record five clean-machine unaided install results without maintainer intervention. |
| [guard_artifact_published](https://tinyzkp.com/releases#gate-guard-artifact-published) | `release` | `blocked` | 0 | Publish the signed Guard artifact, checksum, provenance, and channel metadata. |
| [guard_release_ready](https://tinyzkp.com/releases#gate-guard-release-ready) | `release` | `blocked` | 0 | Publish the reviewed Guard release manifest and its bound source identity. |
| [hosted_infrastructure_decommissioned](https://tinyzkp.com/releases#gate-hosted-infrastructure-decommissioned) | `operations` | `blocked` | 0 | Decommission retained hosted infrastructure only after the obligation inventory is complete. |
| [legacy_obligations_resolved](https://tinyzkp.com/releases#gate-legacy-obligations-resolved) | `operations` | `blocked` | 0 | Resolve and record every retained customer, billing, data, and service obligation. |
| [legal_terms_approved](https://tinyzkp.com/releases#gate-legal-terms-approved) | `legal` | `blocked` | 0 | Approve the commercial terms and publish the binding legal version. |
| [merchant_live_owner_smoke_passed](https://tinyzkp.com/releases#gate-merchant-live-owner-smoke-passed) | `commerce` | `blocked` | 0 | Complete and record the owner-controlled Lemon Squeezy production smoke test. |
| [merchant_sandbox_lifecycle_passed](https://tinyzkp.com/releases#gate-merchant-sandbox-lifecycle-passed) | `commerce` | `blocked` | 0 | Complete and record the Lemon Squeezy sandbox purchase, renewal, cancellation, and access lifecycle. |
| [release_rehearsal_within_budget](https://tinyzkp.com/releases#gate-release-rehearsal-within-budget) | `operations` | `blocked` | 0 | Complete a release rehearsal and bind its measured support and maintenance budget evidence. |
| [three_external_workloads](https://tinyzkp.com/releases#gate-three-external-workloads) | `qualification` | `blocked` | 0 | Record three independent external workload qualification results in launch evidence. |
| [two_standard_annual_customers](https://tinyzkp.com/releases#gate-two-standard-annual-customers) | `qualification` | `blocked` | 0 | Record two standard annual-customer qualification outcomes without changing the public offer. |
