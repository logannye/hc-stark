# TinyZKP Guard Revenue Readiness Pipeline

This pipeline is a canonical gate view with a date-only schedule overlay. It is not a sales forecast, customer ledger, payment ledger, or booked-revenue report.

## Summary

- Total records: 12
- Blocking records: 12
- Passed records: 0
- Sales open: `false`
- Checkout enabled: `false`
- Revenue evidence claimed: `false`
- Recorded revenue: `$0`

## Gate Records

| Gate | Category | Status | Evidence | Next action date | Next action |
|---|---|---|---:|---|---|
| [engine_release_ready](https://tinyzkp.com/releases#gate-engine-release-ready) | `release` | `blocked` | 0 |  | Publish digest-bound engine release evidence from the reviewed release commit. |
| [five_unaided_installs](https://tinyzkp.com/releases#gate-five-unaided-installs) | `qualification` | `blocked` | 0 |  | Record five clean-machine unaided install results without maintainer intervention. |
| [guard_artifact_published](https://tinyzkp.com/releases#gate-guard-artifact-published) | `release` | `blocked` | 0 |  | Publish the signed Guard artifact, checksum, provenance, and channel metadata. |
| [guard_release_ready](https://tinyzkp.com/releases#gate-guard-release-ready) | `release` | `blocked` | 0 |  | Publish the reviewed Guard release manifest and its bound source identity. |
| [hosted_infrastructure_decommissioned](https://tinyzkp.com/releases#gate-hosted-infrastructure-decommissioned) | `operations` | `blocked` | 0 |  | Decommission retained hosted infrastructure only after the obligation inventory is complete. |
| [legacy_obligations_resolved](https://tinyzkp.com/releases#gate-legacy-obligations-resolved) | `operations` | `blocked` | 0 |  | Resolve and record every retained customer, billing, data, and service obligation. |
| [legal_terms_approved](https://tinyzkp.com/releases#gate-legal-terms-approved) | `legal` | `blocked` | 0 |  | Approve the commercial terms and publish the binding legal version. |
| [merchant_live_owner_smoke_passed](https://tinyzkp.com/releases#gate-merchant-live-owner-smoke-passed) | `commerce` | `blocked` | 0 |  | Complete and record the owner-controlled Lemon Squeezy production smoke test. |
| [merchant_sandbox_lifecycle_passed](https://tinyzkp.com/releases#gate-merchant-sandbox-lifecycle-passed) | `commerce` | `blocked` | 0 |  | Complete and record the Lemon Squeezy sandbox purchase, renewal, cancellation, and access lifecycle. |
| [release_rehearsal_within_budget](https://tinyzkp.com/releases#gate-release-rehearsal-within-budget) | `operations` | `blocked` | 0 |  | Complete a release rehearsal and bind its measured support and maintenance budget evidence. |
| [three_external_workloads](https://tinyzkp.com/releases#gate-three-external-workloads) | `qualification` | `blocked` | 0 |  | Record three independent external workload qualification results in launch evidence. |
| [two_standard_annual_customers](https://tinyzkp.com/releases#gate-two-standard-annual-customers) | `qualification` | `blocked` | 0 |  | Record two standard annual-customer qualification outcomes without changing the public offer. |
