# TinyZKP Guard business guide

Status: approved passive-revenue operating policy.

## Product and buyer

TinyZKP Guard is a customer-operated overflow and recovery supervisor for the
exact supported Plonky3 profile. The buyer is a proof-infrastructure lead,
protocol engineer, or technical founder with an observed memory, hardware-cost,
or interrupted-job problem. CI runners and schedulers are the machine users.

TinyZKP does not sell generic cryptography consulting, hosted proving, agent
receipts, or a claim that it is the only implementation of a technique.

## Catalog

| Product | Price | Included |
|---|---:|---|
| Community | $0 | MIT engine, verifier, schemas, reference workloads, doctor, and published evidence |
| Guard monthly | $499/month | Local Guard supervisor and activation of releases that pass a qualification window |
| Guard annual | $4,990/year | Same product; default purchase option |

One subscription covers one legal organization's internal users and runners.
There are no credits, meters, top-ups, machine activation counts, trials,
coupons, discounts, add-ons, subscription-pause promises, enterprise tiers,
SLAs, or bundled engineering hours.
Redistribution, resale, and service-bureau use are prohibited by the commercial
license.

Activated releases remain usable offline indefinitely. An active subscription
is required only to activate a later release.

Superseded and withdrawn release-index states control ordinary distribution,
recommendation, and support. An already-downloaded activated copy makes no
channel request, cannot learn either state, and remains locally usable; this is
not a technical resume-only restriction. Guard v1 has no release-specific
activation denylist, so a customer who retained an unactivated copy may still
activate that exact release while the merchant reports an active subscription.

The $499/$4,990 prices are frozen through general availability plus six months;
no GA date is declared yet. Annual is the default and founding customers use
the same undiscounted annual variant. Any later price change uses new merchant
variant IDs and grandfathers existing subscribers. Existing variant IDs remain
intact and are never deleted or repurposed.

## Founding validation

The pre-launch validation cohort is permanently capped at three organizations
and disappears at general availability.

Each organization:

1. Runs the signed exact-contract free doctor locally and records only the
   `DoctorReportV1` digest and standardized compatibility result.
2. Supplies at most one workload through the standard public adapter.
3. Accepts the published $4,990 annual price before TinyZKP accepts the
   validation.
4. Receives no customer-specific branch, custom AIR work, witness handling, or
   architecture consulting.
5. May consume no more than four hours of TinyZKP assistance.

Launch requires three external workloads from at least two organizations and
two ordinary annual purchases through the self-service checkout. If the shared
adapter cannot support the workloads without source changes, the subscription
does not launch.

## Customer lifecycle

1. An evergreen compatibility or benchmark page reaches a buyer with an active
   problem.
2. The buyer runs the free local doctor.
3. Compatible buyers purchase through the merchant-of-record.
4. Checkout sends the receipt and license key without TinyZKP intervention.
5. The customer verifies, activates, and runs the signed local artifact.
6. The merchant handles renewal, dunning, invoices, payment changes, and
   cancellation.
7. Documentation, GitHub issues, and one managed mailbox handle product defects
   on the published profile.

No customer workload, witness, scratch artifact, or proof enters TinyZKP
infrastructure.

## Demand without an operating treadmill

Distribution is limited to evergreen, high-intent surfaces:

- GitHub Releases, GHCR, and the public CI action.
- Reproducible benchmark and compatibility pages.
- Documentation for Plonky3 OOM, SSD-backed proving, and resumable proof jobs.
- Exactly one moderator-approved Plonky3 community announcement, only after the
  signed exact-contract doctor evaluation release exists.
- At most one awesome-plonky3 ecosystem-list submission, only after production
  qualification.

There is no newsletter, blog schedule, lifecycle campaign, cold-outbound
program, direct-message campaign, recurring announcement, paid-ad program,
generic agent SEO, or custom CRM.

## Support and maintenance limits

- Best-effort asynchronous support only; no response-time commitment.
- Issues may include only release identity, a synthetic reproduction, and a
  manually inspected `SupportReportV1`. Do not share `DoctorReportV1`. Never
  accept witness, proof, checkpoint, private path, or license-key material.
- Ordinary issues are batched. Security disclosures use the private security
  channel.
- Four qualification windows are scheduled each year. A window may publish no
  binary; release only when a warranted change passes its applicable gates.
- Qualification is capped at eight owner hours and $3,000 external spend per
  window, with a $6,000 cash reserve.
- Ordinary business operations must remain below two hours per month.
- Support target is at most six minutes per customer per month. Seven through
  twelve minutes is warning state; two consecutive months above twelve freezes
  sales. Any month above two owner hours freezes sales.

If a prospect requires custom AIR work, an SLA, SSO, a security questionnaire,
a DPA for proof data, a private branch, or hosted operations, decline the sale.

## Metrics and stop rules

Review only:

- distinct qualified organizations (one cumulative count per organization;
  repeat reports and bots do not count);
- checkout conversion;
- paid organizations and ARR;
- churn and refunds;
- compatibility failures;
- support minutes.

Do not build a custom analytics service or CRM.

The market clock remains `not_started` until the signed exact-contract doctor
artifact and the single moderator-approved Plonky3 announcement are both
evidenced. `2026-10-16` remains the initial decision date. The six-month stop
deadline is derived from the actual announcement timestamp.

At the six-month deadline, stop commercial work if fewer than twenty qualified
organizations have run the doctor, or if at least twenty qualify and fewer than
three organizations pay. At month twelve, stop if ARR is below six
annual-equivalent customers. Target at least 70% annual subscribers; treat a
shortfall as a warning. Early monthly cancellation above 30% freezes
feature/compatibility expansion, not sales. Evaluate the 75% renewal target
only after at least five renewal outcomes.

Immediately freeze sales for verifier/correctness, signature, provenance,
offline-runtime, checkpoint-recovery, release-identity, legal, merchant
semantic, customer-proof-data, or high/critical security failure. The local
scorecard can recommend `continue`, `freeze_sales`, or `stop_commercial`; it
cannot mutate checkout without separately signed reviewed evidence.

The intended steady state is approximately ten annual customers and $50,000
ARR, with at least 75% renewal, not an enterprise software company.

## Compatibility expansion

The initial v1 founding gate does not require broader-profile demand. A new
compatibility profile is considered only after five technically qualified
organizations request the same profile and three provide conditional standard
annual commitments. The complete profile-specific technical gate must then be
repeated.

## Launch authority

`release/guard-launch-state-v2.json` is the generated machine source of truth.
Its source is `GuardLaunchEvidenceV2`, and passing evidence additionally
requires an independently protected trust-policy digest. Public
checkout remains disabled until technical evidence, external workloads,
unaided installs, legal approval, merchant lifecycle tests, first customers,
legacy-obligation resolution, and hosted-infrastructure retirement are all
reviewed and recorded.

Candidate preparation is a separate, narrower authorization. It is permitted
only after the engine, legal, merchant-sandbox, and rehearsal gates pass and
canonical Guard signing trust is configured. Signed candidate bytes remain
marked `signed_candidate`, `candidate_build_authorized`, and
`commercial_release_authorized: false`; later promotion publishes those exact
bytes and records evidence without rebuilding or resigning them.
