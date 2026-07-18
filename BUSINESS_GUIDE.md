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
| Guard monthly | $499/month | Local Guard supervisor and qualified releases |
| Guard annual | $4,990/year | Same product; default purchase option |

One subscription covers one legal organization's internal users and runners.
There are no credits, meters, top-ups, machine activation counts, trials,
discount programs, enterprise tiers, SLAs, or bundled engineering hours.
Redistribution, resale, and service-bureau use are prohibited by the commercial
license.

Activated releases remain usable offline indefinitely. An active subscription
is required only to activate a later release.

## Founding validation

The pre-launch validation cohort is permanently capped at three organizations
and disappears at general availability.

Each organization:

1. Runs the free doctor and shares only a scrubbed compatibility result.
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

- GitHub Releases, crates.io, GHCR, and the public CI action.
- Reproducible benchmark and compatibility pages.
- Documentation for Plonky3 OOM, SSD-backed proving, and resumable proof jobs.
- One-time founding-partner outreach before launch.

There is no newsletter, blog schedule, lifecycle campaign, cold-outbound
program, paid-ad program, generic agent SEO, or custom CRM.

## Support and maintenance limits

- Best-effort asynchronous support only; no response-time commitment.
- Issues must include the release ID, compatibility result, verifier result,
  and scrubbed diagnostics. Never accept witness or license-key material.
- Ordinary issues are batched. Security disclosures use the private security
  channel.
- One scheduled release day per quarter; additional releases only for material
  security or correctness defects.
- Ordinary business operations must remain below two hours per month.
- Support must average no more than fifteen minutes per customer per month.

If a prospect requires custom AIR work, an SLA, SSO, a security questionnaire,
a DPA for proof data, a private branch, or hosted operations, decline the sale.

## Metrics and stop rules

Review only:

- qualified doctor users;
- checkout conversion;
- paid organizations and ARR;
- churn and refunds;
- compatibility failures;
- support minutes.

Do not build a custom analytics service or CRM.

Stop commercial investment if fewer than three organizations pay after twenty
technically qualified doctor users. Freeze new sales if integration exceeds
four hours per customer or support/operations exceed their limits for two
consecutive quarters.

The intended steady state is approximately ten annual customers and $50,000
ARR, not an enterprise software company.

## Launch authority

`release/guard-launch-gates-v1.json` is the machine source of truth. Public
checkout remains disabled until technical evidence, external workloads,
unaided installs, legal approval, merchant lifecycle tests, first customers,
legacy-obligation resolution, and hosted-infrastructure retirement are all
reviewed and recorded.
