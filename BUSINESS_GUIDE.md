# TinyZKP business operating guide

TinyZKP is an infrastructure company for proving teams with a reproducible RAM
bottleneck. It is not a general receipt SaaS, an AI-agent product, a public
pay-as-you-go prover, or a new proof protocol.

## Positioning

**Promise:** prove larger Plonky3 STARK traces within a RAM budget, using
deterministic SSD scratch and recoverable jobs while preserving the official
proof format and verifier.

**Buyer:** proving lead, protocol engineering lead, zkVM/rollup CTO,
proof-network infrastructure owner, or ZK coprocessor team.

**Qualification:** a supported, reproducible workload that verifies under the
pinned Plonky3 verifier and either OOMs today or has at least a 1.5× gap between
current peak memory and the target ceiling.

**Primary call to action:** benchmark your workload. The evaluation application
must collect the stack, workload, rows, current RSS/OOM evidence, target RAM,
scratch availability, verifier, sensitivity, technical owner, budget owner,
and timeline. Never accept witness data or credentials through the website.

## Offers

[`site/pricing.json`](site/pricing.json) is the current machine-readable source.
No seller may change price, scope, or support obligations in a proposal without
updating that source and its parity gates.

| Offer | Commercial terms | Delivery boundary |
|---|---|---|
| Founding Evaluation | $25K; first two customers; 50% signature / 50% delivery | One workload, three weeks, maximum fifteen engineering days |
| Standard Evaluation | $40K; 50% signature / 50% delivery | Same fixed scope; changes require written order |
| TinyZKP Certified | $60K/year prepaid | One workload, signed LTS, notices, automated quarterly report, ≤10 support hours/quarter |
| TinyZKP Fleet/OEM | $125K/year minimum prepaid | Private deployment, policy, observability, checkpoint operations, release coordination, SLA |
| Custom engineering | $300/hour minimum effective rate | Separately scoped; must improve the backend, adapter, or repeatable deployment product |
| Reserved capacity | Future $15K/month minimum | Unavailable until review, demand, and ≥80% measured gross margin |

Evaluation milestones use Stripe Invoicing. Recurring contracts use annual
Stripe Billing subscriptions with `send_invoice`. Public Checkout and customer
initiated plan switching remain disabled. Existing customer records must be
preserved; pausing or cancelling a legacy subscription requires documented
notification and a prorated refund or credit decision.

## Funnel and automation

1. A team runs the open-source benchmark or submits reproducible OOM evidence.
2. The application receives an automatic acknowledgement and benchmark command.
3. A deterministic qualification check confirms verifier success, supported
   workload, reproducibility, and memory gap.
4. A founder runs one technical review call.
5. A fixed-scope evaluation is invoiced 50% upfront.
6. The delivery report contains raw measurement data and a production
   recommendation.
7. A successful workload converts to Certified or Fleet/OEM.

Do not automate unsolicited outbound. Until three recurring customers exist,
send at most twenty researched founder messages per month. Traffic, directory
listings, free accounts, and unsent leads carry zero pipeline value.

Low-touch delivery comes from strict boundaries:

- one workload and one acceptance matrix per evaluation;
- standard manifests, bundles, reports, policies, and runbooks;
- signed LTS trains instead of customer-specific branches;
- automated quarterly benchmark reports;
- ten included support hours per customer per quarter;
- change orders for extra workloads or bespoke engineering;
- no private control-plane repository before the first annual agreement.

## Revenue and financial controls

The month-12 target is two $125K Fleet/OEM contracts plus one $60K Certified
contract: approximately $310K ARR. Evaluation revenue funds external review and
integration work but is not ARR.

Monthly reporting must include:

- contracted ARR and cash collected;
- evaluation deposits and delivery liabilities;
- COGS by workload and support hours by customer;
- reproducible bottlenecks, qualified applications, evaluations sold, and
  evaluation-to-annual conversion;
- gross margin, customer concentration, churn risk, and runway;
- release adoption and unresolved security/reliability risk.

Start each month from
[`commercial/monthly-scorecard.example.json`](commercial/monthly-scorecard.example.json)
and run `python3 scripts/commercial/validate_scorecard.py <scorecard>`. The
validator gives unsigned opportunities zero contracted value, rejects vanity
metrics, reconciles customer ARR, enforces the support cap, and fails closed on
the 90% software / 80% hosted margin floors.

Targets: at least 90% software gross margin, at least 80% for any future hosted
capacity, annual prepayment, no more than ten included support hours per quarter,
and no full-time hire until signed recurring revenue covers the role.

## Release and claim control

No production or paid proving relaunch occurs until every entry in
[`release/backend-v1-gates.json`](release/backend-v1-gates.json) is passed with
evidence and the file status is `ready`. The tag-publishing workflow enforces
this mechanically.

Every published benchmark must link hardware, source revision, dependency
profile, workload digest, exact command, raw baseline/candidate reports, and
verification result. Never call TinyZKP faster when the measured advantage is
capacity or recoverability. Never market component memory as full-pipeline
memory.

The website, API, MCP, CLI, compatibility manifest, and benchmark report must
expose the same release identity. During recovery, live canaries must prove that
hosted proving and checkout are unavailable and status says backend recovery.

## Weekly operating review

Review only evidence-bearing metrics:

- completed buyer calls;
- reproducible memory bottlenecks;
- reports submitted and qualification outcome;
- evaluations contracted, deposits collected, and delivery status;
- conversions to Certified/Fleet, contracted ARR, and concentration;
- support hours, COGS, gross margin, and cash runway;
- release-gate progress, review findings, and customer adoption.

Publish no more than one substantive benchmark, integration report, or RFC per
month. Open an upstream Plonky3 RFC only after the local 1M-row prototype has
honest measurements; propose block-readable matrices and caller-supplied
storage without making TinyZKP's release depend on upstream acceptance.

## Deferred work

Hosted pay-as-you-go, standalone v9, privacy claims, recursion, GPU, zkML, zkVM,
KZG, IPA, rollup integrations, warm fleets, Postgres scheduling, and horizontal
scale remain inactive unless a signed customer funds them and they have their
own security and unit-economics plan.
