# TinyZKP Guard Revenue Readiness

TinyZKP's current low-maintenance business is the Community/Guard software
model: Community is MIT-licensed and free; Guard is a commercial object-code
subscription offered at $499 monthly or $4,990 annually. Hosted proving, usage
metering, bespoke services, and outbound-led acquisition are outside the active
offer.

Sales and checkout are fail-closed. The current commerce provider is Lemon
Squeezy, but checkout must remain disabled until every canonical Guard launch
gate passes and the reviewed commerce configuration is bound into launch
evidence.

## Canonical sources

Only these files drive the active revenue-readiness ledgers:

- `site/pricing.json`
- `site/commerce.json`
- `site/release.json`
- `release/guard-launch-state-v2.json`

The active execution ledger contains one row per canonical Guard launch gate.
The pipeline ledger mirrors those rows and adds only an optional
`next_action_at` date. Neither ledger is a customer, payment, forecast, or
booked-revenue system.

## Deterministic checks

Generate the ledgers only after changing a canonical source:

```bash
python3 scripts/marketing/render_gtm_execution_ledger.py
python3 scripts/marketing/render_gtm_pipeline_ledger.py --sync-state
```

Production preflight and CI should run all four checks:

```bash
python3 scripts/marketing/render_gtm_execution_ledger.py --check
python3 scripts/ci/gtm_execution_ledger_check.py
python3 scripts/marketing/render_gtm_pipeline_ledger.py --check
python3 scripts/ci/gtm_pipeline_ledger_check.py
```

These checks reject stale generated files, noncanonical gate status, revenue
claims, forecast values, acquisition CTAs, and references to retired hosted or
distribution paths.

## Active files

| File | Purpose |
|---|---|
| `generated/gtm_execution_ledger.json` | Machine-readable Guard offer, commerce state, and gate queue |
| `generated/gtm_execution_ledger.csv` | Compact one-row-per-gate operations view |
| `generated/gtm_execution_ledger.md` | Human-readable fail-closed revenue-readiness report |
| `gtm_pipeline_state.json` | Date-only schedule overlay; it cannot store free-form data, override canonical status, or record revenue |
| `generated/gtm_pipeline_ledger.*` | Current gate queue plus the date-only schedule overlay |

## Historical material

> **Archived recovery-era material — do not execute, publish, submit, or use
> for outreach.** The legacy files describe retired hosted-service,
> distribution, checkout, and outbound systems. TinyZKP permits no email
> outreach. `commercial/no-email-evaluation-runbook.md` is itself a historical
> recovery artifact and has no authority over the current Guard offer. Use
> `release/guard-launch-state-v2.json` for current qualification state.

- `GTM_DISTRIBUTION_PLAN.md` is historical/retired implementation evidence.
  Claims inside it are snapshots of the former model and are not current
  operating instructions.
- `gtm_pipeline_state.v1-retired.json` preserves the former no-PII pipeline
  state for audit history. It is not read by active renderers or checks.
- `scripts/marketing/sync_stripe_checkout_pipeline.py` preserves the former
  Stripe aggregation implementation for audit history, but its executable
  entry point fails before parsing arguments, reading files, contacting an
  account, or writing state.
- Other acquisition drafts and distribution artifacts in this directory are
  retained as historical evidence only. They must not be submitted or used to
  repopulate the active Guard ledgers.
