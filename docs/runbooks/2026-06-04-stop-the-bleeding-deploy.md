# Stop-the-bleeding deploy checklist (2026-06-04)

Closes the P0/P1 audit findings whose fixes were already written but stranded in
open PRs, plus three net-new fixes. Everything below is **green locally**; the
only remaining steps are the outward-facing ones (push / merge / deploy), which
are the operator's call.

**Box:** `ssh root@46.225.78.136` (Hetzner CPX42), repo at `/opt/hc-stark`,
branch tracks `origin/main`. Prod runs
`docker compose -f docker-compose.yml -f deploy/hetzner/docker-compose.prod.yml`
plus the **host systemd** unit `hc-billing-webhook` (NOT a compose service).

## What ships

| PR | What it closes | State | Action before merge |
|----|----------------|-------|---------------------|
| **#22** | **OPS-1/BILL-09 (P0):** off-box backup of tenant_store/usage/api_keys; CORS lock; no demo cred; `.env` ignored | MERGEABLE | none — merge as-is |
| **#26** | OPS-2 (daily audit cried wolf), OPS-4 (safe deploy script), **+ new** OPS-2/3 external uptime probe | MERGEABLE | push the new `deploy/uptime-probe/` commit |
| **#21** (rebased) | BILL-02 free re-signup, BILL-03 trace_length under-bill, BILL-05 inflight TOCTOU, BILL-04 Compute metering pipeline; **+ net-new** BILL-01 webhook plan-accept, BILL-05 batch cap | rebased locally (5 commits + 2 net-new) | **force-push** (history rewritten) |
| **#27** | Phase 1B sound v7 general-AIR + gated range_proof | MERGEABLE | none — range stays `audited:false`, zero behavior change |

## 0. Push the local work (operator)

```bash
# rebased #21 (was CONFLICTING on GitHub; now clean on current main)
git push --force-with-lease origin phase0.3-abuse-billing
# #26 with the new uptime-probe commit
git push origin ops/post-phase0.2-audit-sync-and-deploy-script
```

Re-confirm all four show MERGEABLE: `for n in 21 22 26 27; do gh pr view $n --json mergeable -q .mergeable; done`.

## 1. Merge order

1. **#22** — off-box backup first (the existential fix).
2. **#26** — gives the safe 3-tier deploy script + stops the false audit failures + the uptime probe.
3. **#21** — billing-correctness + BILL-01/BILL-05 (force-push first).
4. **#27** — Phase 1B (any time; no live behavior change).

The four are largely disjoint; this order just front-loads durability.

## 2. One-time setup BEFORE/AROUND deploy

**Off-box backup (#22) — do this first, it's the P0:**
```bash
apt-get install -y rclone
rclone config                       # add a PRIVATE bucket: Backblaze B2 / Hetzner Storage Box / S3, SSE on, no anon read
# set in /opt/hc-stark/.env:
echo 'HC_BACKUP_REMOTE="<remote>:<bucket>"' >> /opt/hc-stark/.env
/opt/hc-stark/billing/backup.sh     # run once; confirm a snapshot is PUSHED off-box (not just /opt/hc-stark/backups)
# then prove a restore works:
#   follow docs/runbooks/restore.md into a throwaway dir; confirm sqlite + api_keys.txt come back
crontab -l | grep backup.sh         # confirm the daily cron is actually installed
```

**Compute billing (#21 → BILL-04) — required before advertising Compute self-serve:**
```bash
cd billing && ./setup_stripe_products.sh        # creates the trace_step_usage meter + per-step price
# wire the Cloudflare Pages secret:
npx wrangler pages secret put STRIPE_PRICE_ID_TRACE_STEP_METERED   # = the new trace-step price id
```

**Developer price (#21-adjacent → BILL-06):** confirm the Cloudflare secret
`STRIPE_PRICE_ID_DEVELOPER` points at the **$19** price, not the legacy $9 in
`.stripe_ids.json`. If $19 doesn't exist yet, create it
(`--unit-amount 1900`, annual `18240`) and update the secret + `.stripe_ids.json`.

**External uptime probe (#26 → OPS-2/3):** either
```bash
cd deploy/uptime-probe && npx wrangler secret put ALERT_WEBHOOK_URL && npx wrangler deploy
```
or stand up UptimeRobot/Better Stack monitors per `deploy/uptime-probe/README.md`
(api `/healthz`=200, mcp host-reachable, SMS/Slack alert, alert on 2 fails).

## 3. Deploy to the box

```bash
ssh root@46.225.78.136
cd /opt/hc-stark
git fetch origin && git checkout main && git pull --ff-only
deploy/hetzner/deploy.sh    # #26's blessed path: rebuilds all 3 tiers AND restarts hc-billing-webhook
```
> The 2026-05-30 outage was caused by deploying the container + CF site but
> forgetting `systemctl restart hc-billing-webhook` (host unit serving pre-0.2
> code). `deploy.sh` does this and runs a `/session/resolve` stale-code canary.

## 4. Post-deploy verification

- `curl -s https://api.tinyzkp.com/healthz` → 200 (and internal `:8080/healthz`).
- `curl -s https://api.tinyzkp.com/templates` → still ONLY `accumulator_step` (honest catalog intact; #27 does not change this — range stays `audited:false`).
- CORS now first-party: `curl -sI -H 'Origin: https://evil.example.com' https://api.tinyzkp.com/healthz | grep -i access-control-allow-origin` → NOT `*`.
- Free re-signup with an existing free email → **409** (BILL-02 live).
- Run `scripts/monitoring/api_health_audit.sh` → passes with **no false failures** (#26 live).
- The uptime probe pages on a forced failure (point a target at a bad URL or stop the API container briefly).
- Stripe **test** checkouts: a **Scale** checkout provisions a tenant stored as `scale` (BILL-01 — was `developer`); a **Compute** checkout provisions `compute` (needs the §2 meter + secret).

## Net-new fixes included (not in any original PR)

- **BILL-01** (`billing/provision_tenant.py`): `_normalize_plan()` maps `pro→scale`, `compute→compute` in both `_handle_checkout_completed` and `_plan_from_subscription`; +9 tests.
- **BILL-05** (`crates/hc-server/src/lib.rs`): `prove_batch` projects the whole batch against the monthly cap up front (`estimated_job_cost_cents` + `batch_would_exceed_cap`); +5 tests. *Follow-up:* an end-to-end batch-cap 402 integration test needs a usage-recording fixture that doesn't exist yet in `crates/hc-server/tests`.
- **OPS-2/3** (`deploy/uptime-probe/`): external Cloudflare Worker cron probe + UptimeRobot runbook.

## Still open after this (next tracks)

- **BILL-07** dunning (don't hard-suspend on first failed charge).
- **ZK-1/ZK-2** soundness-doc rewrite (wrong `2^-1320`/`2^-1920` bounds on main — audit-blocking).
- **WEB-1** "5,000 proofs/mo" contradiction + HTML↔pricing parity lint.
- **GTM-2** reframe/replace the accumulator "ran the code it claims" claim.
- **OPS-6** managed Postgres cutover (structural unlock).
