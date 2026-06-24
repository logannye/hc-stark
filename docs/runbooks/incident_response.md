# TinyZKP incident response runbook

Status: production operating runbook.

Use this when TinyZKP has a customer-visible outage, degraded proving path,
billing/account incident, security concern, or bad deployment. The goal is to
restore a safe service quickly, communicate plainly, and preserve enough
evidence for a useful follow-up.

## Severity levels

| Severity | Customer impact | Examples | First response target |
|---|---|---|---|
| SEV1 | Broad outage or data/billing/security risk | API cannot create/verify proofs, billing double-charge risk, verifier accepts bad proofs, leaked secret | Acknowledge within 15 minutes |
| SEV2 | Major feature degraded with workaround | MCP unavailable but HTTP API works, signup broken but existing keys work, proving p95 > target | Acknowledge within 30 minutes |
| SEV3 | Narrow or cosmetic issue | One docs route stale, non-critical dashboard issue, isolated customer support case | Respond within 1 business day |

Default to the higher severity when billing correctness, verifier correctness,
or customer trust is ambiguous.

## Incident categories

Use one primary category in status updates and postmortems:

- Website and signup
- API proving
- Verification
- MCP transport
- Billing and account
- Package / SDK / verifier release
- Security disclosure
- Infrastructure / deployment

## First 15 minutes

1. Name the incident: `YYYY-MM-DD short-title`.
2. Pick severity and category.
3. Open a scratch log with timestamps.
4. Check public canaries:

```bash
curl -fsS https://api.tinyzkp.com/healthz
curl -fsS https://api.tinyzkp.com/templates | jq .
curl -fsS https://tinyzkp.com/status | rg 'System Status'
curl -fsS https://mcp.tinyzkp.com/.well-known/mcp/server-card.json | jq .
./scripts/ci/reconciliation_invariants.sh --live
bash scripts/monitoring/api_health_audit.sh
```

5. Check service logs on the host:

```bash
ssh root@46.225.78.136
cd /opt/hc-stark
docker compose -f docker-compose.yml -f deploy/hetzner/docker-compose.prod.yml ps
docker compose -f docker-compose.yml -f deploy/hetzner/docker-compose.prod.yml logs --tail=200 hc-server
journalctl -u hc-billing-webhook -n 200 --no-pager
```

6. If billing correctness is uncertain, pause usage sync before retrying
   customer-facing operations:

```bash
systemctl stop hc-billing-usage-sync.timer 2>/dev/null || true
systemctl stop hc-billing-usage-sync.service 2>/dev/null || true
```

## Communication template

Use short, factual updates. Do not speculate about cryptographic safety or
billing impact before evidence supports it.

```text
Investigating: <category> is degraded starting <UTC time>. Impact: <what users see>. Current workaround: <if any>. Next update by <UTC time>.
```

```text
Identified: root cause is <brief cause>. We are applying <mitigation>. Impact remains <scope>. Next update by <UTC time>.
```

```text
Resolved: <category> recovered at <UTC time>. Impact window: <start>-<end>. Follow-up: <billing reconciliation / postmortem / no action>.
```

## Triage by category

### Website and signup

- Check Cloudflare Pages deployment status.
- Fetch exact routes, not only `/`:

```bash
for route in / /try /docs /signup /contact /account /status /research /security; do
  curl -fsS "https://tinyzkp.com$route" >/dev/null && echo "ok $route" || echo "bad $route"
done
```

- If Pages serves fallback content, redeploy from the last known-good commit.

### API proving

- Check `/healthz`, `/templates`, and one authenticated prove/verify flow.
- Watch Prometheus alerts:
  - `HcHighFailureRate`
  - `HcSlowProves`
  - `HcNoCompletions`
  - `HcUsageCapHits`
- If worker spawns saturate, lower anonymous/MCP capacity before raising global
  worker caps.

### Verification

- Treat verifier acceptance bugs as security incidents.
- Stop publishing affected verifier packages if package integrity or verifier
  correctness is uncertain.
- Preserve proof bytes and verifier version for every failing case.

### MCP transport

- Check the public server card and tool list.
- If anonymous abuse is contributing, set `HC_MCP_REQUIRE_AUTH=true` or lower
  `HC_MCP_MAX_INFLIGHT` while keeping authenticated HTTP API available.

### Billing and account

- Check Stripe dashboard events, `tenant_store.sqlite`, `usage.sqlite`, and
  `billing/sync_usage.py --report`.
- For Postgres migration windows, run:

```bash
python3 billing/usage_pg_tools.py compare --since-ms "$DUAL_WRITE_START_MS"
```

- Do not declare resolved until Stripe events, tenant state, and local usage
  rows are reconciled.

### Security disclosure

- Acknowledge receipt quickly and move details out of public channels.
- Capture affected versions, endpoints, proof formats, and reproduction steps.
- If proof soundness or verifier acceptance is implicated, freeze public
  claims until the issue is understood.

## Rollback

- Website rollback: redeploy previous Cloudflare Pages deployment.
- API rollback: use the Hetzner deploy logs to identify the previous good git
  revision, then redeploy that revision only if fixing forward is slower than
  user impact allows.
- Billing rollback: never simply restore a DB without reconciling Stripe events
  emitted during the incident window.
- Protocol/verifier rollback: requires a security note when bad proofs may have
  verified.

## Post-incident

Within 2 business days for SEV1/SEV2:

- Write a short postmortem with timeline, impact, root cause, mitigation, and
  follow-up owners.
- Add or tighten a synthetic monitor if the incident was not caught by existing
  probes.
- Update docs/runbooks if the operator had to improvise.
- Reconcile billing or customer credits before closing the incident.
