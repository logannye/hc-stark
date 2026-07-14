# External uptime probe (audit OPS-2 / OPS-3)

**Problem this fixes.** Today the only liveness watchdog is `scripts/monitoring/api_health_audit.sh`, which runs **daily on Logan's personal Mac** — if the laptop is asleep, prod can be down for hours unnoticed. Worse, Prometheus + Alertmanager run **as containers on the Hetzner box they monitor**, so a total host/disk/network failure (exactly the OPS-1 catastrophe) takes the alerting down *with* it. You would learn prod is down from a customer email, not from a page.

The fix is one **external** probe that lives off the box and off the laptop. Pick **one** of the two options below. Either satisfies OPS-2/OPS-3; UptimeRobot is faster to stand up, the Worker keeps everything in this repo.

---

## Option A — UptimeRobot / Better Stack (recommended, zero code)

Third-party, externally hosted, free tier, pages by SMS/email/Slack. ~5 minutes:

1. Create these **HTTP(s)** monitors while the service is in backend recovery:
   - API `/healthz` and `/readyz`, webhook `/health`, site `/`, and site `/status` — expect HTTP **200**.
   - `https://tinyzkp.com/discovery.json` — expect `service_status` to be `backend_recovery`.
   - API `/templates` and site `/api/create-checkout` — expect HTTP **503** and `protocol_upgrade`; an HTTP 200 is a containment failure.
   - MCP `/mcp` initialization — expect HTTP **200** and `protocolVersion`.
2. Interval **1–5 min**; alert after **2 consecutive failures** (filters transient blips).
3. Add an **SMS or Slack** alert contact (not email-only — you want to be woken up).
4. Optional: add `https://tinyzkp.com/` (the Cloudflare Pages marketing site) as a homepage monitor.

At public-beta activation, replace the recovery expectations with API and site
`service_status=public_beta`, dashboard and beta-pricing availability, and
continued failure of retired legacy proving routes.

That's it — nothing to deploy.

---

## Option B — Cloudflare Worker cron (in-repo, no third party)

`worker.js` runs on Cloudflare's edge (off the box, off the laptop) every 2 minutes, retries once to filter blips, and POSTs to the authenticated TinyZKP email relay on a confirmed failure. You already use Cloudflare for the site, so there is no new vendor or SMTP server.

```bash
cd deploy/uptime-probe
wrangler secret put ALERT_WEBHOOK_URL
wrangler secret put ALERT_WEBHOOK_TOKEN
wrangler deploy
```

The tracked Worker defaults to `AUDIT_MODE=containment`. Activation deploys it
with `--var AUDIT_MODE:public_beta`; rollback restores `containment`. Any other
mode fails the entire probe instead of silently selecting a contract.

Verify it works by hitting the deployed worker URL in a browser — it runs the probe on demand and returns JSON (`200` if everything is up, `503` if a target is down). To force a page, point a target at a known-bad URL temporarily, or stop the API container and watch the webhook fire within ~2 min.

Notes:
- Alerts use the authenticated relay in `deploy/cloudflare/alert-relay`, which sends only to the account-verified `logan@galenhealth.org` destination through Cloudflare Email Service. It does not revive the retired MailChannels path.
- Adjust the cadence in `wrangler.toml` (`crons`). `*/2 * * * *` = every 2 minutes (UTC).
- The Worker probes the same surfaces as Option A, including content markers
  that catch fallback pages, stale schema deploys, and accidental re-enablement.
  Switch the target contract only as an explicit activation transaction.

---

## Relationship to the on-box stack

This probe **complements** Prometheus/Alertmanager — it does not replace them. Keep the on-box stack for in-app signals (high failure rate, slow proves, unbilled-usage backlog), which it does well. The external probe exists solely to catch **total host failure**, which on-box alerting structurally cannot.
