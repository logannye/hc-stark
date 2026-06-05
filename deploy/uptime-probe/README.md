# External uptime probe (audit OPS-2 / OPS-3)

**Problem this fixes.** Today the only liveness watchdog is `scripts/monitoring/api_health_audit.sh`, which runs **daily on Logan's personal Mac** — if the laptop is asleep, prod can be down for hours unnoticed. Worse, Prometheus + Alertmanager run **as containers on the Hetzner box they monitor**, so a total host/disk/network failure (exactly the OPS-1 catastrophe) takes the alerting down *with* it. You would learn prod is down from a customer email, not from a page.

The fix is one **external** probe that lives off the box and off the laptop. Pick **one** of the two options below. Either satisfies OPS-2/OPS-3; UptimeRobot is faster to stand up, the Worker keeps everything in this repo.

---

## Option A — UptimeRobot / Better Stack (recommended, zero code)

Third-party, externally hosted, free tier, pages by SMS/email/Slack. ~5 minutes:

1. Create two **HTTP(s)** monitors:
   - `https://api.tinyzkp.com/healthz` — expect HTTP **200**, keyword/string check optional.
   - `https://mcp.tinyzkp.com/` — "host reachable" check (any HTTP response is fine; only a connection failure/timeout is "down").
2. Interval **1–5 min**; alert after **2 consecutive failures** (filters transient blips).
3. Add an **SMS or Slack** alert contact (not email-only — you want to be woken up).
4. Optional: add `https://tinyzkp.com/` (the Cloudflare Pages marketing site) as a third monitor.

That's it — nothing to deploy.

---

## Option B — Cloudflare Worker cron (in-repo, no third party)

`worker.js` runs on Cloudflare's edge (off the box, off the laptop) every 2 minutes, retries once to filter blips, and POSTs to a webhook on a confirmed failure. You already use Cloudflare for the site, so there's no new vendor.

```bash
cd deploy/uptime-probe
npx wrangler secret put ALERT_WEBHOOK_URL   # paste a Slack/Discord/JSON webhook URL
npx wrangler deploy
```

Verify it works by hitting the deployed worker URL in a browser — it runs the probe on demand and returns JSON (`200` if everything is up, `503` if a target is down). To force a page, point a target at a known-bad URL temporarily, or stop the API container and watch the webhook fire within ~2 min.

Notes:
- Alerts go to a **webhook** (Slack/Discord/generic), deliberately not email — the prior MailChannels email path broke (PR #9).
- Adjust the cadence in `wrangler.toml` (`crons`). `*/2 * * * *` = every 2 minutes (UTC).
- The Worker probes the same two surfaces as Option A; extend `TARGETS` in `worker.js` to add more.

---

## Relationship to the on-box stack

This probe **complements** Prometheus/Alertmanager — it does not replace them. Keep the on-box stack for in-app signals (high failure rate, slow proves, unbilled-usage backlog), which it does well. The external probe exists solely to catch **total host failure**, which on-box alerting structurally cannot.
