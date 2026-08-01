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

`worker.js` runs on Cloudflare's edge (off the box, off the laptop) every 2 minutes,
retries once to filter blips, and POSTs to the authenticated TinyZKP email relay
on a confirmed failure. A KV incident record suppresses duplicate mail for an
unchanged failure, sends at most one reminder every six hours, and emits one
recovery message when the surface becomes healthy. You already use Cloudflare
for the site, so there is no new vendor or SMTP server.

```bash
cd deploy/uptime-probe
wrangler secret put ALERT_WEBHOOK_URL
wrangler secret put ALERT_WEBHOOK_TOKEN
wrangler deploy
```

For production, use the owner-dispatched
`.github/workflows/deploy-uptime-probe.yml` from the exact current `main`
commit. Its protected `tinyzkp-monitoring-production` environment requires:

- secret `CLOUDFLARE_MONITORING_API_TOKEN`, separate from the Pages token and
  limited to account-level **Workers Scripts: Edit** for deploying this Worker;
  it does not receive Pages Write, DNS Write, or account-administration scope;
- variable `CLOUDFLARE_ACCOUNT_ID`, reusing the existing non-secret account ID;
- variables `TINYZKP_UPTIME_PROBE_URL` and `TINYZKP_UPTIME_PROBE_HOST`. The URL
  must equal exactly `https://<host>/` with no userinfo, port, query, or fragment;
  the host must be the assigned `*.workers.dev` hostname or
  `uptime.tinyzkp.com`;
- preconfigured Worker secrets `ALERT_WEBHOOK_URL` and
  `ALERT_WEBHOOK_TOKEN`.

The workflow is main-only, owner-dispatched, commit-bound, tests before deploy,
and requires the deployed probe to resolve the same canonical mode published by
the site. Do not reuse the account-scoped Pages Write token: that credential is
deliberately unable to deploy Workers.

This monitoring environment and its least-privilege token are owner setup
inputs. Until they are configured and this workflow succeeds, external
off-device launch monitoring remains an explicit production blocker.

The tracked Worker resolves `AUDIT_MODE=canonical` from the exact published
release-channel contract on every run. The active Guard contracts are:

- `guard_prelaunch`: Guard marketing and evaluation are public, checkout and
  release artifacts remain blocked, and the legacy hosts still return their
  expected `200` recovery responses.
- `guard_withdrawn`: the Guard SKU is permanently withdrawn from new sale,
  checkout remains closed, any previously published fulfillment is preserved,
  and the legacy API, webhook, and MCP hosts must return static `410/noindex`
  retirement responses.
- `guard_transition`: every legacy API, MCP, and webhook probe must return
  `410` with `X-Robots-Tag: noindex`; owner-qualified commerce is configured
  as `live_hidden`, but checkout remains closed and the only release blocker
  is publication of the already-built Guard artifact.
- `guard_live`: the legacy hosts remain `410/noindex`, the published launch
  and commerce contracts are owner-qualified, Guard `0.1.0` is available,
  checkout is live, monthly and annual hosted checkout links are distinct,
  and the generic unsigned store billing portal is configured. The probe
  validates links and metadata without creating a purchase.
- `guard_frozen`: the legacy hosts remain `410/noindex`, every checkout URL is
  removed, and the exact generic billing portal plus already licensed Guard
  artifacts, signed release index, and anonymous OCI digests remain reachable.
  Use this only for the owner-signed emergency sales freeze; it is not a
  rollback to the hosted service.

Rollback-only contracts are:

- `containment`: the earlier backend-recovery site and service contract.
- `public_beta`: the retired hosted-beta activation contract, retained only for
  rollback compatibility.

Any other mode fails the entire probe instead of silently selecting a contract.
The production Worker must bind `ALERT_STATE` to its dedicated KV namespace;
without the binding, probing still works but duplicate suppression deliberately
fails open so a persistence outage cannot hide an incident.

Verify it works by hitting the deployed worker URL in a browser — it runs the probe on demand and returns JSON (`200` if everything is up, `503` if a target is down). To force a page, point a target at a known-bad URL temporarily, or stop the API container and watch the webhook fire within ~2 min.

Notes:
- Alerts use the authenticated relay in `deploy/cloudflare/alert-relay`, which sends only to the account-verified `logan@galenhealth.org` destination through Cloudflare Email Service. It does not revive the retired MailChannels path.
- Adjust the cadence in `wrangler.toml` (`crons`). `*/2 * * * *` = every 2 minutes (UTC).
- After merging this launch change in the canonical checkout, rerun
  `deploy/macos/install_api_audit_launchagent.sh`, then verify
  `launchctl print gui/$(id -u)/com.tinyzkp.api-audit` names the copied
  `guard_health_audit.py` runtime and reports a successful run. The Mac audit
  is defense in depth; the Worker remains the off-device production monitor.
- The Worker probes the same surfaces as Option A, including content markers
  that catch fallback pages, stale schema deploys, and accidental re-enablement.
  Switch `guard_prelaunch` → `guard_transition` → `guard_live` only as an
  explicit activation transaction. `guard_live` → `guard_frozen` is the
  owner-signed emergency stop that preserves customer fulfillment. Revert to
  `guard_prelaunch` only if the pre-GA transition deployment is rolled back.
  A committed SKU withdrawal selects `guard_withdrawn` independently of launch
  evidence; do not override it with a concrete Worker variable.

---

## Relationship to the on-box stack

This probe **complements** Prometheus/Alertmanager — it does not replace them. Keep the on-box stack for in-app signals (high failure rate, slow proves, unbilled-usage backlog), which it does well. The external probe exists solely to catch **total host failure**, which on-box alerting structurally cannot.
