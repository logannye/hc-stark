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

### What actually watches the live product

Every contract above describes *retired* surfaces and *published JSON*. The
only thing a customer can currently use is the estimator served by
`site/_worker.js`, which is also the instrument the 90-day demand clock
(`release/demand-clock-v1.json`) is read from — and for a long time nothing
watched it at all. Three targets close that, in every post-retirement mode
(`guard_withdrawn`, `guard_transition`, `guard_live`, `guard_frozen`):

| target | cadence | what it proves |
| --- | --- | --- |
| `estimator-route-mounted` | every tick (2 min) | `GET /v1/estimate` returns `405` with `Allow: POST`, so the route is mounted and still the estimator — not an asset-handler `404`, not a dropped `_worker.js`, not a method guard that quietly disappeared |
| `keys-route-mounted` | every tick (2 min) | the same for `GET /v1/keys` |
| `estimator-answers` | once per UTC hour | `POST /v1/estimate` with a fixed 2^20-row goldilocks manifest returns a real answer: `provable_today: true`, no blocking reasons, and a bounded peak that both beats the conventional peak and fits the declared 2 GiB budget |

`estimator-answers` deliberately does **not** assert exact byte figures. The
estimator is a deterministic cost model, so pinning
`bounded.peak_resident_bytes` would catch a silent regression — and would page
the owner just as hard for an *intended* model revision. Exact numbers already
have an owner with the right failure cost:
`scripts/ci/estimate_wasm_cli_parity_gate.mjs` fails the **build**, before the
deploy. A pager must not duplicate a build gate.

**Why the POST is hourly, and what it costs.** A successful estimate consumes
one slot of the anonymous 30/hour rate-limit window and appends one shape-only
row to `demand_log`. At the `*/2` cron cadence that is exactly 30 requests per
hour — the ceiling, with zero headroom — so the single retry that exists to
filter a blip would itself `429` and turn every blip into a page; it would also
inject ~21,600 synthetic rows into the 90-day demand window. Hourly bounds both
(≤24 rows/day, 28 slots of headroom) and still catches a dead cost model within
the hour, which is the right resolution for an artifact that only changes on
deploy. The two free `405` checks keep the two-minute watch.

Those probe rows are identifiable: the fixture is deterministic, so every probe
row carries
`request_digest = 7b47655339a060af69c77888e7333f90f9995b43b723ac1c40c1b84df9d21ad9`.
The kill/continue verdict is unaffected by them — it counts distinct **keyed**
organizations only, and the probe never mints a key, precisely so it can never
manufacture the number the decision turns on.

They are also load-bearing in one direction. `scripts/ci/demand_report.py`
treats a window with **zero** `demand_log` rows as an unmet precondition,
because a dead write path and a dead market produce byte-identical input. An
hourly writer that is known to be alive is exactly what disambiguates them:
with this probe running, zero rows can only mean the write path is broken, and
non-zero rows with no keyed organizations is a real reading of silence. So if
probe rows are ever excluded from the reported figures, they must **not** be
excluded from that zero-row liveness precondition — doing so would restore the
ambiguity the precondition exists to remove.

**Known blind spot.** Every D1 write in `site/_worker.js` fails open and silent
by design, so a dead write path still returns a perfectly healthy estimate. This
probe proves the answer is real; it cannot prove the row was recorded, because
it has no D1 binding to read back. The `demand_report.py` precondition above is
where that half is caught, one report at a time rather than one page.

Any other mode fails the entire probe instead of silently selecting a contract.
The production Worker must bind `ALERT_STATE` to its dedicated KV namespace;
without the binding, probing still works but duplicate suppression deliberately
fails open so a persistence outage cannot hide an incident.

Verify it works by hitting the deployed worker URL in a browser — it runs the probe on demand and returns JSON (`200` if everything is up, `503` if a target is down). An on-demand run deliberately ignores the hourly cadence and runs **every** target, including `estimator-answers`: a manual verification that silently skipped the only product check would be worse than no verification. To force a page, point a target at a known-bad URL temporarily, or stop the API container and watch the webhook fire within ~2 min.

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
