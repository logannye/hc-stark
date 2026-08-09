# TinyZKP production operations

Status: active operator runbook. This describes the system that is actually
deployed. Every path, name, identifier, and command below was read out of this
repository — the file it came from is cited inline so a reader can re-derive it
rather than trust it.

Read this before any other runbook in this directory. Most of the others
describe the hosted stack (`hc-server`, Docker Compose, Prometheus, the Hetzner
box, Lemon Squeezy checkout) that was deleted; they now carry a retirement
banner and must not be executed. The ops envelope for the live system is under
two hours a month, and the single largest way to blow through it is to follow a
runbook for a machine that no longer exists.

---

## 1. What is actually running

Four things. There is no server, no container, no queue, no message broker, no
cron job on a host, and no payment processor. Revenue is zero by design.

### 1.1 The static site and its worker

Cloudflare Pages project `tinyzkp`, production branch `main`, in **Advanced
Mode**: `site/_worker.js` is the entire request path for every hostname the
project serves. It calls no upstream service. In route order (see the default
`fetch` export at the bottom of `site/_worker.js`):

| Match | Behavior |
|---|---|
| `api.tinyzkp.com`, `mcp.tinyzkp.com`, `webhook.tinyzkp.com` | static `410 Gone` + `X-Robots-Tag: noindex`, no `ASSETS` call, no upstream |
| canonical redirects | apex/`www`/trailing-slash normalization |
| `POST /v1/estimate` | shape-only resource estimate, computed by the compiled Rust cost model imported as WASM |
| `POST /v1/keys` | mints one free opaque bearer key that raises the caller's estimate rate limit |
| everything else | static assets via `env.ASSETS`, with `.html` extension fallback |

`/v1/estimate` numbers come solely from `estimate_json` in the vendored WASM.
`scripts/ci/estimate_wasm_cli_parity_gate.mjs` fails the build if that WASM and
the native `hc-cli estimate` ever compute different numbers for the same input,
so the endpoint cannot silently drift away from the engine.

Rate limits, both fixed one-hour windows: **30/hour** anonymous, keyed on a
salted HMAC of `CF-Connecting-IP` (never the raw address), and **300/hour** for
a caller presenting `Authorization: Bearer <key>`. Both constants live in
`site/_worker.js` (`ANON_RATE_LIMIT_PER_HOUR`, `KEYED_RATE_LIMIT_PER_HOUR`) and
`scripts/ci/test_worker_estimate.mjs` reads them back out of the committed
source text, so the test and the worker cannot drift apart.

### 1.2 The D1 database

One database, `tinyzkp-estimator`, id `ea4ad71c-6175-4a69-b106-02cc4af378ae`,
bound as `DB` in `site/wrangler.toml`. Schema lives in repo-root `migrations/`
(`migrations_dir = "../migrations"` — deliberately outside the deployed
static-asset tree):

| Table | Migration | Holds |
|---|---|---|
| `rate_limit_windows` | `0000` | anonymous per-salted-IP-hash counters |
| `demand_log` | `0001` | one shape-only row per successful estimate |
| `estimator_keys`, `keyed_rate_limit_windows` | `0002` | SHA-256 of each minted key + per-`key_id` counters |
| `rejected_log` | `0003` | rejected-request counts, reported separately from demand |

Apply migrations from the `site/` directory, where `wrangler.toml` is:

```bash
cd site
wrangler d1 migrations apply DB --remote
```

What is deliberately **not** stored: raw IP addresses, raw request bodies, AIRs,
witnesses, paths, and email addresses. `POST /v1/keys` takes an email only to
check it is shaped like an address before minting, then discards it — there is
no email column in any migration, and no account, confirmation, or key-recovery
flow that would need one.

### 1.3 The uptime probe

Cloudflare Worker `tinyzkp-uptime-probe`, config
`deploy/uptime-probe/wrangler.toml`, code `deploy/uptime-probe/worker.js`.

- **Cron `*/2 * * * *`** (UTC). A confirmed failure pages within ~2 minutes.
  It runs on Cloudflare's edge, off the laptop, which is the entire point: an
  alerting path that shares a failure domain with the thing it monitors is
  decoration.
- **`AUDIT_MODE = "canonical"`** — on every run the probe fetches
  `https://tinyzkp.com/release-channels-v1.json` and probes the target set for
  whatever `current_channel` says. Today that resolves to **`guard_withdrawn`**,
  which asserts the site root is `200`, `commerce.json`/`release.json`/
  `discovery.json` satisfy their withdrawn contracts, and all six retired
  legacy endpoints return `410` + `noindex`. A stale deployment therefore fails
  closed instead of confidently probing the wrong launch posture.
- **Alerting**: it retries once to filter blips, then POSTs to the authenticated
  email relay named by the Worker secrets `ALERT_WEBHOOK_URL` and
  `ALERT_WEBHOOK_TOKEN`.
- **Dedupe**: KV namespace `ALERT_STATE`
  (`204107410bc540aa97647c5289b18f89`) holds one incident record per failure
  fingerprint. An unchanged incident re-pages at most once every
  `ALERT_REMINDER_SECONDS = 21600` (6 hours) instead of every 2 minutes, and one
  recovery message is sent when the surface becomes healthy again.

`GET /` on the probe runs the same checks synchronously and returns the JSON
summary: `200` with `"ok": true` when everything passes, `503` otherwise. That
is the fastest manual answer to "is production up?".

### 1.4 The demand clock

`release/demand-clock-v1.json` records `demand_clock_started_at: 2026-07-29` —
the date the estimator became *discoverable*, not the date it shipped. The
trailing 90-day window closes around **2026-10-27**.
`scripts/ci/demand_report.py` computes the kill/continue verdict from the
`demand_log` table. Section 6 runs it.

---

## 2. Is it up? (the 60-second check)

```bash
# 1. The probe's own verdict. 200 + ok:true means every canonical-channel
#    target passed on this run.
curl -sS https://uptime.tinyzkp.com/ | jq '{ok, mode, failures: [.results[] | select(.ok == false) | .name]}'

# 2. The estimator itself. The probe does NOT cover these two endpoints
#    (see TROUBLESHOOTING rule 5), so check them by hand.
curl -sS -X POST https://tinyzkp.com/v1/estimate \
  -H 'Content-Type: application/json' \
  --data @- <<'JSON' | jq '.schema_version'
{"schema_version":1,"field":"babybear","extension_degree":4,
 "logical_rows":4194304,"trace_width":180,"max_constraint_degree":3,
 "public_values":8,"has_next_row_columns":true,
 "features":{"uses_lookups":true,"uses_buses":false,"uses_permutations":false,
   "uses_multi_table":true,"uses_preprocessed_columns":false,
   "uses_periodic_columns":false,"uses_recursion":false,"uses_gpu":false},
 "ram_budget_bytes":2147483648}
JSON
```

That request body is the `SP1_SHAPED_REQUEST` fixture from
`scripts/ci/test_worker_estimate.mjs`; keeping the smoke test and the unit test
on the same input means a manual check that passes here is a check CI also
covers.

Substitute the actual probe hostname if it is the assigned `*.workers.dev` name
rather than `uptime.tinyzkp.com` — the deploy workflow accepts either, and the
authoritative value is the `TINYZKP_UPTIME_PROBE_URL` variable on the
`tinyzkp-monitoring-production` environment.

A `503` from `/v1/keys` with `keys_unavailable` means D1 is unreachable at
runtime. Note the asymmetry, because it decides how urgently you respond:
`/v1/keys` fails closed (it cannot mint a key it cannot persist), while
`/v1/estimate` fails **open** — a missing or broken `env.DB` still returns a
correct estimate, silently logging nothing and limiting nothing. A healthy
`/v1/estimate` is therefore not evidence that D1 is healthy.

---

## 3. Deploying the site

Merging to `main` is the deploy. `.github/workflows/deploy-site.yml` runs on
`push` to `main` for the tracked paths (`site/**`, `docs/**`, `release/**`,
`scripts/ci/**`, `scripts/deploy/**`, and others listed in the workflow), plus
`workflow_dispatch`.

Two jobs matter:

1. **`static-contracts`** — runs on both PRs and pushes. Launch/market/scorecard
   gates, route and deploy checks, the pytest suite, `node --check
   site/_worker.js`, the worker dispatch/estimate/parity tests, and
   `npm --prefix deploy/uptime-probe test`. This is the job whose red is a real
   red on a PR.
2. **`production`** — `if: github.event_name != 'pull_request' && github.ref ==
   'refs/heads/main' && vars.TINYZKP_SITE_AUTODEPLOY == 'enabled'`. It
   materializes the pinned Node 24.18.0 / Wrangler 4.85.0 toolchain, runs the
   protected production preflight, then plans and applies the deployment through
   `scripts/deploy/cloudflare_pages_release.py` and finishes with the static
   canary.

If nothing deployed after a merge, check
`vars.TINYZKP_SITE_AUTODEPLOY` **first**. When it is not `enabled` the
production job is skipped, the workflow is green, and the site is unchanged —
a green run is not evidence of a deploy.

For an out-of-band deploy from a reviewed SHA, or to inspect the plan before
applying, use the wrapper directly — the exact plan/apply/canary command
sequence, the operator directory layout, and the failure semantics are in
[`cloudflare_pages_release.md`](cloudflare_pages_release.md). Do not use `npx`,
a global Wrangler, or the Cloudflare dashboard.

### Rolling back

Rollback is mostly automatic and you should let it be:

- If Wrangler fails, times out, or may have published, the wrapper calls the
  Pages rollback API for **only** the prior deployment captured in the reviewed
  plan and writes `deployment.json.failure.json`.
- If the post-deploy canary fails, it rolls back to the deployment record's
  exact prior deployment and verifies the restored canonical state.

Manual rollback takes no operator-supplied target — it reads
`prior_production_deployment` out of the deployment record. The two-step
plan-then-apply commands are in
[`cloudflare_pages_release.md`](cloudflare_pages_release.md) §4.

`automatic rollback FAILED` or `failed_rollback_failed` means production state
is **unverified**. Stop, preserve the failure record, and do not announce or
continue the release.

---

## 4. Deploying the uptime probe

Owner-dispatched only, from the exact current `main`:

```bash
gh workflow run deploy-uptime-probe.yml \
  --ref main \
  -f expected_main_sha="$(git rev-parse origin/main)"
```

The workflow (`.github/workflows/deploy-uptime-probe.yml`) refuses to run unless
the ref is `main`, the actor and triggering actor are both the repository owner,
`GITHUB_SHA` equals both `expected_main_sha` and `origin/main`, and the tree is
clean. It then runs `node --check`, the probe's own test suite, and asserts
`AUDIT_MODE = "canonical"` is still in the config before deploying with the
`CLOUDFLARE_MONITORING_API_TOKEN` secret from the protected
`tinyzkp-monitoring-production` environment. After deploying it fetches the
probe URL and requires `ok == true` with a `mode` equal to the site's published
`current_channel`.

That environment needs, as owner setup:

- secret `CLOUDFLARE_MONITORING_API_TOKEN` — account-level **Workers Scripts:
  Edit** only. The Pages token deliberately cannot deploy Workers; do not
  substitute it.
- variable `CLOUDFLARE_ACCOUNT_ID`.
- variables `TINYZKP_UPTIME_PROBE_URL` and `TINYZKP_UPTIME_PROBE_HOST`, where
  the URL is exactly `https://<host>/` with no userinfo, port, path, query, or
  fragment.

The Worker secrets `ALERT_WEBHOOK_URL` and `ALERT_WEBHOOK_TOKEN` are **not** set
by the workflow. Set them once, out of band, from `deploy/uptime-probe/`:

```bash
wrangler secret put ALERT_WEBHOOK_URL
wrangler secret put ALERT_WEBHOOK_TOKEN
```

---

## 5. Retention

`RETENTION_DAYS = 180` in `site/_worker.js`. That is exactly twice
`demand_report.py`'s 90-day analysis window: the window is never truncated, and
the tables do not accumulate indefinitely.

Pruning piggybacks on ordinary writes — it runs inside the `/v1/estimate` path,
gated on a module-scope `lastPrunedHour` so it fires at most once per isolate
per hour — **because Pages has no scheduled trigger**. There is no cron to check
and no job to restart. Consequences an operator needs to hold:

- With no traffic, nothing prunes. That is not an incident; nothing is growing
  either.
- A failed prune is swallowed and retried on the next isolate/hour. Retention
  must never affect a response, so it never surfaces as an error to a caller.
- `estimator_keys` is **deliberately excluded** from pruning. Deleting a row
  there would silently revoke a caller's key with no notice and no recovery
  path — the table has no email to notify anyone at. It is also tiny.

`scripts/ci/privacy_disclosure_gate.py` fails if the published privacy notice
and the code disagree about whether retention is enforced at all, so changing
`RETENTION_DAYS` without updating the notice reds the build.

---

## 6. Reading the demand log and running the decision

The whole hosted-estimator phase exists to produce this one report. Run it at
least monthly, and once at the close of the window.

```bash
cd site
# 1. Export the remote D1 database. This emits SQL text, not a SQLite file.
wrangler d1 export tinyzkp-estimator --remote --output ../demand.sql

cd ..
# 2. Load it, because demand_report.py opens a SQLite file read-only
#    (connect_readonly, `--db` = "Path to a SQLite file with the demand_log
#    schema").
rm -f demand.sqlite && sqlite3 demand.sqlite < demand.sql

# 3. The verdict.
python3 scripts/ci/demand_report.py --db demand.sqlite | jq '.verdict, .preconditions'
```

No script in this repo wraps steps 1 and 2 — they are two commands, and
inventing a wrapper for a monthly read would cost more than it saves. The flags
are for the pinned Wrangler 4.85.0; if `d1 export` rejects them, check
`wrangler d1 export --help` rather than reaching for the dashboard.

Delete `demand.sql` and `demand.sqlite` when finished. They are shape-only —
no IPs, emails, bodies, or keys — but there is no reason to keep a copy of the
production database on a laptop.

The verdict is one of three values, and it is stated outright so that a reader
cannot interpret bare numbers favourably:

- **`CONTINUE`** — 15 or more distinct **keyed** organizations in the trailing
  90 days.
- **`KILL_THRESHOLD_MET`** — fewer than 15. Anonymous traffic never counts
  toward this threshold, by design: `anon_ip_hash` both over- and under-counts
  real callers, and summing it into the figure would flatter it in exactly the
  direction that defeats the point of measuring.
- **`MEASUREMENT_INVALID`** — a discoverability precondition is unmet (the
  estimate page missing from `site/sitemap.xml`, absent from `site/llms.txt`,
  or serving `noindex`). A zero reading under those conditions is a NON-RESULT.
  Fix the named precondition and restart the clock reasoning; do not retire the
  product on an artifact of its own marketing.

Blocking-reason codes are ranked by **distinct callers** per code, never raw row
count, so one caller retrying an unsupported config fifty times cannot outvote
fifteen callers who each tried once. That ranking is the answer to "which
profile should we build next".

---

## TROUBLESHOOTING

These are rules, not tips. Each one is here because it already cost time.

**1. A `database_id` that does not resolve makes Wrangler reject the deploy
outright.** It is not a runtime binding failure you discover later — Wrangler
refuses to publish at all. A placeholder UUID in `site/wrangler.toml` killed the
production deploy on 2026-07-27 (auto-rolled back, no outage). The worker's
runtime fail-open behavior when `env.DB` is missing does not cover this: it
never gets to run.

**2. Never "fix" a D1 problem by deleting the `d1_databases` block.** The deploy
would go green and the endpoint would keep serving correct estimates —
`/v1/estimate` fails open — while logging nothing and rate-limiting nothing.
The demand measurement, which is the only reason this phase exists, would be
silently destroyed, and the loss would be invisible until the 90-day report came
back empty and unexplainable. Fix the id; never remove the binding.

**3. The `production` job shows "skipping" on pull requests.** Its condition
starts `github.event_name != 'pull_request'`. The deploy path is therefore only
exercised **after merge** — a fully green PR has proven the contracts, not the
deployment. Watch the post-merge run.

**4. Deploying the uptime probe does not clear its Worker secrets.**
`ALERT_WEBHOOK_URL` and `ALERT_WEBHOOK_TOKEN` persist across `wrangler deploy`
and across the deploy workflow, which never sets them. Do not re-enter them
after every deploy, and do not conclude from a silent probe that the secrets
were wiped — check the KV dedupe window (rule 5's neighbor: an unchanged
incident is silent for 6 hours by design).

**5. The probe does not cover `/v1/estimate` or `/v1/keys`.** Its
`guard_withdrawn` target set is the six retired legacy endpoints plus the site
root, `commerce.json`, `release.json`, and `discovery.json`. The estimator
endpoints — the only part of production a user actually calls — are outside it.
A green probe means the site and the retirement posture are correct; it says
nothing about the estimator. Until that gap is closed, section 2's manual curl
is the only coverage those endpoints have.

**6. A green CI run is not a deploy, and a green probe is not a working
product.** Both are necessary; neither is sufficient. When asking "did the
change reach production?", the answer is the Pages deployment record, not the
workflow's colour.
