# TinyZKP reconciliation deploy runbook - 2026-06-23

This runbook ships the public reconciliation work as one coordinated release:

- Website pages and navigation: `/research`, `/security`, docs lifecycle copy.
- API discovery schema: `/templates` includes `lifecycle`.
- MCP discovery schema: template tools include `lifecycle`.
- Repo positioning: `hc-stark` is production, `space-efficient-zero-knowledge-proofs`
  is research lineage.

Do not deploy the website by itself for this release. The new public pages say
template discovery exposes lifecycle labels, so the API and MCP binaries must be
deployed before or alongside the website.

## Release invariant

A successful release has these externally visible properties:

1. `https://tinyzkp.com/research` serves the new research lineage page, not a
   fallback or homepage.
2. `https://tinyzkp.com/security` serves the new security/audit status page.
3. `https://tinyzkp.com/docs#template-lifecycle` documents `live`,
   `audit_gated`, and `preview`.
4. `https://api.tinyzkp.com/templates` returns the production template catalog
   with a `lifecycle` field on each template.
5. Default production discovery still exposes only `accumulator_step`.
6. MCP template discovery returns lifecycle labels that match the API.
7. The older KZG/BN254 repository points readers forward to `hc-stark` and
   TinyZKP.com without implying it powers the hosted service.

## Pre-deploy checks

Run from a clean checkout of the branch to be merged:

```bash
cargo fmt --all --check
git diff --check
cargo test -p hc-workloads
cargo test -p hc-mcp
cargo test -p hc-server honest_catalog
cargo test -p hc-sdk v7_range
./scripts/run_soundness_suite.sh
./scripts/ci/reconciliation_invariants.sh
python3 scripts/ci/launch_gate_audit.py
python3 -m pytest scripts/ci/test_launch_gate_audit.py
python3 scripts/ci/production_launch_preflight.py
python3 -m pytest scripts/ci/test_production_launch_preflight.py
python3 -m pytest scripts/ci/test_release_identity_check.py
python3 scripts/ci/server_card_check.py
python3 -m pytest scripts/ci/test_server_card_check.py
python3 scripts/ci/backup_restore_check.py
python3 -m pytest scripts/ci/test_backup_restore_check.py
python3 -m pytest billing/tests/test_backup_script.py
python3 -m pytest scripts/ci/test_deploy_readiness_check.py
python3 -m pytest scripts/ci/test_site_deploy_check.py
python3 scripts/ci/site_route_check.py
python3 -m pytest scripts/ci/test_site_route_check.py
python3 scripts/ci/site_deploy_check.py
node scripts/ci/site_worker_dispatch_test.mjs
python3 scripts/ci/compose_config_check.py
python3 -m pytest scripts/ci/test_compose_config_check.py
python3 -m pytest billing/tests/test_site_pricing_parity.py
python3 -m pytest billing/tests/test_provision_free.py
python3 -m pytest billing/tests/test_session_endpoints.py
python3 -m pytest billing/tests/test_sessions.py
python3 -m pytest billing/tests/test_tenant_store.py
python3 -m pytest billing/tests/test_usage_pg_tools.py
python3 -m pytest billing/tests/test_tenant_pg_tools.py
python3 -m pytest billing/tests/test_contact_intake.py
xmllint --noout site/sitemap.xml
find site/functions/api -name '*.js' -print0 | xargs -0 -n1 node --check
bash -n scripts/monitoring/api_health_audit.sh scripts/monitoring/shared_dispatch_smoke.sh billing/backup.sh deploy/hetzner/install_billing_runtime.sh
```

On the production host, `deploy/hetzner/deploy.sh` runs
`deploy/hetzner/install_billing_runtime.sh`, then the readiness check before
rebuilding services:

```bash
python3 scripts/ci/deploy_readiness_check.py \
  --production \
  --check-host-python \
  --host-python /opt/hc-stark/.venv/bin/python
```

Both gates must pass before any state-backend cutover deploy.

Confirm the public release notes and operating policy are part of the same
diff:

```bash
rg 'Reconciliation and positioning|Template lifecycle metadata|Release surfaces' CHANGELOG.md docs/governance/release_policy.md
```

Run the legacy repo smoke test from its checkout:

```bash
bash scripts/test_sszkp.sh
```

If both repos are checked out side by side, run the comprehensive local launch
gate audit from the product repo before merge:

```bash
python3 scripts/ci/launch_gate_audit.py --require-legacy
python3 scripts/ci/production_launch_preflight.py --require-legacy
```

Before merge, confirm the diff contains no generated proof artifacts:

```bash
git status --short
if git ls-files | rg -q '(^|/)proof\.bin$'; then
  echo "proof.bin is still tracked" >&2
  exit 1
fi
```

## Merge order

1. Merge the `hc-stark` reconciliation branch to `main`.
2. Merge the legacy repo positioning branch to that repo's default branch.
3. Wait for GitHub to show the expected commits on both default branches.
4. Deploy the Hetzner services from `main`.
5. Deploy Cloudflare Pages from the same `main` revision.

The old repo can merge before or after the product repo, but the public website
should not deploy until the product repo's API/MCP changes are on production.
Record the product commit SHA; post-deploy canaries use it to reject API/MCP/site
version skew.

## Hetzner deploy

SSH to the production host and use the blessed deploy script:

```bash
ssh root@46.225.78.136
cd /opt/hc-stark
deploy/hetzner/deploy.sh
```

The script fetches `origin/main`, rebuilds the Docker Compose services, syncs
Caddy if needed, refreshes the host billing virtualenv from
`billing/requirements.txt`, syncs the host billing cron/systemd definitions,
restarts the host `hc-billing-webhook` systemd unit, and checks local API and
webhook health. If `.env` sets
`HC_SERVER_PROVE_DISPATCH=shared`, it also enables the `shared-workers` Compose
profile and runs `hc-job-worker --check-config` before restarting the
containerized services.

If this step fails, stop. Do not deploy Cloudflare Pages.

## Cloudflare Pages deploy

Deploy the static site and advanced-mode worker from a clean `main` checkout.
Before running `wrangler`, validate the static config from the repo root and,
for production, validate a local file containing the expected Pages bindings:

```bash
python3 scripts/ci/site_deploy_check.py
python3 scripts/ci/site_deploy_check.py --production --bindings-file /secure/tinyzkp-pages.env
python3 scripts/ci/production_launch_preflight.py \
  --production \
  --env-file /opt/hc-stark/.env \
  --pages-bindings-file /secure/tinyzkp-pages.env \
  --check-host-python \
  --host-python /opt/hc-stark/.venv/bin/python
cd site
npx wrangler pages deploy . --project-name tinyzkp --branch main
```

The production binding file must contain the same names set in Cloudflare Pages
secrets/variables: `INTERNAL_SECRET`, `STRIPE_SECRET_KEY`,
`STRIPE_PRICE_ID_METERED` or `STRIPE_PRICE_ID`,
`STRIPE_PRICE_ID_TRACE_STEP_METERED`, `STRIPE_PRICE_ID_DEVELOPER`,
`STRIPE_PRICE_ID_PRO`, `STRIPE_PRICE_ID_SCALE`, and `TINYZKP_DEMO_API_KEY`.

Use `--commit-dirty=true` only for an emergency operator patch that has a
separate rollback note. The normal reconciliation deploy should be traceable to
the merged `main` commit.

Set `TINYZKP_RELEASE_SHA` and `TINYZKP_RELEASE_REF` in Cloudflare Pages when
running a manual deploy path that does not expose `CF_PAGES_COMMIT_SHA` at
runtime.

## Post-deploy canaries

Run these from a local machine after both deploys finish:

```bash
curl -fsS https://api.tinyzkp.com/healthz >/dev/null
curl -fsS https://api.tinyzkp.com/templates | jq .
curl -fsS https://tinyzkp.com/research | rg 'One company, one thesis: space-efficient proving\.'
curl -fsS https://tinyzkp.com/security | rg 'Responsible disclosure'
curl -fsS https://tinyzkp.com/docs | rg 'Template Lifecycle'
./scripts/ci/reconciliation_invariants.sh --live
TINYZKP_EXPECT_RELEASE_SHA="$(git rev-parse HEAD)" python3 scripts/ci/production_launch_preflight.py --live
python3 scripts/ci/production_launch_preflight.py --live
TINYZKP_SMOKE_API_KEY=tzk_... ./scripts/monitoring/shared_dispatch_smoke.sh
TINYZKP_SMOKE_API_KEY=tzk_... python3 scripts/ci/production_launch_preflight.py --live --authenticated-smoke
bash scripts/monitoring/api_health_audit.sh
```

`shared_dispatch_smoke.sh` is required for this reconciliation release even if
production still uses local prove dispatch, because it proves the public
template lifecycle contract and the authenticated prove/poll/inspect/verify
flow from the same operator machine that will run later shared-worker cutovers.

For the first reconciliation release, run the audit once with the MCP lifecycle
canary enabled as well:

```bash
TINYZKP_AUDIT_MCP_E2E=1 bash scripts/monitoring/api_health_audit.sh
```

That exercises the hosted Streamable HTTP MCP flow:
`initialize -> notifications/initialized -> tools/list -> list_templates ->
prove_template -> poll_job -> get_proof -> verify_proof`. Leave it disabled for
routine high-frequency checks unless you intentionally want the MCP anonymous
lane to consume prove capacity.

The `/templates` response must include a `lifecycle` field. A minimal healthy
production response looks like:

```json
{
  "templates": [
    {
      "id": "accumulator_step",
      "lifecycle": "live"
    }
  ]
}
```

The real response contains additional metadata. The canary is the presence and
value of `lifecycle`, plus the absence of unaudited templates from default
public discovery.

## Fallback-page detection

Status 200 alone is not enough for Cloudflare Pages. Extensionless routes can
serve a fallback page while still returning 200. The production audit now checks
content markers for:

- `/research`: `One company, one thesis: space-efficient proving.`
- `/security`: `Responsible disclosure`
- `/docs`: `Template Lifecycle`

If any marker fails, treat the site deploy as failed even when the status code
is 200.

## Rollback

If the API deploy succeeds but the Cloudflare Pages deploy fails:

1. Leave the API in place if `/templates` remains backward compatible.
2. Redeploy the previous known-good Pages deployment from the Cloudflare
   dashboard or CLI.
3. Re-run the full audit.

If the Hetzner deploy fails before Cloudflare Pages deploy:

1. Do not deploy the website.
2. Use the deploy script logs to identify whether the failure is Docker, Caddy,
   billing webhook, or health checks.
3. Roll back to the previous `main` commit on the host only if the service is
   degraded and the failure cannot be fixed forward quickly.
4. Re-run local host checks and the public audit after recovery.

## Communications

After the release passes canaries, update the public status or launch note with
one concise message:

> TinyZKP has unified its public product story. `hc-stark` is the production
> STARK receipt system behind TinyZKP.com, while
> `space-efficient-zero-knowledge-proofs` remains public research lineage for
> the earlier KZG/BN254 approach.

Avoid saying the older repo was "replaced" or "deprecated" without context. The
strong positioning is lineage: the older repo shows the origin of the
space-efficiency thesis; the current repo is where customers build.
