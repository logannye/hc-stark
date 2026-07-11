# Cloudflare Pages same-SHA release and rollback

Use `scripts/deploy/cloudflare_pages_release.py` for the production TinyZKP
Pages project. Do not invoke `npx`, a global Wrangler, a dashboard deploy, or a
raw rollback request. The wrapper hard-codes project `tinyzkp`, production
branch `main`, the reviewed Node 24.18.0/Wrangler 4.85.0 materialization, and
the documented Pages project/deployment/rollback API paths.

The default `deploy` and `rollback` modes are read-only plans. They make only
the Cloudflare reads needed to confirm the exact account, project, and current
canonical production deployment. They perform no Cloudflare write unless both
the write environment switch and the exact freshly recomputed plan hash are
present.

## Private operator directory

Create one current-owner directory and keep it mode `0700`. Every plan and
record is exclusively created as canonical JSON mode `0600`; existing files,
symlinks, group-readable files, and non-canonical records fail closed.

```bash
install -d -m 0700 /var/lib/tinyzkp-private/pages-releases
export CLOUDFLARE_ACCOUNT_ID=REPLACE_WITH_REVIEWED_32_HEX_ACCOUNT
export CLOUDFLARE_API_TOKEN=REPLACE_WITH_PAGES_SCOPED_TOKEN
```

Use a Pages-scoped API token, not a Global API key. The token is passed only to
the fixed Cloudflare API client and pinned Wrangler subprocess. It is never
written to a plan, command digest, deployment record, canary record, or
rollback record.

## 1. Preview the same-SHA deployment

The reviewed release must be the exact clean Git `HEAD`. The wrapper rejects
tracked, staged, and untracked changes below `site/`. It creates a deterministic
Git archive from the reviewed commit, rejects links and special files, and
binds the Git tree, archive, complete asset manifest, and pinned runtime
materialization into the preview hash.

```bash
SHA=REPLACE_WITH_REVIEWED_40_HEX_RELEASE
ACCOUNT="$CLOUDFLARE_ACCOUNT_ID"

python3 scripts/deploy/cloudflare_pages_release.py deploy \
  --release-sha "$SHA" \
  --expected-account-id "$ACCOUNT" \
  --plan-output /var/lib/tinyzkp-private/pages-releases/deploy-plan.json
```

Review the plan's exact prior canonical production deployment, source hashes,
runtime hashes, account/project identity, and `plan_sha256`. A new production
deployment must never be attempted from a plan whose prior deployment or
source identity has changed.

## 2. Apply the exact preview

Run apply with a new, unused deployment-record path. Apply recomputes the
complete plan under an owner-only operation lock before invoking only:

```text
/var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node
  /var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js
  pages deploy <sealed-commit-site> --project-name tinyzkp --branch main
  --commit-hash <reviewed-sha> --commit-dirty=false --config <sealed-wrangler.toml>
```

The actual command uses argv directly, not a shell. Wrangler receives a clean
environment containing only the fixed system path, private temporary home,
locale, telemetry opt-out, exact account ID, and API token.

```bash
export TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE=1

python3 scripts/deploy/cloudflare_pages_release.py deploy \
  --release-sha "$SHA" \
  --expected-account-id "$ACCOUNT" \
  --apply \
  --expected-plan-sha256 REPLACE_WITH_EXACT_DEPLOY_PLAN_SHA256 \
  --record-output /var/lib/tinyzkp-private/pages-releases/deployment.json

unset TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE
```

After Wrangler exits, the wrapper retrieves the project's canonical deployment
and the exact deployment object. It records only a new successful production
deployment whose commit is the reviewed SHA, branch is `main`, and
`commit_dirty` is false. The record includes the new deployment ID/URL, prior
production deployment ID, release SHA, source hashes, runtime hashes, command
digest, and deploy-plan hash. Its state remains `deployed_pending_canary`.

Wrangler invocation is the transaction boundary. If Wrangler returns an error,
times out, may have published a deployment, or any later project/deployment/
record validation or record write fails, the wrapper automatically calls the
rollback API for **only** the prior deployment captured in the reviewed deploy
plan. It independently verifies the API result, current canonical deployment,
and exact target deployment. It then creates
`deployment.json.failure.json`, canonical JSON mode `0600`, with the failure
stage, plan/source/toolchain hashes, exact rollback target, and verification
outcome. It stores no command output, exception text, token, or credential.

`automatic rollback FAILED` means production state is unverified: stop the
release, preserve the failure record, revoke normal release activity, and have
a second operator review the recorded target before retrying remediation. Do
not announce or continue the release.

## 3. Consume the record in the post-deploy canary

The canary refuses an unreviewed record digest or a record whose new deployment
is no longer Cloudflare's canonical production deployment. It then runs the
fixed release-identity canary for site/API/MCP same-SHA parity followed by the
backend-recovery containment canary. Canary is a write-capable transaction:
failure automatically rolls Pages back to the deployment record's exact prior
deployment and verifies the restored canonical state. Therefore the write
switch and exact reviewed deployment-record hash are mandatory even though a
passing canary performs no Cloudflare write. Its canonical evidence contains
command/output digests and the rollback outcome, never raw output or
credentials.

```bash
export TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE=1

python3 scripts/deploy/cloudflare_pages_release.py canary \
  --deployment-record /var/lib/tinyzkp-private/pages-releases/deployment.json \
  --expected-record-sha256 REPLACE_WITH_DEPLOYMENT_RECORD_SHA256 \
  --expected-account-id "$ACCOUNT" \
  --output /var/lib/tinyzkp-private/pages-releases/canary.json

unset TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE
```

Do not announce the release unless this command reports `passed` and the
broader live production preflight also passes. `failed_rolled_back` means the
new site was removed from production and the recorded prior site was verified.
`failed_rollback_failed` is a critical incident: treat the production state as
unknown and use the evidence record for a separately reviewed recovery.

## 4. Preview and apply rollback

Rollback accepts no operator-supplied deployment target. It reads only the
`prior_production_deployment` captured in the reviewed deployment record,
requires that the recorded new deployment is still canonical, retrieves the
prior object, and confirms it remains a successful clean production build.

```bash
python3 scripts/deploy/cloudflare_pages_release.py rollback \
  --deployment-record /var/lib/tinyzkp-private/pages-releases/deployment.json \
  --expected-record-sha256 REPLACE_WITH_DEPLOYMENT_RECORD_SHA256 \
  --expected-account-id "$ACCOUNT" \
  --plan-output /var/lib/tinyzkp-private/pages-releases/rollback-plan.json

export TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE=1

python3 scripts/deploy/cloudflare_pages_release.py rollback \
  --deployment-record /var/lib/tinyzkp-private/pages-releases/deployment.json \
  --expected-record-sha256 REPLACE_WITH_DEPLOYMENT_RECORD_SHA256 \
  --expected-account-id "$ACCOUNT" \
  --apply \
  --expected-plan-sha256 REPLACE_WITH_EXACT_ROLLBACK_PLAN_SHA256 \
  --record-output /var/lib/tinyzkp-private/pages-releases/rollback.json

unset TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE
```

The only rollback write surface is Cloudflare's documented
`POST /accounts/{account_id}/pages/projects/tinyzkp/deployments/{recorded_prior_id}/rollback`.
The wrapper verifies that Cloudflare's canonical deployment and API result both
equal that exact recorded target before creating
`rolled_back_pending_canary` evidence. Coordinate API/MCP rollback and rerun
containment canaries as required; a website-only rollback does not itself
restore cross-surface same-SHA parity.

References: [Wrangler Pages deploy options](https://developers.cloudflare.com/workers/wrangler/commands/pages/),
[Pages project identity](https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/get/),
and [Pages rollback API](https://developers.cloudflare.com/api/resources/pages/subresources/projects/subresources/deployments/methods/rollback/).
