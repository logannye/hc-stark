# Retired TinyZKP hostname migration

Status: procedure only. No DNS or Cloudflare custom-domain change is authorized
by this repository.

The exact retired hostnames are:

- `api.tinyzkp.com`
- `mcp.tinyzkp.com`
- `webhook.tinyzkp.com`

The static Pages worker handles those hostnames before canonical redirects and
returns `410 Gone` for every path and method without calling `ASSETS` or an
upstream. They must never redirect to `tinyzkp.com`.

## Preconditions

Do not move a hostname until the read-only external inventory is complete,
every real customer and financial obligation is resolved, statutory records
are retained, customer-artifact deletion follows the published retention
policy, final exports are verified, and the prior origin is ready to be
revoked. The checked-in decommission state is not evidence that any provider
action has happened.

## Migration

1. Record current DNS, Cloudflare custom domains, origin targets, certificates,
   API/MCP/webhook traffic, retention/export status, and rollback owner.
2. Deploy the reviewed static Pages commit and pass its ordinary contract and
   route canaries.
3. Add each exact hostname as a Pages custom domain using an owner-approved
   Cloudflare change. Do not use a Worker route with a dynamic upstream.
4. For every hostname, verify `GET` and `POST` on `/`, an arbitrary path, and
   a former service path return `410`, `X-Robots-Tag: noindex, nofollow`, no
   `Location`, and no origin request. Run:

   ```sh
   python3 scripts/deploy/static_site_canary.py --mode retired-hosts
   ```

5. Create signed `DecommissionEvidenceV1` only after the canary verifies all
   three hostnames and every decommission count is zero.
6. Preserve static `410 Gone` for at least 90 days. Record the start and
   earliest removal timestamp.
7. After 90 days and a second obligation review, remove the retired DNS/custom
   domains. Revoke old host credentials and certificates under the credential
   inventory.

Any redirect, `2xx`, authenticated response, upstream request, unresolved
obligation, or incomplete export blocks decommission evidence and launch.
