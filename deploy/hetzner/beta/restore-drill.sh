#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != --confirm-isolated-restore ]]; then
  echo "usage: $0 --confirm-isolated-restore" >&2
  exit 2
fi

secret_dir=${TINYZKP_BETA_SECRET_DIR:-/etc/tinyzkp/beta}
: "${TINYZKP_POSTGRES_IMAGE:?digest-pinned PostgreSQL image required}"
[[ "$TINYZKP_POSTGRES_IMAGE" == *@sha256:* ]] || {
  echo "TINYZKP_POSTGRES_IMAGE must be digest pinned" >&2
  exit 3
}

suffix=$(date -u +%Y%m%dT%H%M%SZ)
restore_volume="tinyzkp-beta-restore-$suffix"
restore_container="tinyzkp-beta-restore-$suffix"
docker volume create "$restore_volume" >/dev/null
cleanup() {
  docker rm -f "$restore_container" >/dev/null 2>&1 || true
  if [[ "${TINYZKP_KEEP_RESTORE_VOLUME:-0}" != 1 ]]; then
    docker volume rm "$restore_volume" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Named volumes start as root. Prepare the isolated target before restoring as
# the same unprivileged user that owns the production cluster.
docker run --rm --entrypoint sh -v "$restore_volume:/restore" \
  "$TINYZKP_POSTGRES_IMAGE" -c 'chown -R postgres:postgres /restore'
docker run --rm --user postgres \
  -v "$restore_volume:/var/lib/postgresql/data" \
  -v "$secret_dir/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro" \
  "$TINYZKP_POSTGRES_IMAGE" \
  pgbackrest --config=/etc/pgbackrest/pgbackrest.conf --stanza=tinyzkp-beta \
  --pg1-path=/var/lib/postgresql/data/pgdata restore

docker run -d --name "$restore_container" \
  -e PGDATA=/var/lib/postgresql/data/pgdata \
  -v "$restore_volume:/var/lib/postgresql/data" \
  -v "$secret_dir/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro" \
  "$TINYZKP_POSTGRES_IMAGE" postgres -c listen_addresses='' >/dev/null

ready=0
for _ in $(seq 1 30); do
  if docker exec -u postgres "$restore_container" \
    pg_isready -U tinyzkp_beta -d tinyzkp_beta >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  docker logs "$restore_container" >&2
  echo "isolated restore did not become ready" >&2
  exit 4
fi

docker exec -i -u postgres "$restore_container" \
  psql -U tinyzkp_beta -d tinyzkp_beta -v ON_ERROR_STOP=1 <<'SQL'
SELECT count(*) FROM tenants;
SELECT count(*) FROM beta_credit_events;
SELECT tenant_id,
       sum(subscription_delta_millicredits) AS subscription_event_total,
       sum(purchased_delta_millicredits) AS purchased_event_total,
       sum(reserved_delta_millicredits) AS reserved_event_total
  FROM beta_credit_events GROUP BY tenant_id ORDER BY tenant_id;

DO $$
DECLARE mismatch_count bigint;
BEGIN
  WITH event_totals AS (
    SELECT tenant_id,
           sum(subscription_delta_millicredits) AS subscription_total,
           sum(purchased_delta_millicredits) AS purchased_total,
           sum(reserved_delta_millicredits) AS reserved_total
      FROM beta_credit_events
     GROUP BY tenant_id
  )
  SELECT count(*) INTO mismatch_count
    FROM beta_credit_accounts accounts
    FULL JOIN event_totals events USING (tenant_id)
   WHERE coalesce(accounts.subscription_millicredits, 0) <> coalesce(events.subscription_total, 0)
      OR coalesce(accounts.purchased_millicredits, 0) <> coalesce(events.purchased_total, 0)
      OR coalesce(accounts.reserved_millicredits, 0) <> coalesce(events.reserved_total, 0);
  IF mismatch_count <> 0 THEN
    RAISE EXCEPTION 'credit ledger restore mismatch for % tenant(s)', mismatch_count;
  END IF;
END $$;
SQL
echo "PASS isolated PostgreSQL restore and immutable credit-ledger reconciliation"
if [[ "${TINYZKP_KEEP_RESTORE_VOLUME:-0}" == 1 ]]; then
  echo "retained restore volume: $restore_volume"
fi
