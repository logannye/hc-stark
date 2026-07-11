#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != --confirm-isolated-restore ]]; then
  echo "usage: $0 --confirm-isolated-restore" >&2
  exit 2
fi

COMPOSE=(docker compose -f docker-compose.api.yml)
restore_volume="tinyzkp-beta-restore-$(date -u +%Y%m%dT%H%M%SZ)"
docker volume create "$restore_volume" >/dev/null
cleanup() { docker rm -f tinyzkp-beta-restore >/dev/null 2>&1 || true; }
trap cleanup EXIT

"${COMPOSE[@]}" run --rm -T -v "$restore_volume:/restore" postgres \
  pgbackrest --stanza=tinyzkp-beta --pg1-path=/restore --delta restore
docker run --rm --name tinyzkp-beta-restore \
  -e POSTGRES_PASSWORD=restore-only \
  -v "$restore_volume:/var/lib/postgresql/data" \
  -p 127.0.0.1:55432:5432 \
  postgres:17.5-bookworm@sha256:fbcea1bd13b6a882cd6caa6b58db3ae5c102efe50ec625b3e2a5cbc50db5bfe4 \
  postgres -c listen_addresses='*' &

for _ in $(seq 1 30); do
  pg_isready -h 127.0.0.1 -p 55432 && break
  sleep 1
done
psql postgresql://postgres:restore-only@127.0.0.1:55432/postgres -v ON_ERROR_STOP=1 <<'SQL'
SELECT count(*) FROM tenants;
SELECT count(*) FROM beta_credit_events;
SELECT tenant_id,
       sum(subscription_delta_millicredits) AS subscription_event_total,
       sum(purchased_delta_millicredits) AS purchased_event_total,
       sum(reserved_delta_millicredits) AS reserved_event_total
  FROM beta_credit_events GROUP BY tenant_id ORDER BY tenant_id;
SQL
echo "Isolated restore is queryable on port 55432; complete API-key and retained-bundle verification before removing volume $restore_volume"

