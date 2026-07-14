#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATIONS="$ROOT/crates/hc-beta-api/migrations"
POSTGRES_IMAGE="${TINYZKP_MIGRATION_TEST_POSTGRES_IMAGE:-postgres:17.5-bookworm@sha256:fbcea1bd13b6a882cd6caa6b58db3ae5c102efe50ec625b3e2a5cbc50db5bfe4}"
CONTAINER="tinyzkp-migration-upgrade-${GITHUB_RUN_ID:-$$}-${RANDOM}"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --detach --rm \
  --name "$CONTAINER" \
  --env POSTGRES_PASSWORD=migration-test-only \
  --env POSTGRES_USER=tinyzkp_beta \
  --env POSTGRES_DB=tinyzkp_migration_upgrade_test \
  "$POSTGRES_IMAGE" >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -U tinyzkp_beta -d tinyzkp_migration_upgrade_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$CONTAINER" pg_isready -U tinyzkp_beta -d tinyzkp_migration_upgrade_test >/dev/null

for migration in "$MIGRATIONS"/000{1,2,3,4,5}_*.sql; do
  docker exec -i "$CONTAINER" psql \
    -X -v ON_ERROR_STOP=1 -U tinyzkp_beta -d tinyzkp_migration_upgrade_test \
    < "$migration" >/dev/null
done

docker exec "$CONTAINER" psql \
  -X -v ON_ERROR_STOP=1 -U tinyzkp_beta -d tinyzkp_migration_upgrade_test \
  -c "INSERT INTO beta_workers (worker_id, credential_hash, enabled, max_slots, free_scratch_bytes, release_sha) VALUES ('upgrade-worker', repeat('a', 64), true, 4, 709345742848, repeat('0', 40));" \
  >/dev/null

docker exec -i "$CONTAINER" psql \
  -X -v ON_ERROR_STOP=1 -U tinyzkp_beta -d tinyzkp_migration_upgrade_test \
  < "$MIGRATIONS/0006_autopilot_operations.sql" >/dev/null

capacity="$(docker exec "$CONTAINER" psql -X -A -t -v ON_ERROR_STOP=1 \
  -U tinyzkp_beta -d tinyzkp_migration_upgrade_test \
  -c "SELECT total_scratch_bytes FROM beta_workers WHERE worker_id = 'upgrade-worker';")"
constraint_count="$(docker exec "$CONTAINER" psql -X -A -t -v ON_ERROR_STOP=1 \
  -U tinyzkp_beta -d tinyzkp_migration_upgrade_test \
  -c "SELECT count(*) FROM pg_constraint WHERE conrelid = 'beta_workers'::regclass AND conname = 'beta_workers_scratch_capacity_check' AND convalidated;")"

[[ "$capacity" == "709345742848" ]] || {
  echo "worker scratch capacity backfill mismatch: $capacity" >&2
  exit 1
}
[[ "$constraint_count" == "1" ]] || {
  echo "worker scratch capacity constraint is missing or unvalidated" >&2
  exit 1
}

echo "PASS public-beta PostgreSQL upgrade from migration 5 with an existing worker"
