#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mount=${TINYZKP_API_STORAGE_MOUNT:-/var/lib/docker}
used=$(df -P "$mount" | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
[[ "$used" =~ ^[0-9]+$ && "$used" -le 100 ]] || { echo "invalid df utilization" >&2; exit 2; }
free=$((100-used))
status=healthy
(( free >= 30 )) || status=unhealthy
/usr/bin/docker compose --env-file /etc/tinyzkp/beta/compose.env -f docker-compose.api.yml run --rm --no-deps \
  --entrypoint /usr/local/bin/hc-beta-health-report beta-ops api_storage "$status" "$free"
