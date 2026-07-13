#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
/usr/bin/docker compose --env-file /etc/tinyzkp/beta/compose.env -f docker-compose.api.yml run --rm --no-deps \
  --entrypoint /usr/local/bin/hc-beta-viability beta-ops activate
