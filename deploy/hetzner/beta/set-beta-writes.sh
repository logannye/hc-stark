#!/usr/bin/env bash
set -euo pipefail

VALUE="${1:-}"
EXPECTED_SHA="${2:-}"
EXPECTED_STATUS="${3:-}"
SECRET_DIR="${TINYZKP_BETA_SECRET_DIR:-/etc/tinyzkp/beta}"
ENV_FILE="$SECRET_DIR/beta-api.env"
COMPOSE_ENV="$SECRET_DIR/compose.env"
DEPLOY_DIR=/opt/tinyzkp/deploy/hetzner/beta

[[ $EUID -eq 0 ]] || { echo "set-beta-writes must run as root" >&2; exit 2; }
[[ "$VALUE" == 0 || "$VALUE" == 1 ]] || { echo "writes value must be 0 or 1" >&2; exit 2; }
[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "exact release SHA required" >&2; exit 2; }
[[ "$EXPECTED_STATUS" == operator_canary || "$EXPECTED_STATUS" == public_beta ]] || { echo "invalid expected status" >&2; exit 2; }
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || { echo "beta API environment is missing or unsafe" >&2; exit 3; }
[[ "$(stat -c %a "$ENV_FILE")" == 600 || "$(stat -c %a "$ENV_FILE")" == 400 ]] || { echo "beta API environment must be owner-only" >&2; exit 3; }
[[ -f "$COMPOSE_ENV" && ! -L "$COMPOSE_ENV" ]] || { echo "beta Compose environment is missing or unsafe" >&2; exit 3; }
[[ "$(stat -c %a "$COMPOSE_ENV")" == 600 || "$(stat -c %a "$COMPOSE_ENV")" == 400 ]] || { echo "beta Compose environment must be owner-only" >&2; exit 3; }

lock=/run/lock/tinyzkp-beta-writes.lock
exec 9>"$lock"
flock -n 9 || { echo "another writes transaction is active" >&2; exit 3; }
backup="$(mktemp "$SECRET_DIR/.beta-api.env.XXXXXX")"
temporary="$(mktemp "$SECRET_DIR/.beta-api.next.XXXXXX")"
chmod 0600 "$backup" "$temporary"
cp "$ENV_FILE" "$backup"
restore() {
  install -o root -g root -m 0600 "$backup" "$ENV_FILE"
  cd "$DEPLOY_DIR"
  /usr/bin/docker compose --env-file "$COMPOSE_ENV" -f docker-compose.api.yml up -d --no-deps beta-api >/dev/null 2>&1 || true
}
committed=0
cleanup() {
  status=$?
  if [[ $status -ne 0 && $committed -eq 0 ]]; then restore; fi
  rm -f "$backup" "$temporary"
  exit "$status"
}
trap cleanup EXIT INT TERM

awk -v value="$VALUE" '
  BEGIN { found=0 }
  /^TINYZKP_BETA_WRITES_ENABLED=/ { print "TINYZKP_BETA_WRITES_ENABLED=" value; found=1; next }
  { print }
  END { if (!found) print "TINYZKP_BETA_WRITES_ENABLED=" value }
' "$ENV_FILE" >"$temporary"
install -o root -g root -m 0600 "$temporary" "$ENV_FILE"
cd "$DEPLOY_DIR"
/usr/bin/docker compose --env-file "$COMPOSE_ENV" -f docker-compose.api.yml up -d --no-deps beta-api >/dev/null

ready=0
for _ in $(seq 1 30); do
  if discovery="$(curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8090/v1/discovery 2>/dev/null)"; then
    if [[ "$(jq -er .release_sha <<<"$discovery")" == "$EXPECTED_SHA" \
       && "$(jq -er .service_status <<<"$discovery")" == "$EXPECTED_STATUS" \
       && "$(jq -er .signup <<<"$discovery")" == "$([[ "$VALUE" == 1 && "$EXPECTED_STATUS" == public_beta ]] && echo true || echo false)" ]]; then
      ready=1
      break
    fi
  fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo "beta API did not return the requested writes state" >&2; exit 4; }
committed=1
trap - EXIT INT TERM
rm -f "$backup" "$temporary"
echo "TinyZKP beta writes set to $VALUE for $EXPECTED_SHA"
