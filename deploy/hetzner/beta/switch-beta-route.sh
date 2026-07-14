#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
EXPECTED_SHA="${2:-}"
EXPECTED_STATUS="${3:-}"
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_MODE="${TINYZKP_ROUTE_TEST_MODE:-0}"
TARGET_ROUTE="${TINYZKP_ROUTE_TARGET_ROUTE:-/etc/caddy/tinyzkp-beta-route.caddy}"
TARGET_CADDY="${TINYZKP_ROUTE_TARGET_CADDY:-/etc/caddy/Caddyfile}"
CONTAINMENT_CADDY="${TINYZKP_ROUTE_CONTAINMENT_CADDY:-/etc/caddy/Caddyfile.tinyzkp-containment}"
LOCK="${TINYZKP_ROUTE_LOCK:-/run/lock/tinyzkp-beta-route.lock}"

if [[ $EUID -ne 0 && "$TEST_MODE" != 1 ]]; then
  echo "switch-beta-route must run as root" >&2
  exit 2
fi
if [[ "$TEST_MODE" == 1 ]]; then
  for target in "$TARGET_ROUTE" "$TARGET_CADDY" "$CONTAINMENT_CADDY" "$LOCK"; do
    [[ "$target" == "${TMPDIR:-/tmp}/"* ]] || {
      echo "test-mode paths must remain below TMPDIR" >&2
      exit 2
    }
  done
fi
if [[ ! "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "an exact lowercase release SHA is required" >&2
  exit 2
fi
case "$ACTION:$EXPECTED_STATUS" in
  public:public_beta|rollback:public_beta|dark:operator_canary|containment:backend_recovery) ;;
  *) echo "usage: $0 public|rollback|dark|containment EXPECTED_SHA EXPECTED_STATUS" >&2; exit 2 ;;
esac

exec 9>"$LOCK"
flock -n 9 || { echo "another route transaction is active" >&2; exit 3; }

transaction="$(mktemp -d "$(dirname "$TARGET_CADDY")/.tinyzkp-route.XXXXXX")"
chmod 0700 "$transaction"
previous_route="$transaction/previous-route.caddy"
previous_caddy="$transaction/previous-Caddyfile"
staged_route="$transaction/next-route.caddy"
staged_caddy="$transaction/next-Caddyfile"
cp -p "$TARGET_ROUTE" "$previous_route"
cp -p "$TARGET_CADDY" "$previous_caddy"

install_target() {
  source="$1"
  destination="$2"
  if [[ "$TEST_MODE" == 1 ]]; then
    install -m 0640 "$source" "$destination"
  else
    install -o root -g caddy -m 0640 "$source" "$destination"
  fi
}

restore_previous() {
  install_target "$previous_route" "$TARGET_ROUTE"
  install_target "$previous_caddy" "$TARGET_CADDY"
  caddy validate --adapter caddyfile --config "$TARGET_CADDY" >/dev/null 2>&1 || return 1
  systemctl reload caddy
}

committed=0
cleanup() {
  status=$?
  if [[ $status -ne 0 && $committed -eq 0 ]]; then
    echo "route transaction failed; restoring the previous configuration" >&2
    restore_previous || echo "CRITICAL: automatic Caddy restoration failed" >&2
  fi
  rm -rf "$transaction"
  exit "$status"
}
trap cleanup EXIT INT TERM

case "$ACTION" in
  public) source_route="$SOURCE_DIR/caddy-route.public-beta.caddy" ;;
  rollback) source_route="$SOURCE_DIR/caddy-route.rollback.caddy" ;;
  dark) source_route="$SOURCE_DIR/caddy-route.dark-canary.caddy" ;;
  containment) source_route="$SOURCE_DIR/caddy-route.containment.caddy" ;;
esac
install -m 0640 "$source_route" "$staged_route"

if [[ "$ACTION" == containment ]]; then
  [[ -f "$CONTAINMENT_CADDY" ]] || {
    echo "containment Caddyfile backup is missing" >&2
    exit 3
  }
  install -m 0640 "$CONTAINMENT_CADDY" "$staged_caddy"
else
  sed "s#/etc/caddy/tinyzkp-beta-route.caddy#$staged_route#" \
    "$SOURCE_DIR/Caddyfile.beta" >"$staged_caddy"
  chmod 0640 "$staged_caddy"
fi
caddy validate --adapter caddyfile --config "$staged_caddy"

install_target "$staged_route" "$TARGET_ROUTE"
if [[ "$ACTION" == containment ]]; then
  install_target "$staged_caddy" "$TARGET_CADDY"
else
  install_target "$SOURCE_DIR/Caddyfile.beta" "$TARGET_CADDY"
fi
caddy validate --adapter caddyfile --config "$TARGET_CADDY"
systemctl reload caddy

if [[ "$ACTION" != containment ]]; then
  local_discovery="$(curl --fail --silent --show-error --max-time 10 http://127.0.0.1:8090/v1/discovery)"
  [[ "$(jq -er .release_sha <<<"$local_discovery")" == "$EXPECTED_SHA" ]] || {
    echo "local discovery release SHA mismatch" >&2
    exit 4
  }
  [[ "$(jq -er .service_status <<<"$local_discovery")" == "$EXPECTED_STATUS" ]] || {
    echo "local discovery status mismatch" >&2
    exit 4
  }
fi

curl --fail --silent --show-error --max-time 15 https://api.tinyzkp.com/healthz >/dev/null
if [[ "$ACTION" == public || "$ACTION" == rollback ]]; then
  external_discovery="$(curl --fail --silent --show-error --max-time 15 https://api.tinyzkp.com/v1/discovery)"
  [[ "$(jq -er .release_sha <<<"$external_discovery")" == "$EXPECTED_SHA" ]]
  [[ "$(jq -er .service_status <<<"$external_discovery")" == "$EXPECTED_STATUS" ]]
elif [[ "$ACTION" == dark ]]; then
  code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 15 https://api.tinyzkp.com/v1/discovery)"
  [[ "$code" == 503 ]] || { echo "dark route exposed public discovery" >&2; exit 4; }
else
  external_status="$(curl --fail --silent --show-error --max-time 15 https://tinyzkp.com/discovery.json | jq -er .service_status)"
  [[ "$external_status" == backend_recovery ]] || { echo "containment discovery did not recover" >&2; exit 4; }
fi

committed=1
trap - EXIT INT TERM
rm -rf "$transaction"
echo "TinyZKP beta route transaction committed: $ACTION $EXPECTED_SHA $EXPECTED_STATUS"
