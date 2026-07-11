#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET=/etc/caddy/tinyzkp-beta-route.caddy

if [[ $EUID -ne 0 ]]; then
  echo "switch-beta-route must run as root" >&2
  exit 2
fi

case "$ACTION" in
  public)
    discovery="$(curl --fail --silent --show-error http://127.0.0.1:8090/v1/discovery)"
    if [[ "$(jq -r .service_status <<<"$discovery")" != public_beta ]]; then
      echo "beta API is not authorized in public_beta mode" >&2
      exit 3
    fi
    install -o root -g caddy -m 0640 "$SOURCE_DIR/caddy-route.public-beta.caddy" "$TARGET"
    install -o root -g caddy -m 0640 "$SOURCE_DIR/Caddyfile.beta" /etc/caddy/Caddyfile
    ;;
  rollback)
    install -o root -g caddy -m 0640 "$SOURCE_DIR/caddy-route.rollback.caddy" "$TARGET"
    install -o root -g caddy -m 0640 "$SOURCE_DIR/Caddyfile.beta" /etc/caddy/Caddyfile
    ;;
  containment)
    [[ -f /etc/caddy/Caddyfile.tinyzkp-containment ]] || { echo "containment Caddyfile backup is missing" >&2; exit 3; }
    install -o root -g caddy -m 0640 "$SOURCE_DIR/caddy-route.containment.caddy" "$TARGET"
    install -o root -g caddy -m 0640 /etc/caddy/Caddyfile.tinyzkp-containment /etc/caddy/Caddyfile
    ;;
  *)
    echo "usage: $0 public|rollback|containment" >&2
    exit 2
    ;;
esac

caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
curl --fail --silent --show-error https://api.tinyzkp.com/healthz >/dev/null
echo "TinyZKP beta route switched to $ACTION"
