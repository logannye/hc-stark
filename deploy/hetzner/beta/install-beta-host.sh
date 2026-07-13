#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SOURCE="$ROOT/deploy/hetzner/beta"

if [[ $EUID -ne 0 ]]; then
  echo "install-beta-host must run as root" >&2
  exit 2
fi
if [[ "$ROLE" != api && "$ROLE" != worker ]]; then
  echo "usage: $0 api|worker" >&2
  exit 2
fi

install -d -o root -g root -m 0755 /opt/tinyzkp/deploy/hetzner/beta
cp -R "$SOURCE"/. /opt/tinyzkp/deploy/hetzner/beta/
find /opt/tinyzkp/deploy/hetzner/beta -type f -name '*.env' -exec chmod 0600 {} +

if [[ "$ROLE" == api ]]; then
  secret_dir=${TINYZKP_BETA_SECRET_DIR:-/etc/tinyzkp/beta}
  for file in beta-api.env pgbouncer.env postgres_password pgbackrest.conf compose.env; do
    path="$secret_dir/$file"
    [[ -f "$path" ]] || { echo "missing $path" >&2; exit 3; }
    mode=$(stat -c %a "$path")
    [[ "$mode" == 600 || "$mode" == 400 ]] || { echo "$path must be mode 0600 or 0400" >&2; exit 3; }
  done
  [[ "$(stat -c %u "$secret_dir/pgbackrest.conf")" == 999 ]] || {
    echo "$secret_dir/pgbackrest.conf must be owned by PostgreSQL uid 999" >&2
    exit 3
  }
  [[ -d "$secret_dir/release" ]] || { echo "missing $secret_dir/release" >&2; exit 3; }
  [[ "$(stat -c %a "$secret_dir/release")" == 700 ]] || { echo "$secret_dir/release must be mode 0700" >&2; exit 3; }
  /usr/bin/docker network inspect tinyzkp-observability >/dev/null 2>&1 || \
    /usr/bin/docker network create --internal --subnet 172.31.77.0/24 tinyzkp-observability >/dev/null
  install -d -o 10001 -g 10001 -m 0700 /var/lib/tinyzkp-owner /var/lib/tinyzkp-owner/reports
  if [[ ! -f /etc/caddy/Caddyfile.tinyzkp-containment ]]; then
    install -o root -g caddy -m 0640 /etc/caddy/Caddyfile /etc/caddy/Caddyfile.tinyzkp-containment
  fi
  install -o root -g caddy -m 0640 "$SOURCE/caddy-route.containment.caddy" /etc/caddy/tinyzkp-beta-route.caddy
  install -o root -g root -m 0644 "$SOURCE"/systemd/tinyzkp-*.service /etc/systemd/system/
  install -o root -g root -m 0644 "$SOURCE"/systemd/tinyzkp-*.timer /etc/systemd/system/
  systemctl daemon-reload
  chmod 0755 /opt/tinyzkp/deploy/hetzner/beta/report-api-storage.sh /opt/tinyzkp/deploy/hetzner/beta/record-beta-activation.sh
  systemctl enable tinyzkp-pgbackrest-diff.timer tinyzkp-pgbackrest-full.timer tinyzkp-stripe-reconcile.timer tinyzkp-retention.timer tinyzkp-api-storage-health.timer tinyzkp-owner-digest.timer tinyzkp-viability.timer
  echo "API host files installed. Start dark deployment only after docker compose config succeeds."
else
  secret_dir=${TINYZKP_WORKER_SECRET_DIR:-/etc/tinyzkp/worker}
  for file in worker.env compose.env; do
    path="$secret_dir/$file"
    [[ -f "$path" ]] || { echo "missing $path" >&2; exit 3; }
    mode=$(stat -c %a "$path")
    [[ "$mode" == 600 || "$mode" == 400 ]] || { echo "$path must be mode 0600 or 0400" >&2; exit 3; }
  done
  mountpoint -q /srv/tinyzkp-scratch || { echo "/srv/tinyzkp-scratch is not mounted" >&2; exit 3; }
  options=$(findmnt -no OPTIONS /srv/tinyzkp-scratch)
  for option in noexec nodev nosuid; do
    [[ ",$options," == *",$option,"* ]] || { echo "scratch mount lacks $option" >&2; exit 3; }
  done
  chown 10001:10001 /srv/tinyzkp-scratch
  chmod 0700 /srv/tinyzkp-scratch
  install -o root -g root -m 0644 "$SOURCE/systemd/tinyzkp-beta-worker.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable tinyzkp-beta-worker.service
  echo "Worker files installed. Start only after WireGuard reaches 10.77.0.1:8091."
fi
