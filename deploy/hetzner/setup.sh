#!/usr/bin/env -S -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C TZ=UTC TINYZKP_CLEAN_LAUNCH=1 /bin/bash --noprofile --norc
# TinyZKP — Hetzner server provisioning (idempotent).
# Run as root on the reviewed Debian 12 x86-64 host. Ubuntu and non-x86-64
# hosts are not compatible with the pinned billing-runtime profile.
[[ ${TINYZKP_CLEAN_LAUNCH:-} == 1 ]] || {
  /usr/bin/printf '%s\n' 'ERROR: invoke setup.sh directly through its clean shebang' >&2
  exit 1
}
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset PYTHONPATH PYTHONHOME NODE_OPTIONS BASH_ENV ENV CDPATH GIT_DIR GIT_WORK_TREE \
  LD_PRELOAD DYLD_INSERT_LIBRARIES HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy || true

echo "==> TinyZKP server setup"

OS_ID="$(/usr/bin/sed -n 's/^ID=//p' /usr/lib/os-release | /usr/bin/tr -d '\"' | /usr/bin/head -n 1)"
OS_VERSION_ID="$(/usr/bin/sed -n 's/^VERSION_ID=//p' /usr/lib/os-release | /usr/bin/tr -d '\"' | /usr/bin/head -n 1)"
if [ "$OS_ID" != debian ] || [ "$OS_VERSION_ID" != 12 ] \
    || [ "$(/usr/bin/dpkg --print-architecture)" != amd64 ]; then
  echo "ERROR: TinyZKP production provisioning requires Debian 12 amd64." >&2
  exit 1
fi

# ---- Docker ----
if ! command -v docker &>/dev/null; then
  echo "Installing Docker..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

# ---- Caddy ----
if ! command -v caddy &>/dev/null; then
  echo "Installing Caddy..."
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y -qq caddy
fi

# ---- Python (for billing scripts) ----
if ! command -v python3 &>/dev/null; then
  apt-get install -y -qq python3 python3-pip python3-venv
elif ! python3 -m venv --help >/dev/null 2>&1; then
  apt-get install -y -qq python3-venv
fi

# ---- Directory structure ----
echo "Setting up /opt/hc-stark..."
mkdir -p /opt/hc-stark/site

# ---- Host runtime preparation ----
# Generic bootstrap cannot authorize release-bound runtime bytes. Installation
# waits for the independently reviewed host-provenance record and exact offline
# wheelhouse described in billing/RUNTIME.md.
install -d -o root -g root -m 0755 /var/lib/tinyzkp-runtime
install -d -o root -g root -m 0700 /var/lib/tinyzkp-runtime/wheelhouse
echo "NOTICE: populate and review the exact wheelhouse, then run install_billing_runtime.sh explicitly."

# ---- Firewall ----
if command -v ufw &>/dev/null; then
  echo "Configuring firewall..."
  ufw --force reset >/dev/null 2>&1
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp   # SSH
  ufw allow 80/tcp   # HTTP (Caddy redirect)
  ufw allow 443/tcp  # HTTPS (Caddy)
  ufw --force enable
fi

# ---- Caddy config ----
echo "Installing Caddyfile..."
cp "$(dirname "$0")/Caddyfile" /etc/caddy/Caddyfile
systemctl reload caddy 2>/dev/null || systemctl restart caddy

# ---- Docker compose systemd ----
cat > /etc/systemd/system/hc-stark.service <<'UNIT'
[Unit]
Description=TinyZKP Docker Compose
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/hc-stark
ExecStart=/usr/bin/docker compose -f docker-compose.yml -f deploy/hetzner/docker-compose.prod.yml up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable hc-stark.service

# ---- Billing cron (disabled during backend recovery) ----
CRON_FILE="/etc/cron.d/hc-billing"
cat > "$CRON_FILE" <<'CRON'
# TinyZKP backend recovery: no usage meter, checkout recovery, lifecycle,
# outbound, or growth-automation jobs may run.
0 2 * * * root /opt/hc-stark/billing/backup.sh >> /var/log/hc-backup.log 2>&1
17 3 * * * tinyzkp-billing /bin/sh -c 'umask 077; exec /var/lib/tinyzkp-runtime/billing-venv/bin/python /opt/hc-stark/billing/evaluation_intake.py --db /opt/hc-stark/data/evaluation_applications.sqlite purge-expired --apply >> /opt/hc-stark/data/evaluation-retention.log 2>&1'
CRON
chmod 644 "$CRON_FILE"
rm -f /etc/cron.d/hc-backup
install -d -o root -g root -m 0700 /opt/hc-stark/backups

# ---- Off-box backup (G13) — operator action required ----
# Without this, the box is a single point of failure for all tenant/usage/key data.
#
#   1. Install rclone:
#        apt-get install -y rclone
#
#   2. Configure a remote (Backblaze B2, S3, Hetzner Storage Box, SFTP, etc.):
#        rclone config --config /var/lib/tinyzkp-private/backup/rclone.conf
#
#   3. Add HC_BACKUP_REMOTE to /opt/hc-stark/.env, e.g.:
#        HC_BACKUP_REMOTE="b2:hc-stark-backups"
#        HC_BACKUP_REMOTE="s3:my-bucket/hc-stark"
#        HC_BACKUP_REMOTE="sftp-box:backups/hc-stark"
#
#   backup.sh exits nonzero until a usable off-host transport is configured.
#   Verify first push manually: /opt/hc-stark/billing/backup.sh
echo "NOTICE: Set HC_BACKUP_REMOTE in /opt/hc-stark/.env and install rclone for off-box backups (G13)."

# ---- Billing webhook systemd ----
if ! getent group tinyzkp-billing >/dev/null; then
    groupadd --system tinyzkp-billing
fi
if ! id -u tinyzkp-billing >/dev/null 2>&1; then
    useradd --system --gid tinyzkp-billing --home-dir /nonexistent \
        --shell /usr/sbin/nologin tinyzkp-billing
fi
SERVICE_UID="$(id -u tinyzkp-billing)"
SERVICE_GID="$(id -g tinyzkp-billing)"
/usr/bin/python3 /opt/hc-stark/billing/backup_env_exec.py \
    ensure-service-data-root --path /opt/hc-stark/data \
    --uid "$SERVICE_UID" --gid "$SERVICE_GID"
install -d -o root -g root -m 0700 \
    /var/lib/tinyzkp-private \
    /var/lib/tinyzkp-private/billing \
    /var/lib/tinyzkp-private/deploy \
    /var/lib/tinyzkp-private/deploy/consumed \
    /var/lib/tinyzkp-private/backup
install -d -o root -g tinyzkp-billing -m 0710 \
    /var/lib/tinyzkp-backup-staging
install -d -o root -g root -m 0700 /var/lib/tinyzkp-preflight-pycache
BACKUP_LOADER_TOKEN=/var/lib/tinyzkp-private/backup/loader-token
if [ ! -e "$BACKUP_LOADER_TOKEN" ]; then
    /usr/bin/python3 /opt/hc-stark/billing/backup_env_exec.py \
        create-loader-token --path "$BACKUP_LOADER_TOKEN"
else
    /usr/bin/python3 /opt/hc-stark/billing/backup_env_exec.py \
        validate-loader-token --path "$BACKUP_LOADER_TOKEN"
fi

cat > /etc/systemd/system/hc-billing-webhook.service <<'UNIT'
[Unit]
Description=TinyZKP Stripe Webhook
After=network.target

[Service]
Type=simple
User=tinyzkp-billing
Group=tinyzkp-billing
WorkingDirectory=/opt/hc-stark/billing
ExecStart=/var/lib/tinyzkp-runtime/billing-venv/bin/gunicorn -w 2 -b 127.0.0.1:5001 provision_tenant:app
Restart=on-failure
RestartSec=5
UMask=0077
Environment=PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=/opt/hc-stark/.env
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/opt/hc-stark/data

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable hc-billing-webhook.service

echo ""
echo "==> Setup complete."
echo ""

# ---- DNS instructions ----
SERVER_IP=$(curl -sf https://ifconfig.me || hostname -I | awk '{print $1}')
echo "==> DNS Records Required"
echo "  Create these A records in Cloudflare (proxied):"
echo "    api.tinyzkp.com      → ${SERVER_IP}"
echo "    webhook.tinyzkp.com  → ${SERVER_IP}"
echo ""
echo "  Example Cloudflare API commands:"
echo "    # Get zone ID"
echo "    ZONE_ID=\$(curl -s -H 'Authorization: Bearer \$CF_API_TOKEN' \\"
echo "      'https://api.cloudflare.com/client/v4/zones?name=tinyzkp.com' | jq -r '.result[0].id')"
echo ""
echo "    # Create api.tinyzkp.com A record"
echo "    curl -s -X POST -H 'Authorization: Bearer \$CF_API_TOKEN' \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      \"https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records\" \\"
echo "      -d '{\"type\":\"A\",\"name\":\"api\",\"content\":\"${SERVER_IP}\",\"proxied\":true}'"
echo ""
echo "    # Create webhook.tinyzkp.com A record"
echo "    curl -s -X POST -H 'Authorization: Bearer \$CF_API_TOKEN' \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      \"https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records\" \\"
echo "      -d '{\"type\":\"A\",\"name\":\"webhook\",\"content\":\"${SERVER_IP}\",\"proxied\":true}'"
echo ""

echo "Next steps:"
echo "  1. Copy the hc-stark repo to /opt/hc-stark/"
echo "  2. cp /opt/hc-stark/deploy/hetzner/.env.example /opt/hc-stark/.env"
echo "  3. Edit /opt/hc-stark/.env with real secrets"
echo "  4. Create Cloudflare DNS records (see above)"
echo "  5. systemctl start hc-stark"
echo "  6. systemctl start hc-billing-webhook"
echo "  7. Verify: curl https://api.tinyzkp.com/healthz"
echo "  8. Off-box backup (G13): apt-get install rclone && rclone config --config /var/lib/tinyzkp-private/backup/rclone.conf"
echo "     Then set HC_BACKUP_REMOTE in /opt/hc-stark/.env"
echo "     See docs/runbooks/restore.md for restore procedure."
