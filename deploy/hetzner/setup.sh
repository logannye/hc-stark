#!/usr/bin/env bash
# TinyZKP — Hetzner server provisioning (idempotent).
# Run as root on a fresh Debian 12 / Ubuntu 22.04+ box.
set -euo pipefail

echo "==> TinyZKP server setup"

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
  apt-get install -y -qq python3 python3-pip
fi
pip3 install --quiet stripe flask gunicorn 2>/dev/null || true

# ---- Directory structure ----
echo "Setting up /opt/hc-stark..."
mkdir -p /opt/hc-stark/{data,site}

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

# ---- Billing cron ----
CRON_LINE="0 * * * * root cd /opt/hc-stark && python3 billing/sync_usage.py >> /var/log/hc-billing.log 2>&1"
CRON_FILE="/etc/cron.d/hc-billing"
echo "$CRON_LINE" > "$CRON_FILE"
chmod 644 "$CRON_FILE"

# ---- Backup cron ----
BACKUP_CRON_LINE="0 2 * * * root /opt/hc-stark/billing/backup.sh >> /var/log/hc-backup.log 2>&1"
BACKUP_CRON_FILE="/etc/cron.d/hc-backup"
echo "$BACKUP_CRON_LINE" > "$BACKUP_CRON_FILE"
chmod 644 "$BACKUP_CRON_FILE"
mkdir -p /opt/hc-stark/backups

# ---- Billing webhook systemd ----
cat > /etc/systemd/system/hc-billing-webhook.service <<'UNIT'
[Unit]
Description=TinyZKP Stripe Webhook
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/hc-stark
ExecStart=/usr/bin/python3 -m gunicorn -w 2 -b 127.0.0.1:5001 billing.provision_tenant:app
Restart=on-failure
RestartSec=5
EnvironmentFile=/opt/hc-stark/.env

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
