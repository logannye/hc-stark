#!/bin/bash
set -euo pipefail

LABEL="com.tinyzkp.api-audit"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SOURCE_PLIST="$REPO_ROOT/deploy/macos/$LABEL.plist"
TARGET_PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
ENV_DIR="$HOME/.config/tinyzkp"
ENV_FILE="$ENV_DIR/audit.env"
LOG_DIR="$HOME/Library/Logs/TinyZKP"
RUNTIME_DIR="$HOME/Library/Application Support/TinyZKP/audit"
DOMAIN="gui/$(id -u)"

expected="/Users/logannye/Documents/TinyZKP/hc-stark"
if [ "$REPO_ROOT" != "$expected" ]; then
    echo "refusing to install from non-canonical checkout: $REPO_ROOT" >&2
    exit 2
fi

mkdir -p "$HOME/Library/LaunchAgents" "$ENV_DIR" "$LOG_DIR" "$RUNTIME_DIR"
python3 "$REPO_ROOT/scripts/monitoring/migrate_audit_env.py" "$ENV_FILE"
chmod 600 "$ENV_FILE"

launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
cp "$REPO_ROOT/scripts/monitoring/api_health_audit.sh" "$RUNTIME_DIR/api_health_audit.sh"
cp "$REPO_ROOT/scripts/monitoring/guard_health_audit.py" "$RUNTIME_DIR/guard_health_audit.py"
cp "$REPO_ROOT/scripts/monitoring/run_api_health_audit.sh" "$RUNTIME_DIR/run_api_health_audit.sh"
chmod 700 "$RUNTIME_DIR"/*.sh "$RUNTIME_DIR"/*.py
cp "$SOURCE_PLIST" "$TARGET_PLIST"
chmod 600 "$TARGET_PLIST"
plutil -lint "$TARGET_PLIST"
launchctl bootstrap "$DOMAIN" "$TARGET_PLIST"
launchctl enable "$DOMAIN/$LABEL"

echo "installed $LABEL from canonical source $REPO_ROOT"
echo "launchd runtime: $RUNTIME_DIR"
echo "configuration: $ENV_FILE"
launchctl print "$DOMAIN/$LABEL" | grep -E 'path =|program =|runs =|last exit code' || true
