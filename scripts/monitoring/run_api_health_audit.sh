#!/bin/bash
# launchd entrypoint. Loads secrets/config from a mode-0600 file, never a plist.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${TINYZKP_AUDIT_ENV_FILE:-$HOME/.config/tinyzkp/audit.env}"

if [ ! -f "$ENV_FILE" ]; then
    echo "missing TinyZKP audit environment: $ENV_FILE" >&2
    exit 2
fi

permissions="$(stat -f '%Lp' "$ENV_FILE")"
if [ "$permissions" != "600" ]; then
    echo "TinyZKP audit environment must have mode 600 (found $permissions): $ENV_FILE" >&2
    exit 2
fi

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

exec /bin/bash "$SCRIPT_DIR/api_health_audit.sh"
