#!/bin/bash
# Run the exact static Guard production contract selected by the owner.
set -euo pipefail

AUDIT_MODE="${TINYZKP_AUDIT_MODE:-}"
case "$AUDIT_MODE" in
    canonical|guard_prelaunch|guard_transition|guard_live|guard_frozen)
        ;;
    *)
        echo "TINYZKP_AUDIT_MODE must be canonical, guard_prelaunch, guard_transition, guard_live, or guard_frozen" >&2
        exit 2
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/guard_health_audit.py" --mode "$AUDIT_MODE"
