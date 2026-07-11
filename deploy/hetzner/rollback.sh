#!/usr/bin/env -S -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C TZ=UTC TINYZKP_CLEAN_LAUNCH=1 /bin/bash --noprofile --norc
# Roll back only the active transaction's recorded prior known-containment SHA.
set -euo pipefail
[[ ${TINYZKP_CLEAN_LAUNCH:-} == 1 ]] || {
    /usr/bin/printf '%s\n' 'ERROR: invoke rollback.sh through its clean shebang' >&2
    exit 1
}
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset PYTHONPATH PYTHONHOME NODE_OPTIONS BASH_ENV ENV CDPATH GIT_DIR GIT_WORK_TREE \
    LD_PRELOAD DYLD_INSERT_LIBRARIES || true

REPO=/opt/hc-stark
LOCK=/var/lib/tinyzkp-private/deploy/deployment.lock
TARGET=${1:-}

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    echo "ERROR: rollback requires root" >&2
    exit 1
fi
case "$TARGET" in
    --fail-closed-no-prior) MODE=fail_closed ;;
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) echo "ERROR: pass the exact prior known-containment SHA or --fail-closed-no-prior" >&2; exit 1 ;;
esac
if [ ! -x /usr/bin/flock ]; then
    echo "ERROR: /usr/bin/flock is required" >&2
    exit 1
fi
cd "$REPO"
exec 8>"$LOCK"
if ! /usr/bin/flock -n 8; then
    echo "ERROR: another deployment transaction is active" >&2
    exit 1
fi
if [ "${MODE:-}" = fail_closed ]; then
    exec /usr/bin/python3 deploy/hetzner/deployment_transaction.py rollback \
        --fail-closed-no-prior
fi
exec /usr/bin/python3 deploy/hetzner/deployment_transaction.py rollback \
    --target-release-sha "$TARGET"
