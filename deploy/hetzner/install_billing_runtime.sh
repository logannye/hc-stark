#!/usr/bin/env -S -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C TZ=UTC TINYZKP_CLEAN_LAUNCH=1 /bin/bash --noprofile --norc
# Install/update the host-level billing webhook Python runtime.
#
# The billing webhook is intentionally a host systemd unit, not a Compose
# service. Keep its dependencies isolated from the OS Python so Debian/Ubuntu
# PEP 668 protections cannot silently break deploys.
set -euo pipefail
[[ ${TINYZKP_CLEAN_LAUNCH:-} == 1 ]] || {
    /usr/bin/printf '%s\n' 'ERROR: invoke installer directly through its clean shebang' >&2
    exit 1
}
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
unset PYTHONPATH PYTHONHOME BASH_ENV ENV CDPATH LD_PRELOAD DYLD_INSERT_LIBRARIES \
    PIP_CONFIG_FILE PIP_INDEX_URL PIP_EXTRA_INDEX_URL PIP_TRUSTED_HOST \
    HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy || true
umask 077

REPO="/opt/hc-stark"
RUNTIME_ROOT="/var/lib/tinyzkp-runtime"
VENV="$RUNTIME_ROOT/billing-venv"
LOCK="$REPO/billing/requirements.lock"
WHEELHOUSE="$RUNTIME_ROOT/wheelhouse"

if [ ! -d "$REPO" ]; then
    echo "ERROR: repo directory not found: $REPO" >&2
    exit 1
fi

if [ ! -f "$LOCK" ] || ! /usr/bin/grep -q -- '--hash=sha256:' "$LOCK"; then
    echo "ERROR: reviewed hash-locked billing/requirements.lock is required" >&2
    exit 1
fi
/usr/bin/python3 - "$LOCK" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
forbidden = ("@", "://", "--index", "--extra-index", "--find-links", "-e ", "--editable")
if any(token in text for token in forbidden):
    raise SystemExit("ERROR: requirements.lock contains a direct URL or pip option")
logical = text.replace("\\\n", " ").splitlines()
pattern = re.compile(
    r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+!-]+"
    r"(?:\s+--hash=sha256:[0-9a-f]{64})+"
)
records = [line.strip() for line in logical if line.strip() and not line.lstrip().startswith("#")]
if not records or any(pattern.fullmatch(line) is None for line in records):
    raise SystemExit("ERROR: requirements.lock must contain only exact pins and SHA-256 hashes")
PY
if [ ! -d "$WHEELHOUSE" ]; then
    echo "ERROR: reviewed offline wheelhouse is required: $WHEELHOUSE" >&2
    exit 1
fi
WHEELHOUSE_IDENTITY="$(/usr/bin/stat -c '%u:%a' "$WHEELHOUSE")"
if [ "$WHEELHOUSE_IDENTITY" != "0:700" ] \
    || [ -n "$(/usr/bin/find "$WHEELHOUSE" -mindepth 1 \
        \( -type l -o ! -type f -o ! -user root -o -perm /222 -o ! -name '*.whl' \) \
        -print -quit)" ]; then
    echo "ERROR: offline wheelhouse must be root-owned mode 0700 with immutable regular wheels" >&2
    exit 1
fi

if [ ! -x /usr/bin/python3 ] || ! /usr/bin/python3 -m venv --help >/dev/null 2>&1; then
    echo "ERROR: reviewed /usr/bin/python3 with venv support is required" >&2
    exit 1
fi

/usr/bin/install -d -o root -g root -m 0755 "$RUNTIME_ROOT"
/bin/rm -rf "$VENV"
/usr/bin/python3 -m venv --copies "$VENV"
PIP_CONFIG_FILE=/dev/null PIP_NO_INDEX=1 "$VENV/bin/python" -m pip install \
    --isolated --quiet --no-index --require-hashes --only-binary=:all: \
    --find-links "$WHEELHOUSE" -r "$LOCK"

"$VENV/bin/python" - <<'PY'
import flask
import gunicorn
import psycopg
import pytest
import stripe

print("billing runtime OK")
PY

# Evidence hashes every resulting byte. Freeze the completed runtime so no
# package, entry point, pyvenv.cfg, or interpreter can change after preflight.
/usr/bin/find "$VENV" -type d -exec /bin/chmod 0555 {} +
/usr/bin/find "$VENV" -type f -perm /0111 -exec /bin/chmod 0555 {} +
/usr/bin/find "$VENV" -type f ! -perm /0111 -exec /bin/chmod 0444 {} +
