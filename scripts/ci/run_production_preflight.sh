#!/usr/bin/env -S -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C TZ=UTC TINYZKP_CLEAN_LAUNCH=1 /bin/bash --noprofile --norc
# Enter the production preflight before Python can import repo-local bytecode.
set -euo pipefail

[[ ${TINYZKP_CLEAN_LAUNCH:-} == 1 ]] || {
    /usr/bin/printf '%s\n' 'ERROR: invoke preflight wrapper directly through its clean shebang' >&2
    exit 1
}

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
REPO=/opt/hc-stark
PYTHON=/var/lib/tinyzkp-runtime/billing-venv/bin/python
PYCACHE=/var/lib/tinyzkp-preflight-pycache
GIT=/usr/bin/git

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    echo "ERROR: production preflight wrapper requires root" >&2
    exit 1
fi
if [ -L "$PYCACHE" ] || [ ! -d "$PYCACHE" ] \
    || [ "$(/usr/bin/stat -c '%u:%g:%a' "$PYCACHE")" != 0:0:700 ] \
    || [ -n "$(/usr/bin/find "$PYCACHE" -mindepth 1 -print -quit)" ]; then
    echo "ERROR: production pycache prefix must be an empty root-owned mode-0700 directory" >&2
    exit 1
fi
if [ ! -x "$PYTHON" ] || [ ! -x "$GIT" ]; then
    echo "ERROR: fixed production Python and Git executables are required" >&2
    exit 1
fi
cd "$REPO"

# Reject index hints that can hide worktree changes and any ignored/untracked
# Python/native import artifact that could execute before Python validates HEAD.
if [ -n "$("$GIT" ls-files --others --exclude-standard -- \
        Dockerfile Cargo.toml Cargo.lock rust-toolchain.toml README.md crates docs scripts)" ] \
    || [ -n "$("$GIT" ls-files --others --ignored --exclude-standard -- \
        Dockerfile Cargo.toml Cargo.lock rust-toolchain.toml README.md crates docs scripts)" ] \
    || "$GIT" ls-files -v | /usr/bin/grep -Eq '^[a-z]' \
    || "$GIT" ls-files -t | /usr/bin/grep -Eq '^S ' \
    || "$GIT" ls-files --others --exclude-standard \
        | /usr/bin/grep -Eq '(^|/)(__pycache__/|[^/]+\.(py[co]?|pth|so|dylib)$)' \
    || "$GIT" ls-files --others --ignored --exclude-standard \
        | /usr/bin/grep -Eq '(^|/)(__pycache__/|[^/]+\.(py[co]?|pth|so|dylib)$)'; then
    echo "ERROR: deployment source contains hidden index state or executable artifacts" >&2
    exit 1
fi

CF_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CF_ACCOUNT="${CLOUDFLARE_ACCOUNT_ID:-}"
exec /usr/bin/env -i \
    PATH="$PATH" HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX="$PYCACHE" \
    PYTEST_ADDOPTS='-p no:cacheprovider' GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
    GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 GIT_OPTIONAL_LOCKS=0 \
    RCLONE_CONFIG=/var/lib/tinyzkp-private/backup/rclone.conf \
    CLOUDFLARE_API_TOKEN="$CF_TOKEN" CLOUDFLARE_ACCOUNT_ID="$CF_ACCOUNT" \
    "$PYTHON" -B scripts/ci/production_launch_preflight.py "$@"
