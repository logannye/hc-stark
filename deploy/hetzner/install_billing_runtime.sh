#!/usr/bin/env -S -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C TZ=UTC TINYZKP_CLEAN_LAUNCH=1 /bin/bash --noprofile --norc
# Install/update the host-level billing webhook Python runtime.
#
# The billing webhook is intentionally a host systemd unit, not a Compose
# service. The only reviewed dependency target is Debian 12 x86-64 CPython
# 3.11; isolation also keeps Debian PEP 668 protections intact.
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
REQUIREMENTS="$REPO/billing/requirements.txt"
LOCK="$REPO/billing/requirements.lock"
BOOTSTRAP_LOCK="$REPO/billing/requirements-bootstrap.lock"
PROFILE="$REPO/billing/runtime-profile.json"
MANIFEST="$REPO/billing/wheelhouse-manifest.json"
HOST_PROVENANCE="$REPO/billing/host-runtime-provenance.json"
RUNTIME_LOCK_TOOL="$REPO/billing/runtime_lock.py"
WHEELHOUSE="$RUNTIME_ROOT/wheelhouse"
STAGING="$RUNTIME_ROOT/.billing-venv.staging"
ROLLBACK="$RUNTIME_ROOT/.billing-venv.rollback"
TRANSACTION_STARTED=0
ACTIVATED=0
HAD_PREVIOUS=0

if [ "$(/usr/bin/id -u)" != 0 ]; then
    echo "ERROR: billing runtime installer must run as root" >&2
    exit 1
fi

cleanup_runtime_install() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$result" -ne 0 ]; then
        if [ "$ACTIVATED" = 1 ] && [ -d "$VENV" ] && [ ! -L "$VENV" ]; then
            /bin/rm -rf -- "$VENV"
        fi
        if [ "$HAD_PREVIOUS" = 1 ] && [ -d "$ROLLBACK" ] && [ ! -L "$ROLLBACK" ]; then
            if [ -e "$VENV" ] || [ -L "$VENV" ]; then
                echo "ERROR: cannot safely restore the prior billing runtime" >&2
                exit 1
            fi
            /bin/mv -- "$ROLLBACK" "$VENV"
        fi
    elif [ "$result" -eq 0 ] && [ "$HAD_PREVIOUS" = 1 ]; then
        /bin/rm -rf -- "$ROLLBACK"
    fi
    if [ "$TRANSACTION_STARTED" = 1 ] && [ -d "$STAGING" ] && [ ! -L "$STAGING" ]; then
        /bin/rm -rf -- "$STAGING"
    fi
    exit "$result"
}
trap cleanup_runtime_install EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ ! -d "$REPO" ]; then
    echo "ERROR: repo directory not found: $REPO" >&2
    exit 1
fi

for trusted_directory in / /opt "$REPO" "$REPO/billing"; do
    if [ ! -d "$trusted_directory" ] || [ -L "$trusted_directory" ] \
        || [ "$(/usr/bin/stat -c '%u' "$trusted_directory")" != 0 ] \
        || [ -n "$(/usr/bin/find "$trusted_directory" -maxdepth 0 -perm /022 -print -quit)" ]; then
        echo "ERROR: billing runtime source parent must be a root-owned non-writable real directory: $trusted_directory" >&2
        exit 1
    fi
done

for required in \
    "$REQUIREMENTS" \
    "$LOCK" \
    "$BOOTSTRAP_LOCK" \
    "$PROFILE" \
    "$MANIFEST" \
    "$HOST_PROVENANCE" \
    "$RUNTIME_LOCK_TOOL"; do
    if [ ! -f "$required" ] || [ -L "$required" ] \
        || [ "$(/usr/bin/stat -c '%u' "$required")" != 0 ] \
        || [ "$(/usr/bin/stat -c '%h' "$required")" != 1 ] \
        || [ -n "$(/usr/bin/find "$required" -maxdepth 0 -perm /022 -print -quit)" ]; then
        echo "ERROR: reviewed billing runtime input must be a root-owned non-writable private regular file: $required" >&2
        exit 1
    fi
done

if [ -e "$RUNTIME_ROOT" ] || [ -L "$RUNTIME_ROOT" ]; then
    if [ ! -d "$RUNTIME_ROOT" ] || [ -L "$RUNTIME_ROOT" ] \
        || [ "$(/usr/bin/stat -c '%u' "$RUNTIME_ROOT")" != 0 ] \
        || [ -n "$(/usr/bin/find "$RUNTIME_ROOT" -maxdepth 0 -perm /022 -print -quit)" ]; then
        echo "ERROR: runtime root must be a root-owned non-writable real directory" >&2
        exit 1
    fi
else
    /usr/bin/install -d -o root -g root -m 0755 "$RUNTIME_ROOT"
fi
if [ ! -x /usr/bin/flock ]; then
    echo "ERROR: /usr/bin/flock is required for an exclusive billing runtime transaction" >&2
    exit 1
fi
# Lock the already-validated directory inode itself. A separately created lock
# pathname could be replaced between first-run creation and open by another
# concurrent root invocation, allowing both installers to lock different files.
exec 9<"$RUNTIME_ROOT"
if ! /usr/bin/flock -n 9; then
    echo "ERROR: another billing runtime installation is already active" >&2
    exit 1
fi
for transient in "$STAGING" "$ROLLBACK"; do
    if [ -e "$transient" ] || [ -L "$transient" ]; then
        echo "ERROR: stale billing runtime transaction path requires operator review: $transient" >&2
        exit 1
    fi
done
TRANSACTION_STARTED=1
if [ -e "$VENV" ] || [ -L "$VENV" ]; then
    if [ ! -d "$VENV" ] || [ -L "$VENV" ] \
        || [ "$(/usr/bin/stat -c '%u' "$VENV")" != 0 ] \
        || [ -n "$(/usr/bin/find "$VENV" -maxdepth 0 -perm /022 -print -quit)" ]; then
        echo "ERROR: existing billing venv is unsafe; refusing replacement" >&2
        exit 1
    fi
fi
cd "$RUNTIME_ROOT"

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

if [ ! -x /usr/bin/python3 ] || ! /usr/bin/python3 -I -S -m venv --help >/dev/null 2>&1; then
    echo "ERROR: reviewed /usr/bin/python3 with venv support is required" >&2
    exit 1
fi

# The wheel lock is intentionally not portable. Refuse Ubuntu, non-x86_64,
# CPython 3.10/3.12, or any other plausible but unreviewed runtime before
# reading a wheel or replacing the existing venv.
/usr/bin/python3 -I -S "$RUNTIME_LOCK_TOOL" verify-host \
    --profile "$PROFILE" --os-release /usr/lib/os-release
/usr/bin/python3 -I -S "$RUNTIME_LOCK_TOOL" verify-host-provenance \
    --profile "$PROFILE" --provenance "$HOST_PROVENANCE"
/usr/bin/python3 -I -S "$RUNTIME_LOCK_TOOL" verify-metadata \
    --profile "$PROFILE" \
    --requirements "$REQUIREMENTS" \
    --lock "$LOCK" \
    --bootstrap-lock "$BOOTSTRAP_LOCK" \
    --manifest "$MANIFEST"
BOOTSTRAP_WHEEL="$(/usr/bin/python3 -I -S "$RUNTIME_LOCK_TOOL" bootstrap-path \
    --profile "$PROFILE" \
    --requirements "$REQUIREMENTS" \
    --lock "$LOCK" \
    --bootstrap-lock "$BOOTSTRAP_LOCK" \
    --manifest "$MANIFEST" \
    --wheelhouse "$WHEELHOUSE" \
    --production-permissions)"
if [ -z "$BOOTSTRAP_WHEEL" ] || [ ! -f "$BOOTSTRAP_WHEEL" ] || [ -L "$BOOTSTRAP_WHEEL" ]; then
    echo "ERROR: verified bootstrap wheel is unavailable" >&2
    exit 1
fi

/bin/mkdir --mode=0700 "$STAGING"
/usr/bin/python3 -I -S -m venv --copies --without-pip "$STAGING"
/bin/chmod 0700 "$STAGING"
PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$BOOTSTRAP_WHEEL" \
    PIP_CONFIG_FILE=/dev/null PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    "$STAGING/bin/python" -S -m pip install \
    --isolated --quiet --no-index --require-hashes --only-binary=:all: \
    --no-compile --find-links "$WHEELHOUSE" -r "$LOCK"

PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$STAGING/bin/python" -I \
    "$RUNTIME_LOCK_TOOL" verify-installed --lock "$LOCK"
/bin/rm -f -- \
    "$STAGING/bin/activate" \
    "$STAGING/bin/activate.csh" \
    "$STAGING/bin/activate.fish" \
    "$STAGING/bin/Activate.ps1"
/usr/bin/python3 -I -S "$RUNTIME_LOCK_TOOL" relocate-venv \
    --staging "$STAGING" --destination "$VENV"

# --copies still creates convenience symlinks on some Debian venv builds.
# Production uses only bin/python and generated console scripts; remove every
# link so the byte identity gate has one private regular file per executable.
/usr/bin/find "$STAGING" -type l -delete
if [ -n "$(/usr/bin/find "$STAGING" -type l -print -quit)" ] \
    || [ -n "$(/usr/bin/find "$STAGING" \( -name '*.pyc' -o -name '*.pth' \) -print -quit)" ]; then
    echo "ERROR: billing runtime contains a symlink, bytecode, or path hook" >&2
    exit 1
fi

# Evidence hashes every resulting byte. Freeze the completed runtime so no
# package, entry point, pyvenv.cfg, or interpreter can change after preflight.
/usr/bin/find "$STAGING" -type d -exec /bin/chmod 0555 {} +
/usr/bin/find "$STAGING" -type f -perm /0111 -exec /bin/chmod 0555 {} +
/usr/bin/find "$STAGING" -type f ! -perm /0111 -exec /bin/chmod 0444 {} +

if [ -d "$VENV" ]; then
    HAD_PREVIOUS=1
    /bin/mv -- "$VENV" "$ROLLBACK"
fi
ACTIVATED=1
/bin/mv -- "$STAGING" "$VENV"

# Re-open the final path after activation. Any failure rolls the previous venv
# back before this installer exits.
PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$VENV/bin/python" -I \
    "$RUNTIME_LOCK_TOOL" verify-installed --lock "$LOCK"
for entry_point in flask gunicorn py.test pytest; do
    first_line="$(/usr/bin/head -n 1 "$VENV/bin/$entry_point")"
    if [ "$first_line" != "#!$VENV/bin/python" ]; then
        echo "ERROR: relocated billing entry point is invalid: $entry_point" >&2
        exit 1
    fi
done
