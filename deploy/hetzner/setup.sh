#!/usr/bin/env -S -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C TZ=UTC TINYZKP_CLEAN_LAUNCH=1 /bin/bash --noprofile --norc
# TinyZKP host filesystem bootstrap only.
#
# RELEASE AUTHORITY: NONE. This script never installs mutable "latest"
# packages, writes live Caddy/systemd/cron configuration, enables/reloads/starts
# a service, deploys a container, or authorizes a TinyZKP release. Provision the
# reviewed Debian 12 base image and host packages separately. Only deploy.sh may
# consume production preflight evidence and open a deployment transaction.
[[ ${TINYZKP_CLEAN_LAUNCH:-} == 1 ]] || {
  /usr/bin/printf '%s\n' 'ERROR: invoke setup.sh directly through its clean shebang' >&2
  exit 1
}
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset PYTHONPATH PYTHONHOME NODE_OPTIONS BASH_ENV ENV CDPATH GIT_DIR GIT_WORK_TREE \
  LD_PRELOAD DYLD_INSERT_LIBRARIES HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy || true

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
  echo "ERROR: filesystem bootstrap requires root" >&2
  exit 1
fi
if [ "$#" -ne 0 ]; then
  echo "ERROR: setup.sh accepts no package, deploy, or service-start options" >&2
  exit 1
fi

OS_ID="$(/usr/bin/sed -n 's/^ID=//p' /usr/lib/os-release | /usr/bin/tr -d '\"' | /usr/bin/head -n 1)"
OS_VERSION_ID="$(/usr/bin/sed -n 's/^VERSION_ID=//p' /usr/lib/os-release | /usr/bin/tr -d '\"' | /usr/bin/head -n 1)"
if [ "$OS_ID" != debian ] || [ "$OS_VERSION_ID" != 12 ] \
    || [ "$(/usr/bin/dpkg --print-architecture)" != amd64 ]; then
  echo "ERROR: TinyZKP production bootstrap requires Debian 12 amd64" >&2
  exit 1
fi

echo "==> TinyZKP bootstrap-only filesystem preparation"
echo "    RELEASE AUTHORITY: NONE; mutable package installs are outside this script"
for executable in /usr/bin/docker /usr/bin/caddy /usr/bin/python3 /usr/bin/flock; do
  if [ ! -x "$executable" ]; then
    echo "ERROR: reviewed base-image provisioning must provide $executable" >&2
    echo "       Do not use setup.sh to install an unpinned latest package" >&2
    exit 1
  fi
done

# The repository must already be materialized at the fixed path. Its immutable
# source identity is checked later by production_launch_preflight.py.
if [ ! -f /opt/hc-stark/billing/backup_env_exec.py ] \
    || [ -L /opt/hc-stark/billing/backup_env_exec.py ]; then
  echo "ERROR: materialize the candidate repository at /opt/hc-stark first" >&2
  exit 1
fi

if ! /usr/bin/getent group tinyzkp-billing >/dev/null; then
  /usr/sbin/groupadd --system tinyzkp-billing
fi
if ! /usr/bin/id -u tinyzkp-billing >/dev/null 2>&1; then
  /usr/sbin/useradd --system --gid tinyzkp-billing --home-dir /nonexistent \
    --shell /usr/sbin/nologin tinyzkp-billing
fi
SERVICE_UID="$(/usr/bin/id -u tinyzkp-billing)"
SERVICE_GID="$(/usr/bin/id -g tinyzkp-billing)"

/usr/bin/install -d -o root -g root -m 0755 /var/lib/tinyzkp-runtime
/usr/bin/install -d -o root -g root -m 0700 \
  /var/lib/tinyzkp-runtime/wheelhouse \
  /var/lib/tinyzkp-private \
  /var/lib/tinyzkp-private/billing \
  /var/lib/tinyzkp-private/contracts \
  /var/lib/tinyzkp-private/deploy \
  /var/lib/tinyzkp-private/deploy/consumed \
  /var/lib/tinyzkp-private/backup \
  /var/lib/tinyzkp-preflight-pycache \
  /opt/hc-stark/backups
/usr/bin/install -d -o root -g tinyzkp-billing -m 0710 \
  /var/lib/tinyzkp-backup-staging
/usr/bin/python3 /opt/hc-stark/billing/backup_env_exec.py \
  ensure-service-data-root --path /opt/hc-stark/data \
  --uid "$SERVICE_UID" --gid "$SERVICE_GID"

BACKUP_LOADER_TOKEN=/var/lib/tinyzkp-private/backup/loader-token
if [ ! -e "$BACKUP_LOADER_TOKEN" ]; then
  /usr/bin/python3 /opt/hc-stark/billing/backup_env_exec.py \
    create-loader-token --path "$BACKUP_LOADER_TOKEN"
else
  /usr/bin/python3 /opt/hc-stark/billing/backup_env_exec.py \
    validate-loader-token --path "$BACKUP_LOADER_TOKEN"
fi

echo "==> Bootstrap complete; no package, firewall, DNS, cron, unit, or service was changed"
echo "    Next: install the reviewed offline billing runtime per billing/RUNTIME.md"
echo "    Then issue complete production evidence and run deploy/hetzner/deploy.sh"
echo "    deploy.sh will reject missing evidence and transact every live mutation"
