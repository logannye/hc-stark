#!/usr/bin/env bash
# Pull free-tier signups from the last 14 days for user-interview outreach.
#
# Usage:
#     scripts/recruit_interview_candidates.sh
#
# Output: TSV to stdout with email, plan, signup_age_days. Pipe into your
# tracking sheet of choice.
#
# Requires DATABASE_URL pointing at the production billing DB. Read-only
# query; safe to run from any host with VPN/SSH access.

set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
    echo "DATABASE_URL must be set (e.g., postgresql://user:pass@host/db)" >&2
    exit 2
fi

psql "$DATABASE_URL" --no-align --tuples-only --field-separator='	' <<'SQL'
SELECT
    email,
    plan,
    EXTRACT(DAY FROM (now() - created_at))::int AS signup_age_days
FROM tenants
WHERE plan = 'free'
  AND created_at > now() - interval '14 days'
  AND email NOT LIKE '%@tinyzkp.com'
ORDER BY created_at DESC
LIMIT 50;
SQL
