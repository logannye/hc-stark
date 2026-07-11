#!/usr/bin/env bash
set -euo pipefail

: "${TINYZKP_DATABASE_URL:?required}"
: "${TINYZKP_SECRET_PEPPER:?base64 secret pepper required}"
: "${TINYZKP_WORKER_ID:?required}"
: "${TINYZKP_WORKER_CREDENTIAL:?required}"

if [[ ! "$TINYZKP_WORKER_ID" =~ ^[a-zA-Z0-9_-]{1,64}$ ]]; then
  echo "invalid worker ID" >&2
  exit 2
fi

credential_hash=$(python3 - <<'PY'
import base64
import hashlib
import hmac
import os

pepper = base64.b64decode(os.environ["TINYZKP_SECRET_PEPPER"], validate=True)
if len(pepper) < 32:
    raise SystemExit("secret pepper is too short")
print(hmac.new(pepper, os.environ["TINYZKP_WORKER_CREDENTIAL"].encode(), hashlib.sha256).hexdigest())
PY
)

psql "$TINYZKP_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -v worker_id="$TINYZKP_WORKER_ID" -v credential_hash="$credential_hash" <<'SQL'
INSERT INTO beta_workers (worker_id, credential_hash, max_slots)
VALUES (:'worker_id', :'credential_hash', 4)
ON CONFLICT (worker_id) DO UPDATE SET
    credential_hash=EXCLUDED.credential_hash,
    max_slots=EXCLUDED.max_slots,
    enabled=true;
SQL

echo "registered worker $TINYZKP_WORKER_ID; the credential was not persisted by this script"

