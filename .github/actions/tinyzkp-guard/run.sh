#!/usr/bin/env bash
set -euo pipefail

case "${TINYZKP_ACTION_RUN}" in
  true|false) ;;
  *)
    echo "run-proof must be true or false" >&2
    exit 11
    ;;
esac

if [[ -z "${TINYZKP_ACTION_GUARD}" || -z "${TINYZKP_ACTION_JOB}" ]]; then
  echo "guard-binary and job must be non-empty" >&2
  exit 11
fi

"${TINYZKP_ACTION_GUARD}" doctor --job "${TINYZKP_ACTION_JOB}"

if [[ "${TINYZKP_ACTION_RUN}" == "false" ]]; then
  exit 0
fi

if [[ -z "${TINYZKP_ACTION_REPORT}" ]]; then
  echo "report must be non-empty when run-proof is true" >&2
  exit 11
fi

"${TINYZKP_ACTION_GUARD}" run --job "${TINYZKP_ACTION_JOB}" > "${TINYZKP_ACTION_REPORT}"

if [[ -n "${TINYZKP_ACTION_BASELINE}" ]]; then
  "${TINYZKP_ACTION_GUARD}" policy check \
    --report "${TINYZKP_ACTION_REPORT}" \
    --baseline "${TINYZKP_ACTION_BASELINE}"
fi
