#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "$1" >&2
  exit 11
}

require_value() {
  local name="$1"
  local value="$2"
  [[ -n "${value}" ]] || fail "${name} must be non-empty"
}

require_relative_path() {
  local name="$1"
  local value="$2"
  require_value "${name}" "${value}"
  [[ "${value}" != /* && "${value}" != *".."* ]] \
    || fail "${name} must be a traversal-free relative path"
}

require_paid_runner() {
  [[ "${RUNNER_OS:-}" == "Linux" ]] \
    || fail "paid operations require a Linux runner"
  [[ "${RUNNER_ARCH:-}" == "X64" ]] \
    || fail "paid operations require an x86-64 runner"
  [[ "${RUNNER_ENVIRONMENT:-}" == "self-hosted" ]] \
    || fail "paid operations require a persistent self-hosted runner"
}

run_guard_result() {
  local report_dir
  local report_name
  report_dir="$(dirname -- "${TINYZKP_ACTION_REPORT}")"
  report_name="$(basename -- "${TINYZKP_ACTION_REPORT}")"
  mkdir -p -- "${report_dir}"
  umask 077
  local temporary="${report_dir}/.${report_name}.tinyzkp-${GITHUB_RUN_ID:-$$}-${RANDOM}.tmp"
  trap 'rm -f -- "${temporary}"' EXIT

  set +e
  "$@" > "${temporary}"
  local command_status=$?
  set -e

  if [[ "${command_status}" -eq 0 || "${command_status}" -eq 13 ]]; then
    local required_status="succeeded"
    [[ "${command_status}" -eq 13 ]] && required_status="interrupted"
    if ! python3 "${TINYZKP_ACTION_PATH}/validate-result.py" \
      job-result "${required_status}" "${temporary}"; then
      fail "Guard emitted an invalid JobResultV1"
    fi
    mv -f -- "${temporary}" "${TINYZKP_ACTION_REPORT}"
    trap - EXIT
    return "${command_status}"
  fi

  if python3 "${TINYZKP_ACTION_PATH}/validate-result.py" error-envelope unused "${temporary}"; then
    cat -- "${temporary}"
  fi
  rm -f -- "${temporary}"
  trap - EXIT
  return "${command_status}"
}

case "${TINYZKP_ACTION_OPERATION}" in
  doctor)
    require_value "engine-binary" "${TINYZKP_ACTION_ENGINE}"
    require_relative_path "job" "${TINYZKP_ACTION_JOB}"
    exec "${TINYZKP_ACTION_ENGINE}" doctor --job "${TINYZKP_ACTION_JOB}"
    ;;
  run)
    require_paid_runner
    require_value "guard-binary" "${TINYZKP_ACTION_GUARD}"
    require_relative_path "job" "${TINYZKP_ACTION_JOB}"
    require_relative_path "report" "${TINYZKP_ACTION_REPORT}"
    run_guard_result "${TINYZKP_ACTION_GUARD}" run \
      --job "${TINYZKP_ACTION_JOB}"
    ;;
  resume)
    require_paid_runner
    require_value "guard-binary" "${TINYZKP_ACTION_GUARD}"
    require_relative_path "job-dir" "${TINYZKP_ACTION_JOB_DIR}"
    require_relative_path "report" "${TINYZKP_ACTION_REPORT}"
    run_guard_result "${TINYZKP_ACTION_GUARD}" resume \
      --job-dir "${TINYZKP_ACTION_JOB_DIR}"
    ;;
  policy)
    require_paid_runner
    require_value "guard-binary" "${TINYZKP_ACTION_GUARD}"
    require_relative_path "report" "${TINYZKP_ACTION_REPORT}"
    require_relative_path "baseline" "${TINYZKP_ACTION_BASELINE}"
    exec "${TINYZKP_ACTION_GUARD}" policy check \
      --report "${TINYZKP_ACTION_REPORT}" \
      --baseline "${TINYZKP_ACTION_BASELINE}"
    ;;
  *)
    fail "operation must be one of: doctor, run, resume, policy"
    ;;
esac
