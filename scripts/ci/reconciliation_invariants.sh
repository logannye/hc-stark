#!/usr/bin/env bash
# Run the quarantined historical containment/recovery diagnostic.
# This wrapper is not invoked by required CI and is not Guard launch authority.
#
# The pre-recovery agent-SaaS reconciliation suite was intentionally removed:
# it required legacy checkout, receipt-sharing, badge, SEO, ChatGPT-app, growth
# cron, and public proving surfaces that containment must keep unavailable.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

exec python3 scripts/ci/recovery_reconciliation_invariants.py "$@"
