# Retired: 2026-06-04 stop-the-bleeding deploy

This runbook is historical and **must not be executed**.

It described obsolete pull/build-in-place deployment, legacy proving,
self-serve Checkout, Compute meters, mutable package installation, direct
`npx` use, and old pull-request operations. Those actions conflict with the
current backend-recovery containment and could reactivate unsafe or billable
legacy surfaces.

Use the authoritative
[`expedited-revenue-launch.md`](expedited-revenue-launch.md) runbook instead.
It requires one reviewed release identity, immutable maintenance images,
transactional host and Pages deployment, exact-ID Stripe containment,
no-email evaluation operations, and post-deploy fail-closed canaries.

The previous instructions remain available only through Git history for
incident archaeology.
