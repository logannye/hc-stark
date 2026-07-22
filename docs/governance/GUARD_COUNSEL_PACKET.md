# TinyZKP Guard counsel review packet

Status: optional advisory intake packet. It is not launch authority. Checkout
is governed by LN Holdings owner approval of the exact seller facts and legal
document digests; counsel review may inform that approval but is not mandatory.

## Seller facts the LN Holdings owner must confirm

| Fact | Required value |
|---|---|
| Exact legal seller name | UNCONFIRMED |
| Entity type and formation jurisdiction | UNCONFIRMED |
| Principal business address | UNCONFIRMED |
| Notice address and method | UNCONFIRMED |
| Privacy-controller identity and contact | UNCONFIRMED |
| Governing law and venue | UNCONFIRMED |
| Tax/export/sanctions posture | UNCONFIRMED |
| Support contact | `support@tinyzkp.com` — delivery unverified |
| Security contact | `security@tinyzkp.com` — delivery unverified |
| Merchant of record | Lemon Squeezy — seller approval pending |

Do not infer any seller fact from a repository owner, domain registration,
payment account, commit author, or email address.

## Fixed product facts

- Product: TinyZKP Guard, proprietary object-code software used on
  customer-controlled compute.
- Open component: the TinyZKP Community engine, verifier, schemas, doctor,
  reference workloads, and public evidence remain MIT licensed.
- Supported production target: Linux x86-64 and exactly
  `tinyzkp-p3-goldilocks-v1`.
- Scope: one legal organization, unlimited internal users and runners.
- Price: $499 monthly or $4,990 annually; annual is the default.
- No free trial, coupon, add-on, enterprise variant, usage fee, hosted compute,
  SLA, onboarding, consulting, custom AIR work, private branch, or support
  response-time commitment.
- A current subscription permits activation of a qualified release. An exact
  release activated while the subscription is current continues working
  locally after cancellation or expiration.
- A current subscription is required to activate a later release.
- Redistribution, sublicensing, resale, OEM embedding, service-bureau use, and
  sharing Guard artifacts or license material are outside the standard grant.
- Proof workloads, witnesses, traces, checkpoints, scratch, and proofs stay on
  customer infrastructure.
- Guard contacts Lemon Squeezy during activation with the license key and Guard
  version. After activation, doctor, run, resume, policy, diagnostics, and
  verification are offline.

## Commercial lifecycle for review

- Lemon Squeezy presents the binding terms at hosted checkout and acts as
  merchant of record.
- Subscriptions renew automatically until canceled. Cancellation takes effect
  at the end of the paid term.
- The hosted customer portal handles receipts, invoices, payment changes,
  renewal, dunning, cancellation, and eligible refunds.
- Default refund posture: no prorated or discretionary refund for an elapsed
  billing period, subject to mandatory law and merchant requirements.
- Existing activated releases are not remotely revoked. Cancellation prevents
  activation of later releases.
- Published release artifacts remain immutable because checkpoints are bound
  to the exact release.

## Privacy and processor map

| Activity | Data | Operator/processor |
|---|---|---|
| Static website delivery | Ordinary request and security metadata | Cloudflare Pages |
| Privacy-preserving site analytics | Aggregated traffic data; no TinyZKP customer database | Cloudflare Web Analytics |
| Checkout and subscription | Identity, billing, tax, payment, receipt, renewal, cancellation, refund | Lemon Squeezy |
| License activation | License key, Guard version, ordinary request metadata | Lemon Squeezy and network providers |
| Public defect reports | User-submitted minimal reproduction and redacted support report | GitHub |
| Private vulnerability reports | Reporter contact and security report | GitHub |
| Local proof operation | Workload, witness, trace, checkpoint, scratch, proof | Customer only |

TinyZKP.com has no custom contact form, proof API, customer account, event
collector, billing database, or hosted proof-data path.

## Documents requiring owner approval

The LN Holdings owner must supply or approve final production versions of:

1. EULA, including seller identity, grant, restrictions, warranty disclaimer,
   liability cap, termination, export/sanctions, notices, and governing law.
2. Subscription/website terms, including renewal, cancellation, merchant-of-
   record relationship, order of precedence, and acceptance record.
3. Privacy notice, including controller, purposes/bases, categories,
   processors, transfers, retention, deletion, and applicable rights.
4. Refund policy aligned with mandatory law and Lemon Squeezy requirements.
5. Third-party/open-source notices and confirmation that the Guard EULA does
   not override the MIT engine or dependency licenses.

## Approval handoff

1. Replace every `UNCONFIRMED` fact with owner-confirmed information.
2. Apply approved text to the production legal pages and release package.
3. Render and review the exact customer-facing pages and checkout presentation.
4. Record the approval date, approver, release date, and SHA-256 digest of every
   final legal artifact outside the public repository where identity must
   remain private.
5. Populate only those reviewed digests and statuses in
   `GuardLaunchEvidenceV2`.
6. Run the launch gate and confirm that legal evidence passes without weakening
   any other gate.

Repository text or this packet alone is not approval. The accepted machine
record is a strict owner-signed `LegalApprovalEvidenceV1` bound to the exact
seller facts, release date, and repository document digests. If counsel is
consulted, preserve that advice privately as advisory support for the owner's
decision; never claim counsel approval unless it actually occurred.
