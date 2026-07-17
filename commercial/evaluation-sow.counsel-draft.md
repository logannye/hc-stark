# TinyZKP Memory-Bounded Prover Evaluation — MSA/SOW Draft

> **DRAFT FOR COUNSEL REVIEW. NOT LEGAL ADVICE. DO NOT SIGN OR SEND UNTIL
> COUNSEL FILLS THE BRACKETED TERMS AND APPROVES THIS FORM.**

## 1. Parties and order

- Provider legal name: `[COUNSEL: PROVIDER ENTITY]`
- Customer legal name: `[CUSTOMER ENTITY]`
- Effective date: `[DATE]`
- Agreement ID: `[AGREEMENT_ID]`
- Offer options: Founding Evaluation — $15,000; Standard Evaluation — $40,000.
- Selected offer and fixed fee: `[COUNSEL: SELECT EXACTLY ONE OFFER]`

This statement of work (SOW), the attached acceptance matrix, and the approved
master services terms together form the agreement. If they conflict, counsel
must specify the order of precedence here: `[COUNSEL: ORDER OF PRECEDENCE]`.

## 2. Fixed scope

TinyZKP will evaluate exactly one pinned Plonky3 workload against one agreed
conventional baseline on one agreed baseline host. The workload digest,
software/profile versions, baseline command, resource policy, and acceptance
criteria are fixed in the attached acceptance matrix before work begins.

- The Founding Evaluation is scheduled for two weeks and capped at eight
  person-days. The Standard Evaluation is scheduled for three weeks and capped
  at fifteen person-days.
- Selected scheduled period: `[COUNSEL: INSERT SELECTED OFFER DURATION]`
- Selected engineering cap: `[COUNSEL: INSERT SELECTED OFFER CAP]`
- Additional workloads, environments, formats, integrations, meetings, or
  engineering time require a written change order signed by both parties.

## 3. Deliverables

Subject to technical feasibility within the fixed scope, TinyZKP will deliver:

1. A conventional baseline report.
2. A resource-bounded adapter prototype for the pinned workload.
3. The official verifier result.
4. Raw and summarized RAM, wall-time, CPU, I/O, scratch, proof-size, and
   verification measurements.
5. Reproduction instructions, known limitations, and a production
   recommendation.

This is an engineering evaluation, not hosted proving, production access, an
audit, a security certification, or an SLA. TinyZKP does not guarantee that a
target RAM, time, performance, or production-suitability result will be met.

## 4. Start conditions and fees

Work starts only after all of the following are complete:

- both parties sign the agreement;
- the customer pays the 50% deposit;
- the workload digest and acceptance matrix are frozen;
- the baseline host and reproduction command are confirmed; and
- the customer provides the non-sensitive materials in Section 5.

Invoices use Stripe Invoicing with `send_invoice`, net 15:

- Deposit: 50% of the fixed fee, invoiced after signature and before work.
- Delivery: remaining 50%, invoiced only after written delivery acceptance
  under Section 6.

Taxes, expenses, refunds, late payments, and cancellation treatment:
`[COUNSEL: COMPLETE THESE TERMS]`.

## 5. Customer materials and data boundary

The customer supplies a reproducible, non-sensitive deterministic input
generator, public corpus, or separately approved test corpus. The customer
must not transfer witnesses, credentials, private keys, personal/customer
data, private source code, production secrets, or regulated data through the
TinyZKP website or application form. Any broader data transfer requires a
separate written security and data addendum before transfer.

The customer represents that it has the right to provide the evaluation
materials and instructions. TinyZKP may reject or securely delete materials
that fall outside this boundary.

## 6. Acceptance

TinyZKP will provide written notice that the deliverables are ready. The
customer will run or review the attached acceptance matrix and respond in
writing within `[COUNSEL: ACCEPTANCE PERIOD]` with either:

- acceptance; or
- a specific, reproducible list of material deviations from the frozen matrix.

TinyZKP will address in-scope deviations within the remaining engineering cap.
Changes to the workload, baseline, host, versions, targets, or matrix are not
defects and require a change order. Deemed acceptance, rejection, cure, and
dispute terms: `[COUNSEL: COMPLETE]`.

## 7. Intellectual property and open-source contributions

Each party retains its pre-existing technology and materials. TinyZKP retains
the existing MIT-licensed core, generally applicable improvements to that
core, benchmark infrastructure, storage/transform techniques, and reusable
adapter interfaces. TinyZKP may contribute generally applicable improvements
to the MIT core.

Customer-specific confidential code and customer-owned pre-existing materials
remain customer materials. Ownership or licensing of a customer-specific
adapter, and the process for separating confidential customer logic from
generally applicable MIT-core improvements, must be selected here before work:
`[COUNSEL/CUSTOMER: ADAPTER OWNERSHIP AND LICENSE]`.

No customer name, benchmark, acceptance record, or result may be published
without written approval. A release-gate design-partner record may be retained
privately with no witness data.

## 8. Confidentiality, security, and deletion

Confidentiality obligations, security standard, incident notice, return or
deletion, and permitted subprocessors: `[COUNSEL: COMPLETE OR INCORPORATE MSA]`.

The public application is retained for at most twelve months unless the
agreement or law requires otherwise. Evaluation artifacts follow the retention
schedule in the acceptance matrix.

## 9. Warranties, disclaimers, liability, termination, and law

`[COUNSEL: ADD APPROVED WARRANTIES, DISCLAIMERS, INDEMNITIES, LIABILITY CAP,
TERMINATION RIGHTS, SURVIVAL, GOVERNING LAW, VENUE, AND GENERAL TERMS.]`

## 10. Signatures

| TinyZKP provider | Customer |
|---|---|
| Name: `[NAME]` | Name: `[NAME]` |
| Title: `[TITLE]` | Title: `[TITLE]` |
| Signature: `[SIGNATURE]` | Signature: `[SIGNATURE]` |
| Date: `[DATE]` | Date: `[DATE]` |

Attachment: completed `acceptance-matrix.template.json`, renamed with the
agreement ID and hashed before signature.
