---
id: adr_llull-buzz-003_buzz-003_recovery-and-assurance
entity: document
subtype: adr
name: ADR 003 - Recoverable operations and bounded assurance
author: ChatGPT, owner-directed synthesis
date: 2026-09-18
refinement: 0.2
origin: synthesis
form: draft
audience: public
product: llull-buzz
status: proposed
decision_date: null
decision_owner: Josue Guevara
approval_ref: null
decision_class: Project-scoped
quality_attributes: [security, integrity, interoperability, recoverability, modifiability]
accepted_ceilings: []
deferred_capability: []
source_basis: ["../../discovery/SOURCE-REGISTER.md#owner-mandate", "../../discovery/SOURCE-REGISTER.md#pinned-primary-source"]
implementation_binding: ["../../../.scratch/llull-buzz/issues/02-realization-plan.md", "../../bootstrap/INITIAL-PROFILE.md", "../contracts/WIRE-PROFILE.md"]
review_triggers: [contract-change, authority-change, dependency-version-change, new-surface, recovery-failure]
supersedes: []
superseded_by: []
proposed_amendments: []
component_refs: [owned.delivery-ledger, owned.task-supervisor, slot.persistence, slot.runtime-image, lib.sqlx, service.media, service.presence]
mandatory_uat_refs: [BZ-UAT03, BZ-UAT05]
conformance_status: not-assessed-for-proposed-delta
ecosystem_placement:
  motivating_design_rationale: Make interruption and upgrade recoverable without treating conversation or execution logs as business authority.
  bears_on_quality_attribute_scenarios: [authorized-completion, denied-effect-isolation, interruption-recovery]
  implements_asrs: [BZ-CMT10, BZ-CMT11, BZ-CMT12, BZ-CMT13, BZ-CMT14]
  affects_architecture_views: [module, runtime, security, API, evidence]
  related_adrs: [depends-on ADR-001, depends-on ADR-002]
---

# ADR 003 - Recoverable operations and bounded assurance

## Status

Proposed revision 0.2. No implementation, restore exercise, security attestation or human verdict.

## Context

Native sessions and process-local limits do not durably own accepted tasks, cumulative authority or
publication uncertainty. A crash, child task or replay cannot renew a grant or repeat a committed
effect. Each business/fiscal/mail provider remains the unique owner of its own results and evidence.

## Decision

Select independent provider PostgreSQL 16 with SQLx 0.9 transactions for enrollment/epochs,
root tasks/generations, budget reservations, attempts, intake, release, publication and observations.
Use persistent systemd-supervised Linux containers; private SeaweedFS media and Valkey presence
are separate roles. Neither native conversation storage nor presence cache is the task ledger.

Each root episode has an original ten-minute absolute expiry, at most eight model generation
attempts, 32 tool admissions, 128,000 cumulative input tokens, 16,000 output tokens and a USD 1.00
maximum admission reservation. Per-generation input is at most 32,000 tokens. Four root episodes
may run concurrently; at most three automatic process restarts share the original root limits.
The [initial profile](../../bootstrap/INITIAL-PROFILE.md) fixes request/lease timeouts and pricing
reservation semantics. These are finite review defaults, not an unmeasured performance SLA.

Reserve transactionally before dispatch; children/retries/steering share root reservations and do
not reset expiry. A 30-second worker lease renewed every ten seconds fences every update by
generation. Unknown attempts retain their reservation until accountable reconciliation. Canceling
or retiring a process stops new work, not an already committed remote effect.

Persist the native publication event bytes and event ID before dispatch and retry only that same
event. Preserve consumer effect references and query their original owner on uncertainty. Allocate
observation sequence numbers under a per-consumer row lock in the same transaction as the event;
a later commit cannot appear below an already acknowledged cursor. ACK means contiguous durable
consumer receipt, not business success, recipient reading or permission to purge.

RPO 15 minutes, regional recovery four hours and process/zone recovery 30 minutes are review
targets requiring real restore evidence. Fenced restore disables outbound effects, advances the
recovery epoch, rejects pre-restore leases and reconciles unknown attempts before admission.
Retention/holds/region are explicit enrolled custody configuration; no missing policy is treated
as unlimited retention or permission to discard accepted work.

## Decision Class

Project-scoped recovery and evidence ownership, not a new fiscal retention or consumer policy.

## Options Considered

| Option | Benefit | Consequence / disposition |
| --- | --- | --- |
| PostgreSQL ledger, fenced workers and immutable attempt IDs | Existing transactional primitives and accountable recovery | Selected; migrations and fault tests required |
| Process logs or Valkey as accepted-work owner | Fewer persistence paths | Rejected; interruption and cache loss cannot preserve ownership |
| Blind replay or automatic alternate sender/model/provider | Apparent progress | Rejected; uncertainty can duplicate effects or cross authority/custody boundaries |

## Rationale

Persist effect identity before network dispatch and distinguish admission, execution, evidence,
publication and receipt. Build recovery from the existing owner result, never from a model guess.

## Atomic Commitments and Authority

| ID | Required behavior | Authority / enforcement owner |
| --- | --- | --- |
| BZ-CMT10 | Retain stable task/send attempts and fenced ownership; reconcile consumer/provider outcomes before restart or retry. | Recovery owner |
| BZ-CMT11 | Preserve absolute authority and cumulative budgets through steering, cancellation and process loss. | Task supervisor |
| BZ-CMT12 | Expose uncertain delivery and accepted-versus-completed work without silently switching sender/provider. | Delivery owner |
| BZ-CMT13 | Bind every security claim to a versioned risk/control/profile and trusted technical run; human UAT remains separate. | Assurance owner |
| BZ-CMT14 | Publish compatible contract/profile versions and retain historical/in-flight operation routing during upgrades. | Release owner |

## Component Selection and Dependency Binding

The [register](../components/REGISTRY.yaml) and [profile](../../bootstrap/INITIAL-PROFILE.md) fix
PostgreSQL, SQLx, supervision, model reservations, private media/presence, service identities and
backup/recovery arrangement. Logical components are not automatically separate services. Resolved
package leaves, migration/code symbols and built image digests are later implementation evidence.

## Trade-offs Accepted

Reservations may conservatively retain capacity after an unknown result. This is preferable to
silent duplication. Human waiting consumes absolute lifetime; a new episode needs an explicit
new authority decision rather than an agent-created replenishment. No useful capability is waived.

## Materially Relevant Benchmark Envelope

Fault points include before reservation, after reservation, during an effect, after a committed
effect before response, before/after observation ACK, cursor expiry and restored storage. The
oracle is one original owner effect and durable, correctly scoped recovery. Model billing bounds
are admission estimates with explicit excess handling, not a promise about a vendor's invoice.

## Deferred Capability + Debt Register

No material durability or recovery choice is unselected. Implementation must supply the tables,
workers, migrations, backup/restore and real fault/usage accounting tests. Original project license
remains an explicit owner decision and is not concealed by a document-check result.

## Consequences

Accepted work and historical operations remain owned across restarts/upgrades. Gaps, uncertainty
and partial evidence are visible. A failed mail or conversation stage cannot undo committed fiscal
or business state. Data custody, holds and per-consumer isolation remain separate from ACK state.

## Acceptance and Downstream UATs

[BZ-PF04/05/06/07](../security/ASSURANCE.md) cover actual persistence, budgets, recovery and
applicability. Human [BZ-UAT03](../../acceptance/UAT-CATALOG.md#bz-uat03) judges interrupted
evidence intake; [BZ-UAT05](../../acceptance/UAT-CATALOG.md#bz-uat05) judges understandable
restart/cancel/unknown outcomes. All are not-run for this new profile. Document checks prove neither.

## Source Basis

The [source register](../../discovery/SOURCE-REGISTER.md) separates native ephemeral sessions from
selected provider persistence and records PostgreSQL/native event/SDK source identities. Existing
native behavior is reused where supported, not presented as the entire durable task implementation.

## Review Triggers

Task/budget, owner, retention, cursor, recovery epoch, schema or infrastructure changes require
scoped technical/human impact analysis. No additional committee or ratification loop is introduced.

## Implementation Binding

The [existing realization record](../../../.scratch/llull-buzz/issues/02-realization-plan.md) points to
this concrete profile and [wire contract](../contracts/WIRE-PROFILE.md). Later implementation
binds real migrations, source symbols, tests and evidence without reopening the settled consumer.

## Conformance and Drift Controls

Reports bind exact subject, checker, effective profile/configuration, expected/executed cases and
file/result hashes. Missing/skipped/stale evidence cannot pass. Document validation is author evidence;
the sole reviewer assesses the submission and identified humans supply their own UAT verdicts.

## Ecosystem Placement

ADR-001 owns neutral interfaces; ADR-002 owns authority/publication; this ADR owns durable identity
and recovery. Consumer compatibility is mapped outside these normative provider definitions.

## Self-Governance Trigger

Not applicable; no external organizational overlay is imported.

## Authoring Checks

Stable CMT/proof/UAT identities and null proposal approval/date are preserved. No runtime build,
restore test, independent certification or merge is claimed by publication.
