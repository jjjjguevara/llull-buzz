---
id: adr_llull-buzz-003_buzz-003_recovery-and-assurance
entity: document
subtype: adr
name: ADR 003 - Recoverable operations and bounded assurance
author: ChatGPT, owner-directed synthesis
date: 2026-09-18
refinement: 0.1
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
implementation_binding: ["../../../.scratch/llull-buzz/issues/02-realization-plan.md"]
review_triggers: [contract-change, authority-change, dependency-version-change, new-surface, recovery-failure]
supersedes: []
superseded_by: []
proposed_amendments: []
component_refs: ["owned.delivery-ledger", "owned.task-supervisor", "slot.persistence", "slot.runtime-image"]
mandatory_uat_refs: ["BZ-UAT03", "BZ-UAT05"]
conformance_status: not-assessed-for-proposed-delta
ecosystem_placement:
  motivating_design_rationale: "Make interruption and upgrade recoverable without treating conversation or execution logs as business authority."
  bears_on_quality_attribute_scenarios: [authorized-completion, denied-effect-isolation, interruption-recovery]
  implements_asrs: ["BZ-CMT10", "BZ-CMT11", "BZ-CMT12", "BZ-CMT13", "BZ-CMT14"]
  affects_architecture_views: [module, runtime, security, API, evidence]
  related_adrs: ["depends-on ADR-001", "depends-on ADR-002"]
---

# ADR 003 - Recoverable operations and bounded assurance

## Status

Proposed. Publication is not acceptance, implementation or a passed UAT. Existing accepted decisions remain effective until an explicit amendment is accepted.

## Context

Ephemeral model sessions and successful sends do not establish durable business completion. Independent products need compatible operation history and evidence without synchronized builds or duplicate state.

## Decision

Retain stable task/send attempts and fenced ownership; reconcile consumer/provider outcomes before restart or retry.

## Decision Class

Project-scoped: this decision governs this reusable product and its interfaces. It creates no new legal interpretation or organization-wide governance regime.

## Options Considered

| Option | Pros | Cons | Complexity | When valid |
| --- | --- | --- | --- | --- |
| Transient session state only | Smallest storage | Loses work/authority accounting on restart | low | Insufficient for these guarantees |
| Durable adapter ledger with consumer truth | Recovery without rebuilding business state | Persistence and reconciliation work | moderate | Recommended |
| Shared business database | Simple direct lookup | Couples products and creates bypasses | high | Rejected for neutral boundary |

## Rationale

Make interruption and upgrade recoverable without treating conversation or execution logs as business authority.

## Atomic Commitments and Authority

| ID | Required behavior | Authority / enforcement owner |
| --- | --- | --- |
| BZ-CMT10 | Retain stable task/send attempts and fenced ownership; reconcile consumer/provider outcomes before restart or retry. | Recovery owner |
| BZ-CMT11 | Preserve absolute authority and cumulative budgets through steering, cancellation and process loss. | Task supervisor |
| BZ-CMT12 | Expose uncertain delivery and accepted-versus-completed work without silently switching sender/provider. | Delivery owner |
| BZ-CMT13 | Bind every security claim to a versioned risk/control/profile and trusted technical run; human UAT remains separate. | Assurance owner |
| BZ-CMT14 | Publish compatible contract/profile versions and retain historical/in-flight operation routing during upgrades. | Release owner |

## Component Selection and Dependency Binding

Bind `owned.delivery-ledger`, `owned.task-supervisor`, `slot.persistence`, `slot.runtime-image` in the local component register. Each choice needs its own version/source, rationale, license, owner, extension surface and observed dependency closure. No additional library or topology is selected by this proposal.

## Trade-offs Accepted

No capability ceiling is accepted by this draft. Proposed engineering/operating cost: Durable operation storage, lifecycle reconciliation and evidence applicability have ongoing operating cost.

## Materially Relevant Benchmark Envelope

Stimulus: crash or duplicate delivery before/after an effect. Source: worker/transport failure. Environment: concurrent/restarted workers. Artifact: intent and result records. Response: recover the same operation without repeated committed effects. Measure: independent durable-state/provider oracles; actual recovery budgets selected per deployment. No performance run is claimed; numerical deployment budgets require an approved workload/profile.

## Deferred Capability + Debt Register

No product-capability deferral is proposed. Exact internal realization belongs to planning, not a waiver of these guarantees. A later deferral needs scope, owner, re-entry trigger and resolution criterion.

## Consequences

Capability gained: Make interruption and upgrade recoverable without treating conversation or execution logs as business authority.

Capability forgone: none proposed. Cost: Durable operation storage, lifecycle reconciliation and evidence applicability have ongoing operating cost.

Mitigation: narrow supported adapters, explicit component admission, local contract vectors, and the independent technical/human evidence below.

## Acceptance and Downstream UATs

The [provided/required contract](../contracts/PROVIDED-REQUIRED.md) binds these commitments to technical obligations. The following human cases are mandatory where their surfaces apply; no API-only provider must invent a standalone UI.

| Human case | Required consequence / role |
| --- | --- |
| [BZ-UAT03](../../acceptance/UAT-CATALOG.md#bz-uat03) | Real adopted-client/consumer task and recovery; named human verdict. |
| [BZ-UAT05](../../acceptance/UAT-CATALOG.md#bz-uat05) | Real adopted-client/consumer task and recovery; named human verdict. |

Code suites, fault schedules, signature verification and runtime attestation are technical evidence, not UAT verdicts. Change affected case versions when semantics, permissions, status or recovery changes.

## Source Basis

| Source pointer | How it bears on the decision | Evidence class |
| --- | --- | --- |
| [Owner mandate](../../discovery/SOURCE-REGISTER.md#owner-mandate) | Reusable non-fork boundary and explicit reciprocal duties. | owner requirement |
| [Pinned upstream](../../discovery/SOURCE-REGISTER.md#pinned-primary-source) | Existing harness/runtime and named integration constraints. | pinned source basis |

## Review Triggers

Contract/authority change, dependency or enabled-module change, new surface, recovery failure, security finding or invalidated UAT. An ordinary compatible update requires impact analysis, not automatic ratification or a duplicate ADR.

## Implementation Binding

[Planning binding](../../../.scratch/llull-buzz/issues/02-realization-plan.md) names the actual follow-up artifact. It is not implemented code or evidence of completion. Actual code/test symbols and native work-item IDs must be bound when implementation is authorized.

## Conformance and Drift Controls

Every affected run reconciles expected versus executed technical cases against exact artifact/configuration/profile digests. Missing, skipped, stale or mismatched evidence does not pass. Positive permitted completion is required alongside denial and fault cases. A consumer-specific import, undeclared dependency, unverified authority shortcut or effect-repeating recovery violates the boundary.

## Ecosystem Placement

Motivating rationale: Make interruption and upgrade recoverable without treating conversation or execution logs as business authority.

Views: public interfaces, module dependencies, execution, security and evidence. Relations: depends-on ADR-001; depends-on ADR-002. Existing owner decisions remain separately authoritative.

## Self-Governance Trigger

Not applicable. This product-scoped contract does not import an external governance overlay.

## Authoring Checks

The proposal includes context, alternatives, attributable commitments, consequences, source basis, planning bindings and mandatory human scenarios. Acceptance date and approval reference intentionally remain empty. Technical conformance and human verdicts must be supplied by later real runs.
