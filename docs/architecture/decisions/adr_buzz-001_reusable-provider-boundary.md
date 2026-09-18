---
id: adr_llull-buzz-001_buzz-001_reusable-provider-boundary
entity: document
subtype: adr
name: ADR 001 - Consumer-neutral integration boundary
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
component_refs: ["owned.contract-ports", "upstream.buzz-sdk", "slot.tool-sdk"]
mandatory_uat_refs: ["BZ-UAT01", "BZ-UAT02"]
conformance_status: not-assessed-for-proposed-delta
ecosystem_placement:
  motivating_design_rationale: "Preserve independently evolvable consumers while reusing upstream conversation and execution capabilities."
  bears_on_quality_attribute_scenarios: [authorized-completion, denied-effect-isolation, interruption-recovery]
  implements_asrs: ["BZ-CMT01", "BZ-CMT02", "BZ-CMT03", "BZ-CMT04"]
  affects_architecture_views: [module, runtime, security, API, evidence]
  related_adrs: []
---

# ADR 001 - Consumer-neutral integration boundary

## Status

Proposed. Publication is not acceptance, implementation or a passed UAT. Existing accepted decisions remain effective until an explicit amendment is accepted.

## Context

Communication and agent integrations need stable capabilities without importing a particular consumer or cloning its application. A repository boundary must not create unowned handoffs or a second business authority.

## Decision

Keep public communication/agent ports independent of consumer business models, client forks and deployment topology.

## Decision Class

Project-scoped: this decision governs this reusable product and its interfaces. It creates no new legal interpretation or organization-wide governance regime.

## Options Considered

| Option | Pros | Cons | Complexity | When valid |
| --- | --- | --- | --- | --- |
| Client fork | Immediate UI control | Upstream coupling and duplicated product | high | Only an explicit future product decision |
| Neutral adapters over upstream | Reuses product and isolates consumers | Requires explicit reciprocal contracts | bounded | Recommended boundary |
| Consumer-specific integration | Fast first coupling | Prevents reuse and hides responsibility | low initially | Not this reusable product |

## Rationale

Preserve independently evolvable consumers while reusing upstream conversation and execution capabilities.

## Atomic Commitments and Authority

| ID | Required behavior | Authority / enforcement owner |
| --- | --- | --- |
| BZ-CMT01 | Keep public communication/agent ports independent of consumer business models, client forks and deployment topology. | Contracts owner |
| BZ-CMT02 | Publish provided and required capabilities with identity, inputs, outcomes, durability and recovery ownership. | Provider/consumer integration owners |
| BZ-CMT03 | Treat module enrollment, human identity, service registration and delegated authority as distinct. | Identity owner |
| BZ-CMT04 | Inventory each selected atomic component, exact version/license and observed dependency closure. | Architecture/build owner |

## Component Selection and Dependency Binding

Bind `owned.contract-ports`, `upstream.buzz-sdk`, `slot.tool-sdk` in the local component register. Each choice needs its own version/source, rationale, license, owner, extension surface and observed dependency closure. No additional library or topology is selected by this proposal.

## Trade-offs Accepted

No capability ceiling is accepted by this draft. Proposed engineering/operating cost: Contract evolution and adapter compatibility must be maintained explicitly.

## Materially Relevant Benchmark Envelope

Stimulus: a new consumer or provider version. Source: integrator. Environment: same registered profile. Artifact: provided/required ports. Response: use compatible contracts or reject explicitly. Measure: no consumer-specific import and no silent capability downgrade. No performance run is claimed; numerical deployment budgets require an approved workload/profile.

## Deferred Capability + Debt Register

No product-capability deferral is proposed. Exact internal realization belongs to planning, not a waiver of these guarantees. A later deferral needs scope, owner, re-entry trigger and resolution criterion.

## Consequences

Capability gained: Preserve independently evolvable consumers while reusing upstream conversation and execution capabilities.

Capability forgone: none proposed. Cost: Contract evolution and adapter compatibility must be maintained explicitly.

Mitigation: narrow supported adapters, explicit component admission, local contract vectors, and the independent technical/human evidence below.

## Acceptance and Downstream UATs

The [provided/required contract](../contracts/PROVIDED-REQUIRED.md) binds these commitments to technical obligations. The following human cases are mandatory where their surfaces apply; no API-only provider must invent a standalone UI.

| Human case | Required consequence / role |
| --- | --- |
| [BZ-UAT01](../../acceptance/UAT-CATALOG.md#bz-uat01) | Real adopted-client/consumer task and recovery; named human verdict. |
| [BZ-UAT02](../../acceptance/UAT-CATALOG.md#bz-uat02) | Real adopted-client/consumer task and recovery; named human verdict. |

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

Motivating rationale: Preserve independently evolvable consumers while reusing upstream conversation and execution capabilities.

Views: public interfaces, module dependencies, execution, security and evidence. Relations: this is the initial boundary proposal. Existing owner decisions remain separately authoritative.

## Self-Governance Trigger

Not applicable. This product-scoped contract does not import an external governance overlay.

## Authoring Checks

The proposal includes context, alternatives, attributable commitments, consequences, source basis, planning bindings and mandatory human scenarios. Acceptance date and approval reference intentionally remain empty. Technical conformance and human verdicts must be supplied by later real runs.
