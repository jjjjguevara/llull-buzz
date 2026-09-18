---
id: adr_llull-buzz-NNN_decision-slug
entity: document
subtype: adr
name: ADR NNN - Decision Title
author: Josue Guevara
date: YYYY-MM-DD
refinement: 0.1
origin: synthesis
form: draft
audience: internal
product: llull-buzz
status: proposed
decision_date: null
decision_owner: Josue Guevara
approval_ref: null
decision_class: Project-scoped
quality_attributes: []
accepted_ceilings: []
deferred_capability: []
source_basis: []
implementation_binding: []
review_triggers: []
supersedes: []
superseded_by: []
ecosystem_placement:
  motivating_design_rationale: null
  bears_on_quality_attribute_scenarios: []
  implements_asrs: []
  affects_architecture_views: []
  related_adrs: []
requirement_refs: []
ac_refs: []
invariant_refs: []
component_refs: []
contract_refs: []
surface_impact: direct-or-indirect-or-none
mandatory_uat_refs: []
non_uat_evidence_refs: []
enforcement_bindings: []
conformance_status: not-assessed-for-proposed-delta
related: []
tags: [architecture, adr]
references: []
---

# ADR NNN - Decision Title

## Status

Use `proposed`, `accepted`, `rejected`, `deprecated`, or `superseded`.
Acceptance requires the decision owner's explicit approval reference and date.
Acceptance is architectural authorization, not implementation or UAT completion.

## Context

State the problem, binding product constraints and decision pressure. Link the
ratified owner answers. Do not silently revise their meanings or interpret a source
repository's default as product policy.

## Decision

State the proposed or accepted choice, scope and exclusions precisely. Identify the
facts it owns, projects or consumes. Distinguish native reuse, configuration, adaptation
and genuinely custom work. Do not turn every logical boundary into a service.

## Decision Class

Use the portable taxonomy without an external organizational overlay:
Strategic (long-term direction), Programmatic (cross-project commitments), Project-scoped,
Iteration-scoped, Task-scoped, Infrastructure, Governance-of-Governance, or Compliance.
Explain the scope. Compliance decisions cite the actual applicable legal commitment;
a fiscal API integration is not automatically a new legal conclusion.

## Options Considered

| Option | Pros | Cons | Complexity | When valid |
| --- | --- | --- | --- | --- |
| Populate actual alternatives | | | | |

Include existing implementations considered and why adaptation is preferable to custom
infrastructure. A rejected candidate remains traceable, not silently removed.

## Rationale

Link the problem, alternatives, source evidence and choice. Label evidence as owner
intent, documented behavior, inspected implementation, measured result or architectural
inference. A library feature list is not an integration or performance result.

## Atomic Commitments and Authority

| Commitment ID | MUST / MUST NOT statement | Authority and permitted writer | Consumer / failure outcome | Enforcement owner |
| --- | --- | --- | --- | --- |
| C-NNN-01 | One independently testable commitment per row | | | |

Name local transaction boundaries, allowed write paths, stable identities, revisions,
causation, human/service/agent attribution, idempotency and uncertain effects where
relevant. Name forbidden shortcuts. Cover replay, policy/configuration change and
cross-provider behavior. References to an event store do not establish complete capture.

## Component Selection and Dependency Binding

| Component ID | Exact identity / edition / version / source pin | Adopt / configure / adapt / custom | Why this component; alternative | Owner and extension surface |
| --- | --- | --- | --- | --- |
| Link the component register | | | | |

The component register owns component identity and rationale; this section binds its
exact selected revision. Enumerate each enabled adapter/runtime module individually. Include
first-party components, external services, libraries, copied code and operational/build
tools. Link transitive dependencies through a versioned complete BOM, with introduction
rationale inherited from a named selected parent unless deliberately customized.
No reference to an unversioned repository may stand in for a release binding.

## Trade-offs Accepted

| Accepted ceiling | Principal cost | Interest profile | Repayment / review trigger |
| --- | --- | --- | --- |
| None accepted while proposed, unless explicitly attributed | | | |

Mirror actual accepted ceilings in frontmatter. Label proposed trade-offs as proposed.
A missing feature, unsupported guarantee or unresolved budget is not an accepted ceiling.

## Materially Relevant Benchmark Envelope

When the decision exposes a quality-attribute trade-off, name the attribute, workload
and evidence. Use numeric targets only if approved for that profile; otherwise use
Stimulus / Source / Environment / Artifact / Response / Response Measure. Keep proposed
budgets distinct from approved limits and measured distributions. Do not substitute a
benchmark for the human judgment required by a linked UAT.

## Deferred Capability + Debt Register

| Capability | Description | Deferral rationale | Re-entry trigger | Resolution criterion | Follow-up artifact | Existing tracker ID |
| --- | --- | --- | --- | --- | --- | --- |
| None approved | | | | | | |

Keep the deferral self-describing. Cite only work items that actually exist. Sequence
work without implicitly reducing the ratified destination. Any product compromise
needs the owner's explicit revision, not an implementation-time assumption.

## Consequences

State capability gained, capability forgone / accepted ceilings, and mitigation.
Distinguish unavoidable development/operation from avoidable technical debt. Include
extension, licensing, upgrade, historical-reference and selective-migration costs.

## Acceptance and Downstream UATs

| AC / invariant | Mandatory human UAT and case version | Required surface / role | Separate technical evidence | Re-run trigger |
| --- | --- | --- | --- | --- |
| Link existing AC meaning | Link a real UAT catalog case | | | |

Direct or indirect UI effects require named downstream UATs, including permissions,
status, navigation, evidence, reports and latency consequences. A no-UAT judgment needs
a specific rationale. No code suite, CI job, benchmark or agent verdict is a human UAT.
Design approval, implementation conformance and actual human acceptance stay separate.
New surfaces must extend the UAT inventory and invalidate affected old results as needed.

## Source Basis

| Source pointer and exact revision | How it bears on the decision | Evidence kind |
| --- | --- | --- |
| Resolve to owner answer, inspected source, applicable standard or actual evidence | | |

An empty source basis is invalid for acceptance. External sources include title,
author/organization, year or observation date, venue and canonical URL/DOI where known.
Do not invent bibliographic details or promote previous research into executed proof.

## Review Triggers

Mirror frontmatter triggers: changed domain meaning, dependency or enabled-module
change, new write path, new user surface, policy/revocation change, service-contract
change, incident, UAT failure, quality regression, migration or licensing change.
Ordinary version bumps trigger impact review, not automatic acceptance or a new ADR
when no architectural meaning changes. Material semantic changes require amendment
or supersession with owner approval.

## Implementation Binding

| Existing binding | Role | Implementation / evidence status |
| --- | --- | --- |
| Real work item or real code/evidence path | | |

Use an existing planning ticket until code exists. Label projected component surfaces
as design identities, not files already implemented. This section never asserts completion.

## Conformance and Drift Controls

| Drift condition | Detection / control | Blocking boundary | Responsible reviewer |
| --- | --- | --- | --- |
| Unrecorded module, bypassed writer, changed contract or invalidated UAT | | | |

State enforcement in architecture review, mechanical checks and runtime controls.
Document checks cannot prove runtime behavior. CI may check reference integrity and
applicable UAT evidence, but cannot create a human verdict. A gate exemption requires
an attributable owner decision with scope and expiry; a waiver is never a pass.

## Ecosystem Placement

Name the motivating rationale, quality scenarios, architecturally significant
requirements, affected module/runtime/data/API/security/deployment/user-surface views,
and labeled ADR relations (`depends-on`, `refines`, `constrains`, `supersedes`).
The canonical Wayfinder still owns unresolved questions and attributed owner answers.

## Self-Governance Trigger

For Governance-of-Governance only: identify the observed failure or explicit owner
request motivating the amendment. Other decision classes may use `not applicable`.
Do not import an external governance process or retroactively rewrite historical ADRs.

## Authoring Checklist

- [ ] Portable frontmatter, status and source basis are complete.
- [ ] Explicit owner approval exists before acceptance; implementation and UAT states remain separate.
- [ ] Every atomic commitment has an owner, permitted effect and enforcement binding.
- [ ] Every direct component/module choice has an individual identity and rationale; dependency closure is bound.
- [ ] Authority, idempotency, uncertainty, replay and provider history are explicit where relevant.
- [ ] Quality envelopes and ceilings distinguish proposal, approval and measured result.
- [ ] Deferrals carry scope, re-entry trigger and explicit approval.
- [ ] User-surface impacts link mandatory UATs and separate technical proof.
- [ ] Source, work-item, component, contract and UAT links resolve.
- [ ] Review triggers and ecosystem relationships are explicit.
