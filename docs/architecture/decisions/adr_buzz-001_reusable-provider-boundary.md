---
id: adr_llull-buzz-001_buzz-001_reusable-provider-boundary
entity: document
subtype: adr
name: ADR 001 - Consumer-neutral integration boundary
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
component_refs: [owned.contract-ports, upstream.buzz-sdk, slot.tool-sdk, lib.serde-jcs, lib.axum]
mandatory_uat_refs: [BZ-UAT01, BZ-UAT02]
conformance_status: not-assessed-for-proposed-delta
ecosystem_placement:
  motivating_design_rationale: Preserve independently evolvable consumers while reusing upstream conversation and execution capabilities.
  bears_on_quality_attribute_scenarios: [authorized-completion, denied-effect-isolation, interruption-recovery]
  implements_asrs: [BZ-CMT01, BZ-CMT02, BZ-CMT03, BZ-CMT04]
  affects_architecture_views: [module, runtime, security, API, evidence]
  related_adrs: []
---

# ADR 001 - Consumer-neutral integration boundary

## Status

Proposed revision 0.2. PC-BZ-01 realization is specified, not accepted or implemented.
No approval reference, independent review verdict or human acceptance is supplied by this author.

## Context

Independent consumers need communication intake, scoped delegated work, publication and recovery
without sharing an operational schema, identity vendor, deployment or release cycle. The earlier
proposal named these duties but left the initial language, SDK and wire realization unexplained.

## Decision

Retain BZ-C01..08 and BZ-R01..06. Select the Rust/Axum/Serde adapter with upstream `buzz-sdk`,
`rmcp` 1.1.0 stdio tools and RFC 8785 canonical JSON through `serde_jcs` 0.2.0. The
[wire profile](../contracts/WIRE-PROFILE.md) defines neutral command envelopes, typed payloads,
invocation evidence and result/observation meanings. The
[initial profile](../../bootstrap/INITIAL-PROFILE.md) fixes processes and effect owners.
This is one concrete compatible realization, not a universal implementation-language constraint.

## Decision Class

Project-scoped. No organization-wide regime, new review committee or legal interpretation.

## Options Considered

| Option | Benefit | Consequence / disposition |
| --- | --- | --- |
| Rust adapters on the pinned native SDK and MCP seam | One native protocol stack and no replacement agent loop | Selected; integration-owned policy and durable adapters remain explicit |
| TypeScript sidecars | Familiar HTTP tooling | Not selected initially; adds runtime and native-protocol translation without a demonstrated benefit here |
| Consumer-specific fork/shared database | Quick direct access | Rejected; destroys independent ownership and client compatibility |

## Rationale

Reuse supported native extension surfaces and standard cryptographic/serialization libraries;
implement only the consumer-neutral authority, durability and release boundaries absent upstream.

## Atomic Commitments and Authority

| ID | Required behavior | Authority / enforcement owner |
| --- | --- | --- |
| BZ-CMT01 | Keep public communication/agent ports independent of consumer business models, client forks and deployment topology. | Contracts owner |
| BZ-CMT02 | Publish provided and required capabilities with identity, inputs, outcomes, durability and recovery ownership. | Provider/consumer integration owners |
| BZ-CMT03 | Treat module enrollment, human identity, service registration and delegated authority as distinct. | Identity owner |
| BZ-CMT04 | Inventory each selected atomic component and exact version/source/license; bind the observed dependency closure when built. | Architecture/build owner |

## Component Selection and Dependency Binding

The [register](../components/REGISTRY.yaml) binds each deliberate selection to purpose, owner,
source/release, license, rationale, alternative, footprint and adaptation. Rust 1.98.1 satisfies
these selected SDKs' declared language requirements. This is compatibility analysis, not a build.
Ordinary resolved dependency leaves and installed/image digests remain build evidence; no material
mechanism is left for a future language, storage or protocol decision.

## Trade-offs Accepted

The initial profile bears the cost of Rust adapters and native-protocol compatibility tests.
No product capability ceiling or permission to omit useful authorized completion is accepted.
Original project licensing is still an explicit unanswered owner decision, not an open-source grant.

## Materially Relevant Benchmark Envelope

A synthetic consumer independently authenticates, enrolls an intended key, submits a permitted
revision-bound task and observes the same result after interruption. The oracle is the consumer's
single committed effect and the provider's durable correlation, not a completed model turn.
Operating limits are fixed in the initial profile; actual latency/capacity measurements are not run.

## Deferred Capability + Debt Register

No capability deferral. The named adapters, migrations, installed inventories and actual code/test
bindings are implementation work. The license decision prevents distribution-ready completion and
is openly recorded in the existing map; it does not delegate the engineering profile to implementation.

## Consequences

Consumers can evolve independently through versioned contracts and source-bound adapters. The
provider must maintain native-protocol conformance and route historical operations across upgrades.
No consumer-private schemas, notes, credentials or internal references are published as provider law.

## Acceptance and Downstream UATs

[Assurance](../security/ASSURANCE.md) binds BZ-PF01/02/04/07. Human
[BZ-UAT01](../../acceptance/UAT-CATALOG.md#bz-uat01) judges useful cross-surface completion;
[BZ-UAT02](../../acceptance/UAT-CATALOG.md#bz-uat02) judges independent enrollment/recovery.
Consumers map these to their own interfaces. Static examples and author checks do not pass them.

## Source Basis

The [source register](../../discovery/SOURCE-REGISTER.md) records the inspected upstream commit,
SDK release/license evidence and source seams. The register and wire profile distinguish existing
native operations from new owned adapter routes; no new endpoint is represented as already shipped.

## Review Triggers

Contract, authority, SDK/native-client surface, source version or recovery changes require scoped
impact analysis. Routine compatible dependency resolution does not create another ratification session.

## Implementation Binding

The existing [realization record](../../../.scratch/llull-buzz/issues/02-realization-plan.md) binds this
execution. The profile and schemas are the implementation input; later work supplies their code,
migrations, tests and build evidence without selecting the architecture again.

## Conformance and Drift Controls

A provider and consumer must agree on profile/schema digests, issuer/audience registration and
required ports. Missing, skipped or mismatched technical/human evidence remains visible. A source
pin alone is not a certified native-client build. Wrong-scope denial must accompany useful success.

## Ecosystem Placement

This ADR owns neutral integration boundaries; ADR-002 owns admission/publication and ADR-003 owns
durable recovery. Normative definitions stay in this repository; consumer mappings live with consumers.

## Self-Governance Trigger

Not applicable; no external organizational overlay is imported.

## Authoring Checks

Stable ADR/CMT/capability identities are preserved; proposal status and null approval/date remain.
Revision-bound document checks verify the submitted artifacts separately from reviewer assessment.
