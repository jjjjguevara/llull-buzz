---
id: adr_llull-buzz-002_buzz-002_restricted-execution-and-publication
entity: document
subtype: adr
name: ADR 002 - Restricted execution, identity and publication
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
component_refs: [upstream.buzz-acp, upstream.buzz-agent, upstream.buzz-auth, owned.launch-protocol, owned.identity-binding, owned.tool-gateway, owned.publisher, slot.model-provider, lib.jsonwebtoken]
mandatory_uat_refs: [BZ-UAT01, BZ-UAT02, BZ-UAT04]
conformance_status: not-assessed-for-proposed-delta
ecosystem_placement:
  motivating_design_rationale: Place enforcement at actual credential, tool and publication boundaries rather than a model heuristic.
  bears_on_quality_attribute_scenarios: [authorized-completion, denied-effect-isolation, interruption-recovery]
  implements_asrs: [BZ-CMT05, BZ-CMT06, BZ-CMT07, BZ-CMT08, BZ-CMT09]
  affects_architecture_views: [module, runtime, security, API, evidence]
  related_adrs: [depends-on ADR-001, constrains ADR-003]
---

# ADR 002 - Restricted execution, identity and publication

## Status

Proposed revision 0.2. No runtime/security certification, reviewer approval or human verdict.

## Context

The inspected ACP/agent code exposes executable, stdio MCP and model-base-URL seams. Private
orchestration modules are not a public embedding API. Process inheritance includes signing/SSH
values and wire-supplied environment, so advisory hooks or `env_clear` alone cannot enforce the
required boundaries. Native key possession and relay membership do not establish consumer authority.

## Decision

Adopt the pinned unmodified `buzz-acp` and `buzz-agent` executables behind the owned ACP wrapper,
tool gateway, model proxy and all-path native publication/media gateway described by the
[initial profile](../../bootstrap/INITIAL-PROFILE.md). Select native NIP-42/NIP-98/Blossom client
flows and `buzz-auth`; use `jsonwebtoken` 10.4.0 for the separately verified ES256 invocation JWS.
No general shell, developer MCP, arbitrary server declaration or credential-bearing model context.

Enroll a freshly authenticated consumer principal to a browser-fixed intended public key before
issuing a five-minute one-use native signed challenge. Recovery proves a new key and revokes the
old binding; historical signatures are retained. Independent modules have independent grants.
The provider creates neither a password directory nor a universal consumer role model.

Invocation evidence binds executing/represented principals, delegation, exact action/resource/revision,
canonical payload, required verdicts and current authority epoch. It supplements enrolled provider
resource authority rather than replacing it. Assertions last at most 60 seconds with at most
30 seconds of clock tolerance; root expiry and authority leases are not extended by that tolerance.

Refresh active authority within 30 seconds and enforce a maximum 60-second stale-admission lease.
Fence task generations and retire affected model/observer history on access-domain or epoch change.
The gateway denies stale native deliveries and media reads and cannot be bypassed through a public
relay or object origin. Already delivered copies and committed effects cannot be recalled.

Every ordinary reply, notification, preview, attachment and diagnostic uses a frozen publication
intent and fresh audience/content release. Native push is not assumed configurable. A consumer's
operational Web Push and durable notification inbox/outbox remain consumer-owned. Typed approved
consumer commands and authorized publication remain useful completion paths, not proposal-only work.

## Decision Class

Project-scoped provider security and integration, not an organization-wide identity decision.

## Options Considered

| Option | Benefit | Consequence / disposition |
| --- | --- | --- |
| Supported executables plus enforced trusted gateways | Reuses agent/native client behavior while isolating credentials | Selected; requires complete native surface tests |
| Advisory hooks or broad agent credentials | Easy setup | Rejected; timeout or alternate publication/tool path can bypass authority |
| Client/core fork | Can add controls directly | Rejected initially; native-compatible server adapters are the selected boundary |
| Read/propose-only restriction | Avoids some effects | Rejected as a blanket policy; loses authorized task completion |

## Rationale

Enforcement must sit before the actual effect, model-context release and native publication, not
in a prompt. Standard verification primitives are reused; scoped registration/release remains owned.

## Atomic Commitments and Authority

| ID | Required behavior | Authority / enforcement owner |
| --- | --- | --- |
| BZ-CMT05 | Reuse buzz-acp and buzz-agent through a profile that admits every executable, tool, skill, credential and egress path. | Runtime owner |
| BZ-CMT06 | Bind actor, task, target revision and grant through verified intake; consumer commands enforce business authority. | Tool/identity owners |
| BZ-CMT07 | Control secrets in both process inheritance and ACP parameters; isolate the restricted runtime from general signing and admin credentials. | Launch/protocol owner |
| BZ-CMT08 | Enforce publication on every output path; default to authorized summaries/links and require explicit copy policy. | Publisher owner |
| BZ-CMT09 | Separate information-access contexts and retire affected history on access changes; prompt instructions cannot declassify data. | Session/identity owners |

## Component Selection and Dependency Binding

The [register](../components/REGISTRY.yaml) fixes source/SDK/model and the profile fixes process,
network, mount, credential and native-client seams. Sonnet 5 uses adaptive thinking through the
model proxy; unsupported manual budgets/sampling and undeclared tools are rejected. Native keys
stay in client secure storage or the separate trusted service; vendor keys stay in the model proxy.

## Trade-offs Accepted

Explicit gateways and access leases add operational work and tests. The initial governed record
path uses relay-retained access-controlled channels, not encrypted private-message history as its
only evidence archive. Loss of a personal decryption key is not disguised as recoverable history.
This profile boundary does not remove neutral capabilities or impose its vendor on other consumers.

## Materially Relevant Benchmark Envelope

Exercise a permitted exact-intent command and publication, intended-key race, changed revision,
offline revocation, retired context and restricted canaries across reply/preview/media/diagnostics.
Measure actual denied effects and bounded stale access, not an authentication mock or model text.
Limits are normative design defaults; no process, cryptographic or performance test ran here.

## Deferred Capability + Debt Register

No unselected material admission/publication mechanism remains. Implementation must prove complete
gateway mediation, key/claim verification and supported native-client coverage before this profile
is enabled. Original project rights use the [owner-approved Apache-2.0 scope](../../bootstrap/LICENSING.md); this does not certify the runtime.

## Consequences

Useful authorized work can complete without exposing consumer databases or broad credentials.
A surface that cannot be mediated is explicitly unavailable, not silently granted access. Native
compatibility, recovery and legitimate workflow usability remain mandatory proof/UAT obligations.

## Acceptance and Downstream UATs

[BZ-PF01/02/03/05/06](../security/ASSURANCE.md) cover real verification, containment, freshness and
all-path release. [BZ-UAT01](../../acceptance/UAT-CATALOG.md#bz-uat01),
[BZ-UAT02](../../acceptance/UAT-CATALOG.md#bz-uat02) and
[BZ-UAT04](../../acceptance/UAT-CATALOG.md#bz-uat04) separately judge useful completion,
independent key recovery and understandable authorized publication. No synthetic fixture passes UAT.

## Source Basis

The [source register](../../discovery/SOURCE-REGISTER.md) records ACP/private-module boundaries,
agent configuration/MCP inheritance, native auth and actual media admission. Native membership
checks are not represented as existing artifact-specific release enforcement.

## Review Triggers

Authority, key lifecycle, client/media protocol, model profile, egress or publication changes invalidate
affected technical and human applicability. A compatible change does not require a new committee.

## Implementation Binding

Use the existing [realization record](../../../.scratch/llull-buzz/issues/02-realization-plan.md),
[profile](../../bootstrap/INITIAL-PROFILE.md) and [wire contract](../contracts/WIRE-PROFILE.md).
Later code implements these selected seams; it does not rediscover the consumer's architecture.

## Conformance and Drift Controls

A trusted manifest and real process/crypto/fault tests must establish that no alternate tool,
credential, context, native event or media route bypasses admission. Reject unregistered issuer,
audience, key URL, algorithm and schema. Static document checks are not this evidence.

## Ecosystem Placement

ADR-001 owns neutral ports; this ADR owns authority and release; ADR-003 owns task/delivery
persistence and bounded recovery. Business/fiscal/mail effects remain at their own providers.

## Self-Governance Trigger

Not applicable; no external organizational overlay is imported.

## Authoring Checks

Stable CMT/capability identities remain. Proposal approval/date remain null. The designated reviewer
alone assesses the submitted correction; this author does not resolve findings or certify runtime.
