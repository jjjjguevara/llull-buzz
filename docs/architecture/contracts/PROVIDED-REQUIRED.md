# Reusable communication and agent interfaces

Contract: llull-buzz integration v0.1, proposed. This is the provider-owned semantic
contract, not an implemented endpoint list. Wire encodings and SDKs are planning bindings.

## Common envelope and meanings

Each operation carries a stable consumer-scoped intent ID, contract/profile version,
payload fingerprint, resource/conversation references, correlation and causation IDs.
Authenticated invoker, subject, service/agent and delegated authority are resolved from
verified context, not trusted from arbitrary model fields. Tenant scope comes from
registration. Unknown capability, wrong scope and unsupported contract are explicit.

Admission result: accepted, denied, conflict or unsupported. Accepted means durable
work is retained, not that a business effect or publication completed. Execution result:
pending, running, awaiting-human, completed, failed-before-effect, effect-unknown or
canceled-before-effect. Delivery/evidence/business outcome are separate observations;
these terms do not replace a provider's established fiscal or consumer domain vocabulary.

Same intent/fingerprint replays the recorded result or current operation reference.
Changed content conflicts. Concurrent claim/worker generations are fenced. A lost response
cannot cause a fresh business effect. Cancellation stops new work where possible and
reconciles committed/in-flight effects; it is not rollback of remote success.

## Provided capabilities

| ID / semantic operation | Inputs and admission | Output / durability / failure owner | Required consumer port |
| --- | --- | --- | --- |
| BZ-C01 DescribeProfile | Registered consumer and requested contract/runtime/client profile. | Actual supported operations, version/limits and declared unavailable capabilities; never pretend a hook is a gate. | BZ-R01 registration and permitted profiles. |
| BZ-C02 BindActor / ChangeAccess | Verified issuer/subject, module enrollment, local key proof and authorized access-change intent. | Versioned local binding and propagation status; ambiguous/revoked identity denies. Preserve historical actor identity. | BZ-R01 identity/enrollment policy; BZ-R02 scoped authority. |
| BZ-C03 AcceptConversationInput | Authenticated source message, original IDs, namespace, destination context and authorized evidence references. | Durable receipt and redeliverable normalized observation; duplicate source delivery does not repeat consumer acceptance. | BZ-R03 durable observation sink; BZ-R05 correlation/evidence access. |
| BZ-C04 StartTask / ObserveTask | Registered task spec/version, verified grant, resource/revision, approved profile, absolute deadline and cumulative budget. | Durable task identity, execution observations, existing domain outcomes and pending work; no success inferred from end_turn. | BZ-R02 authority/approval; BZ-R04 domain operations/result lookup; BZ-R05 permitted context. |
| BZ-C05 CancelTask / ReconcileTask | Authorized task identity and expected revision/generation. | Stopped/new-work-denied state plus in-flight/committed effects; restart cannot replenish grant or budget. | BZ-R02 current authority; BZ-R04 existing result lookup. |
| BZ-C06 Publish | Stable intent, authorized destination/audience, content/evidence scope, safe summary or approved bytes and retention policy. | Durable publication record with provider message reference or explicit unknown; no second send owner or implicit cross-provider failover. | BZ-R06 publication decision, audience and content-release evidence. |
| BZ-C07 EvidenceAccess | Original message/attachment reference, verified requester and permitted purpose. | Authorized metadata/bytes, digest, readiness and source lineage; errors disclose no content or credential. | BZ-R05 evidence registration/retention boundary. |
| BZ-C08 ObserveOperations / ResumeObservations | Enrolled consumer, scoped cursor and compatible observation schema. | Ordered/versioned observations and explicit gaps; query/reconciliation recovers missed notifications. | BZ-R03 durable acceptance and duplicate handling. |

## Required consumer capabilities

| ID | Consumer obligation | What llull-buzz verifies or does when absent |
| --- | --- | --- |
| BZ-R01 | Register a namespace, permitted profiles, issuer/audience policy and independent module enrollment. | Validate registration and credentials; no default universal enrollment or need for a new password directory. |
| BZ-R02 | Supply verifiable subject/service/agent authority, task grants and required human approvals tied to target/revision/fingerprint. | Verify the binding and scope; consumer rechecks at business commitment. Unavailable required verification cannot grant an effect. |
| BZ-R03 | Durably accept authenticated observations and expose acceptance/recovery by stable source/operation identity. | Retain and redeliver until acceptance or explicit terminal policy; ACK does not mean business completion. |
| BZ-R04 | Expose typed governed domain commands/queries and existing-result lookup with idempotency and explicit outcomes. | Call only admitted methods; never bypass with direct database access or invent a generic execute operation. |
| BZ-R05 | Resolve neutral references to authorized context/evidence, register intake and declare retention ownership. | Reject ambiguous cross-consumer correlation; preserve byte/registration distinction and do not require consumer completion for durable intake. |
| BZ-R06 | Decide audience/content release and approved copies; provide compatible policy revision and fresh destination facts. | Enforce each output path and re-evaluate material audience changes. Read authority does not imply export authority. |

Consumers may supply these through local adapters, authenticated APIs or verifiable
assertions. A live callback is not mandatory where offline verification satisfies the
agreed freshness/revocation contract. No named consumer, shared ORM, shared database,
fixed identity vendor or synchronized software release is required.

## Runtime containment profile

Use the initial buzz-acp/buzz-agent direction only with an explicit admitted manifest:
executables, tool servers/schemas, skills, model endpoints, credentials, mounts and
network routes. The launch/protocol adapter controls both inherited environment and
credentials carried in session declarations. Never provide a general shell or signing
API just to satisfy a runtime reply heuristic. Reuse supported upstream mechanisms;
a client fork and a replacement model loop are not the default implementation.

Bind task authority through trusted intake/session identity, never an LLM-supplied role.
Separate session contexts by consumer and information-access domain, including cached
memory and observer transcripts. Retire affected contexts on access change. Model and
tool admission include outstanding work, finite cumulative budgets and absolute expiry.
Hook timeouts, steering and process restarts cannot extend authorization.

## Publication and trust

Retain the configured summary/link default and explicit copy permission. A normal reply,
notification, preview, diagnostic or attachment path must not bypass release control.
A model fed restricted data cannot safely be made a public publisher by prompt alone.
Use audience-permitted context or a separate bounded release operation. Changed audiences
require re-evaluation. Revocation stops future access but cannot erase recipient copies.

## Compatibility and independent progress

The provider publishes immutable contract/schema/profile digests and supported version
relationships. Each consumer owns its mapping. Test doubles enable independent builds;
real integration evidence is needed for composed acceptance. Drain or route historical
operations across upgrades; an unknown operation remains owned and reconcilable.

One integration owns each external publication intent. Business orchestration, fiscal
state and mail delivery stay with their respective owners. A failed message cannot undo
a completed business operation. Evidence recovery cannot recreate a business effect.

## Acceptance links

[AC and human scenarios](../../acceptance/UAT-CATALOG.md) define positive outcomes.
[Security proof profiles](../security/ASSURANCE.md) define separate technical evidence.
[Realization planning](../../../.scratch/llull-buzz/issues/02-realization-plan.md)
must bind actual operations, tests and effective configuration before implementation
acceptance. This proposal has no executed conformance or human verdict.
