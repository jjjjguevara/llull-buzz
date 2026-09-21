# Reusable communication and agent interfaces

Contract: `llull-buzz integration v0.2`, proposed. Profile: `bz-restricted-2026-09/v1`.
This provider-owned semantic contract is realized by the [initial profile](../../bootstrap/INITIAL-PROFILE.md)
and [wire definitions](WIRE-PROFILE.md). Adapter routes are specified, not implemented endpoints.
The v0.1 capability/commitment identities remain stable; this revision fills the initial realization.

## Common envelope and meanings

Commands carry consumer, contract/profile, stable intent, operation, resource/revision and correlation.
The provider computes SHA-256 over the RFC 8785 canonical envelope. Fresh transport authentication
and invocation assertions are outside that immutable envelope. Retry preserves the intent/body;
new evidence does not create a new effect identity. The schemas reject unknown fields/actions.

Authentication proves possession of a separately enrolled provider resource credential. Invocation
evidence additionally binds executing/represented principals, delegation, exact intent and required
approvals to issuer/audience, payload revision/digest and fresh authority epochs. Neither replaces
the other. A consumer rechecks its own business rules at its effect boundary. An agent cannot
supply its own trusted principal, role, tenant, grant or approval in free-form tool arguments.

Admission is accepted, denied, conflict or unsupported. Accepted means the provider transaction
committed, not that an external effect or publication completed. Execution is pending, running,
awaiting-human, completed, failed-before-effect, effect-unknown or canceled-before-effect. Native
publication, evidence registration and consumer business outcomes remain distinct observations.

Same `(consumer, operation, intent_id)` and digest returns the recorded result/current reference.
Changed content or stale expected revision conflicts. Durable generations fence concurrent workers.
A lost response triggers lookup by the existing effect identity, not a fresh effect. Cancellation
stops new work and reconciles committed/in-flight effects; it is never remote rollback.

## Provided capabilities

| ID / semantic operation | Inputs and admission | Output / durable owner and recovery | Required consumer port |
| --- | --- | --- | --- |
| BZ-C01 DescribeProfile | Enrolled consumer and requested contract/profile. | Supported operation/schema/client revisions and limits; explicit unsupported capabilities. | BZ-R01 |
| BZ-C02 BindActor / ChangeAccess | Authenticated principal, browser-fixed intended key, one-use native proof and independent module/access intent. | Provider-owned versioned binding, historical key relation, fresh lease and per-surface propagation state; recover with fresh authentication/new-key proof. | BZ-R01, BZ-R02 |
| BZ-C03 AcceptConversationInput | Verified native source/event/community/channel and authorized evidence references. | Provider durable source receipt and normalized observation; duplicate event does not repeat consumer acceptance. | BZ-R03, BZ-R05 |
| BZ-C04 StartTask / ObserveTask | Typed manifest, exact resource/revision, current delegation/verdicts, original deadline and cumulative budget. | Provider root/generation, reservations, attempts and actual external result references; no success from end_turn. | BZ-R02, BZ-R04, BZ-R05 |
| BZ-C05 CancelTask / ReconcileTask | Authorized task and expected generation/revision. | Stop-new-work state plus committed/unknown effects; same root budgets and original owner lookup survive restart. | BZ-R02, BZ-R04 |
| BZ-C06 Publish | Frozen destination/audience/policy, content/attachment digests and explicit permitted-copy release. | Provider publication/event identity and durable outcome; retry exact native event bytes/ID or report unknown, never alternate sender. | BZ-R06 |
| BZ-C07 EvidenceAccess | Original source/attachment identity, verified requester, purpose and current release. | Scoped metadata/bytes, digest, readiness, original source and consumer-registration status; no broad public object URL. | BZ-R05 |
| BZ-C08 ObserveOperations / ResumeObservations | Enrolled consumer and authenticated scoped cursor. | Committed ordered observations, contiguous consumer ACK, explicit expired/gapped cursor and result/snapshot recovery. | BZ-R03 |

## Required consumer capabilities

| ID | Consumer obligation | Verification / absence behavior |
| --- | --- | --- |
| BZ-R01 | Register consumer namespace, provider resource key, exact issuer/audience/key policy, profiles and independent enrollments. | No default enrollment, universal consumer roles or extra human password directory. |
| BZ-R02 | Provide verifiable executing/represented actor, delegation, required exact-intent verdicts and current authority/recovery state. | Verify target/revision/digest and freshness; unavailable required verification denies new effects, not authorized recovery of past results. |
| BZ-R03 | Durably accept authenticated observations and expose acceptance by stable source/operation identity. | Retain/redeliver until durable ACK or declared retention/gap policy; ACK is not business success. |
| BZ-R04 | Expose registered typed commands/queries and existing-result lookup with idempotency and explicit unknown/conflict outcomes. | No database bypass or generic execute tool. A committed consumer operation is not repeated after lost response. |
| BZ-R05 | Resolve neutral references to authorized context/evidence, register intake and declare retention ownership. | Deny ambiguous cross-consumer correlation; byte durability and consumer registration remain separate. |
| BZ-R06 | Provide fresh destination/audience/policy and release of exact content/attachments/copies. | Revalidate every provider output path; read authority alone never grants export permission. |

A compatible registered assertion/lease may satisfy a required port without a live callback on
every read, provided it meets the selected freshness bound. No named consumer, shared ORM/database,
fixed identity vendor or synchronized release is required. Unknown or stale authority cannot extend
a task lifetime or publish restricted context.

## Runtime and publication boundary

The initial profile fixes admitted binaries, ACP declarations, tools, model endpoint, credentials,
mounts, egress, task lifetimes and cumulative reservations. Both process inheritance and wire
configuration are enforced outside the model. Native controls/hooks remain advisory where the
inspected upstream makes them advisory. Useful approved typed commands and publication are allowed.

Separate context by consumer/access domain, retire warm history on authority change and deny stale
native event/media access. Ordinary replies, notifications, previews, attachments and diagnostics
all pass the provider publisher/gateway. Authenticated evidence intake remains available. Consumer
operational Web Push is independently owned and is not a configurable-native-push assumption.

## Compatibility and independent progress

Publish immutable schema/profile digests and support relationships. Consumers own mappings and
can develop independently with truthful test doubles; composed acceptance requires real integration
evidence. Drain or route old operations through their recorded profile and retain original effect
owners after upgrade. Restore advances recovery epochs and reconciles unknown attempts.

Fiscal result/evidence, mail delivery and conversation publication each have one effect owner and
independently recoverable intent. A failed message cannot undo a committed fiscal or business result.
An evidence or notification repair is not permission to recreate the original effect.

## Acceptance links

[AC and human cases](../../acceptance/UAT-CATALOG.md) bind useful outcomes;
[assurance](../security/ASSURANCE.md) binds separate technical proof. The
[existing realization record](../../../.scratch/llull-buzz/issues/02-realization-plan.md) now points
to concrete selections, not unselected architecture. Later code/build/test bindings remain implementation
work. This proposal and its synthetic examples claim no executable conformance or human verdict.
