# Initial Buzz wire and compatibility profile

Revision: `bz-wire-v1`; parent contract `llull-buzz integration v0.2`;
realization `bz-restricted-2026-09/v1`. Status: proposed definitions, not a runtime API.

## Encoding, admission and canonical intent

Use HTTPS JSON for owned adapter commands and queries; native clients retain NIP-42 WebSocket,
NIP-98 and Blossom protocols. Owned command shapes are in
[the schema](schemas/buzz-wire-v1.schema.json); review scenarios are in
[the example catalog](examples/buzz-wire-v1.json). JSON Schema validates shape, not signatures,
authority, clocks, database transactions, native compatibility or UAT.

Reject duplicate keys before deserialization, unknown properties/actions, invalid UTF-8, non-finite
numbers and integers outside the interoperable exact range. Monetary limits use integer micro-USD;
content/artifact hashes are lowercase SHA-256 hex. Canonicalize the entire immutable command
object using RFC 8785/JCS (`serde_jcs` 0.2.0), then SHA-256 its UTF-8 bytes. This digest excludes
HTTP headers and the external assertion, avoiding self-reference. All strings are preserved as
specified by JCS; do not silently normalize human content or alter an approved attachment.

`intent_id`, correlation/causation, resource revision and body stay fixed on retry. A fresh trace
belongs in the HTTP trace header, not a rewritten command. Unique scope is consumer + operation +
intent; mismatch is 409. Release/assertion `jti` prevents credential replay, not effect identity reuse.
A retransmission needing a fresh assertion receives the same durable operation/result.

## Resource authentication and invocation evidence

Owned APIs require NIP-98 proof by the registered consumer service key, verified over method,
actual registered public URL and request bytes. Persist replay claims atomically through the
`buzz-auth` replay-guard seam. A proxy cannot choose the verified public host from an untrusted
forwarding header. Registration independently limits consumer, API operation and provider resources.
Native end-user key enrollment is a different binding and never borrows this service key.

Consequential requests also carry `X-Llull-Invocation`: ES256 JWS with purpose-specific `typ` and
an exact registered `iss`/`aud`. The header is opaque evidence to infrastructure logs and is redacted.
No token-provided `jku`/`x5u`, arbitrary issuer discovery, unknown critical header or alternate algorithm.
The initial profile uses `llull-invocation+jwt`, `llull-publication+jwt` and `llull-evidence+jwt`.

Required claims: `iss`, `aud`, `sub` (executing principal), `consumer_id`, `intent_id`, `operation`,
`resource`, `resource_revision`, `payload_sha256`, `policy_revision`, `authority_epoch`,
`recovery_epoch`, `iat`, `exp`, `jti`. Consequential delegated work additionally binds
`represented_principal`, `delegation_id`, `root_task_id` and `grant_revision`; required verdicts
are exact action/resource/revision/digest records or references revalidated at the registered authority.
Omission of a represented principal means the executing principal acts only for itself, not anonymous
delegation. The resource credential and assertion must identify the same registered consumer/service.

`exp - iat` is at most 60 seconds; clock tolerance is at most 30 seconds and cannot renew root expiry,
authority lease or a retired recovery epoch. Registration fixes key refresh/revocation and consumer
status ports. Recheck current epoch/grant and required verdict/release at effect admission. A worker
may refresh unchanged authorized intent through the trusted issuer without prompting a human again;
changed recipients/content/resource/revision needs a new applicable verdict. Missing verification
fails closed for new effects. Read/reconcile past results uses separately current record-access scope.

## Owned routes and exact meanings

The profile deliberately adds these adapter routes; it does not invent new upstream client routes.
Path identifiers and body identifiers must agree. GET/query requests also bind method/path/query
through resource authentication and purpose evidence where required by the registered scope.

| Route | Payload / result | Capability |
| --- | --- | --- |
| `GET /integration/v1/profile` | Contract/profile/schema digests, enabled operations, client source and limits | BZ-C01 |
| `POST /integration/v1/enrollments` | `enroll` command; challenge transaction and expiry, not an active binding | BZ-C02 |
| `POST /integration/v1/enrollments/{id}/proof` | `prove-key`; native signed event; atomic challenge consumption and binding revision | BZ-C02 |
| `POST /integration/v1/access-changes` | `change-access`; expected binding revision and revoke/restore of one enrollment | BZ-C02 |
| `POST /integration/v1/conversation-intakes` | `intake`; verified native source and content/evidence digests; durable receipt | BZ-C03 |
| `POST /integration/v1/tasks` | `start-task`; closed admitted tool declarations and original root budgets | BZ-C04 |
| `GET /integration/v1/tasks/{id}` | Scoped task/generation, state, attempts and existing effect-owner references | BZ-C04 |
| `POST /integration/v1/tasks/{id}/cancel` | `cancel-task`; expected generation; no claim of remote rollback | BZ-C05 |
| `POST /integration/v1/tasks/{id}/reconcile` | `reconcile-task`; same root/attempts and original provider lookup | BZ-C05 |
| `POST /integration/v1/publications` | `publish`; frozen native destination/audience/release/content/attachment hashes | BZ-C06 |
| `GET /integration/v1/publications/{id}` | Durable publication intent, persisted signed native event ID and known/unknown outcome | BZ-C06 |
| `GET /integration/v1/evidence/{id}` | Metadata/registration readiness; authorized bytes through native media release gateway | BZ-C07 |
| `GET /integration/v1/observations?cursor=...&limit=...` | Maximum 100 records, scoped committed high-water mark and next cursor | BZ-C08 |
| `POST /integration/v1/observation-acks` | `ack-observations`; consumer durable receipt and contiguous cursor prefix | BZ-C08 |

HTTP 202 acknowledges a committed admission transaction; 200 covers a replay or query; 401/403
means invalid authentication/authority; 409 is intent or expected-revision conflict; 410 is a retired/
expired cursor with explicit recovery coordinates; 422 is unsupported schema/profile. Oversize input
is 413 before acceptance. Temporary admission unavailability is 503 with bounded retry advice and
no claim that an external effect failed. Errors expose opaque IDs, not protected input or evidence.

## Typed payload rules

The schema's tagged command payloads are closed. `start-task` declares a registered tool schema ID
and digest for every admitted operation/resource. The gateway resolves these to locally compiled
Serde command types; no payload may introduce a new server, executable, URL or general execute
operation. The model receives a task-bound handle, not the underlying signing/service credential.

`enroll` fixes issuer/subject, intended key, community and module before challenge creation.
`prove-key` supplies a native signed event object; signature/destination/challenge/key checks are
mandatory runtime checks, not satisfied by its JSON shape. `change-access` uses one enrollment and
expected revision. Restoring access never restores a revoked key or unrelated module membership.

`publish` freezes text and attachment digests plus audience policy/revision/release. A text digest
is SHA-256 of the exact UTF-8 text; attachments bind original bytes and release metadata. Native
previews/filenames/thumbnails/diagnostics are part of the release, not an ungoverned extra channel.
`intake` records native source identity independently of whether consumer evidence registration has
completed. `ack-observations` cannot advance beyond a contiguous durable receipt or purge records.

## Results, cursor and interruption

The result object always identifies contract/profile, consumer, intent, operation ID, immutable
request digest, admission state, execution state and a monotonically increasing operation revision.
It may carry `effect_refs` (owner, stable intent, resource, outcome) and `evidence_refs` (source/hash,
bytes readiness, consumer registration readiness). These are references, not copied operational truth.
A conflict preserves the prior operation and identifies the mismatch without echoing restricted input.

Observation records carry schema/profile, consumer, recovery epoch, committed sequence, stable event
ID, operation ID/revision, kind and scoped result reference. Sequence allocation locks the consumer
counter until the observation transaction commits. Cursor plaintext binds consumer/profile/epoch/
sequence; authenticate it with a rotating provider HMAC key. Store only the cursor/key version and
non-secret audit references. A client cannot forge another consumer or skip uncommitted sequences.
ACK advances only after the consumer's durable transaction. Cursor expiration/restore is explicit 410,
followed by scoped snapshot/current-operation reconciliation and a newly issued high-water mark.

Persist task/effect attempts before dispatch. Worker/child replacement must compare generations and
reuse root reservations. An unknown effect retains its reservation and queries its original owner;
it never silently resends under another identity. Publish stores the exact signed event bytes/ID
before dispatch, so a lost relay response is reconciled by the original ID or retried identically.
A fiscal result/evidence remains committed when later mail or conversation publication fails.

## Applicability and evidence

BZ-PF01..07 cover verification, process/ACP isolation, native release, durable/cursor faults, budgets,
media and exact-profile evidence respectively. BZ-UAT01..05 separately judge user-visible completion,
enrollment, evidence, publication and recovery. Example expected outcomes are design assertions;
parsing/schema checks do not turn them into executed conformance tests or human verdicts.
