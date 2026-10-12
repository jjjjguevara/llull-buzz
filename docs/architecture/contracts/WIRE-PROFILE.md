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

Publication may include `reply_to_event`, the exact lowercase SHA-256 native
message ID being answered. It is part of the frozen publication and release
digest. Before signing and sending, the publisher resolves that signed kind-9
message through its fixed native owner and checks its channel and identity. The
selected upstream message builder adds the native reply tag. A changed or
unavailable source cannot silently become a new channel message. Omission keeps
the original publication serialization; historical commands and receipts are
unchanged. Consumers must qualify the new advertised schema digest before using
the optional field. This field supplies correlation, never release authority.

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
| `GET /integration/v1/evidence/{id}` | Original signed metadata and separate consumer registration readiness | BZ-C07 |
| `POST /integration/v1/attachment-retentions` | `retain-attachment`; exact original intake descriptor, private-origin bytes and separate durable receipt | BZ-C03/07 |
| `GET /integration/v1/evidence/{id}/attachments/{sha256}` | Fresh artifact-specific EvidenceAccess; retained exact bytes, no native/public share URL | BZ-C07 |
| `POST /integration/v1/native-attachment-leases` | `lease-native-attachment`; explicit current EvidenceAccess for one original attachment and proved enrollment | BZ-C07 |
| `POST /integration/v1/native-handoffs` | Optional `read-native-handoff`; fresh browser human, proved enrollment and current native audience; navigation only | BZ-C02/03 |
| Native `GET/HEAD /media/{sha256}` | Same-origin Blossom identity plus one current exact attachment lease; no range, preview or upload | BZ-C07 |
| `GET /integration/v1/observations?cursor=...&limit=...` | Maximum 100 records, scoped committed high-water mark and next cursor | BZ-C08 |
| `POST /integration/v1/observation-acks` | `ack-observations`; consumer durable receipt and contiguous cursor prefix | BZ-C08 |

HTTP 202 acknowledges a committed admission transaction; 200 covers a replay or query; 401/403
means invalid authentication/authority; 409 is intent or expected-revision conflict; 410 is a retired/
expired cursor with explicit recovery coordinates; 422 is unsupported schema/profile. Oversize input
is 413 before acceptance. Temporary admission unavailability is 503 with bounded retry advice and
no claim that an external effect failed. Errors expose opaque IDs, not protected input or evidence.

## Original attachment retention extension (source increment, 2026-10-10)

`retain-attachment` uses a closed `{"source_id":"<intake UUID>","evidence":{...}}`
payload and resource `{namespace: consumer_id, ref: "<intake UUID>/<sha256>", revision: "1"}`.
It requires the registered service's current `retain-attachment` action and invocation
purpose. The full descriptor must equal one in the immutable signed original intake
in the same consumer/module/context. The configured native owner performs a bounded
read from its private `/media/<sha256>` route with a short-lived exact-hash BUD-11
`get` token. It does not fetch the sender's `imeta` URL or issue a host-wide token.
The source must return HTTP 200, the exact declared MIME type and byte length, and
matching SHA-256. Missing/redirected/partial/mismatched bytes do not become durable
attachment evidence. The adopted maximum is 25 MiB per attachment, at most 32 per
original intake; this is not a storage-capacity qualification.

Migration 0007 retains verified bytes with the original source identity. The insert,
command receipt and observation commit together. A fresh-authority replay returns
the original receipt; another unchanged retention intent uses the same immutable
bytes. Lost responses are retried under the same command identity, never a new source.
Historical intake receipts retain their original `attachment_bytes_durable` value.
A retention receipt does not create or change the consumer's evidence registration.

The byte GET requires fresh NIP-98 plus `llull-evidence+jwt`, operation
`read-attachment`, intent equal to the intake UUID, the same source/hash resource
revision `1`, and the empty-body digest. Current service/enrollment, module, context,
policy, recovery epoch and original retention deadline apply before bytes are read.
The response is an attachment with `application/octet-stream`, `nosniff` and
`no-store`; declared active media types are never rendered by this surface.

This additive schema changes discovery's schema digest and must be adopted explicitly
by consumers. The native client Blossom upload/GET/HEAD release gateway, attachment
publication, transformations/previews and browser/native attachment journeys remain
unqualified and unavailable through this increment. No current audience release or
consumer evidence authority is replaced by the new retention route.

## Native original-byte lease extension (source increment, 2026-10-11)

This additive operation realizes the registered assertion/lease option in
[BZ-R05](PROVIDED-REQUIRED.md). It changes the advertised schema digest and requires
deliberate consumer adoption and explicit registration of `lease-native-attachment`.
It does not change `read-attachment`/`retain-attachment`, activate the restricted
profile, or qualify the complete native media gateway.

The lease POST requires registered service NIP-98 plus `llull-evidence+jwt` over
the complete immutable command. Resource: original `<intake UUID>/<sha256>`,
revision `1`. The closed payload supplies `source_id`, exact retained `evidence`,
existing `enrollment_id` and positive `enrollment_revision`, `audience_policy`,
`audience_revision`, `release_ref` and absolute `expires_at`. The registered
consumer issuer attests that this exact person, source, artifact and audience
policy may receive these bytes now. Signed `release_ref` is consumer provenance,
not a new provider authority registry or permission inferred from an opaque
reference. No approval or delegated task grant is invented. Service-key possession
without the exact current EvidenceAccess assertion cannot mint a lease.

The native key comes only from the previously proved active enrollment in the
same consumer/module. The fixed original native owner must confirm the original
channel's current audience revision and membership, including the requester.
Migration 0008 records immutable custody of the original assertion, enrollment
revision/epoch, source, context, owner and expiry. Lease, command receipt and
observation commit together. Retry preserves the original receipt and expiry;
fresh transport never renews it. Expiry beyond the original assertion, authority
freshness or original intake-retention deadline is rejected. The lifetime is at
most the existing 60-second EvidenceAccess bound. Historical custody remains
retained after expiry, without conferring access.

Native GET and HEAD bind the configured relay authority, exact bare SHA-256 path
and signed BUD-11 `get` proof. The selected CLI
[`sign_blossom_get`](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-cli/src/client.rs)
emits a server-tagged kind-24242 proof lasting 600 seconds. It proves identity
only; it never extends EvidenceAccess. Every request rechecks current registration,
policy/recovery epochs, proved enrollment revision/epoch/key, original retention,
fixed owner, actual native audience and final expiry. A foreign key, missing or
expired lease, or multiple current leases for the key/hash denies access rather
than guessing a consumer/source. Callers must keep the lease unambiguous; a second
intent does not supersede or renew the first.

GET returns exact digest-checked bytes as an inert download (`no-store`, `nosniff`,
`application/octet-stream`). HEAD runs the same authority and integrity checks
before returning length without bytes. Conditional requests, ranges, transformed
suffixes, thumbnails, uploads and attachment publication remain unavailable.
Frontdoor routing must reach this adapter on the configured relay origin and keep
the private native owner inaccessible. Authored routes do not prove installed
containment. Actual CLI, PostgreSQL, restart, revocation and composed attachment
journeys remain unrun for this increment.

## Current human native navigation extension (source increment, 2026-10-12)

The optional [native-handoff-v1 schema](schemas/native-handoff-v1.schema.json)
defines a closed Command-shaped request and a separate `response` definition.
Consumers adopt its RFC 8785 SHA-256 digest and provider source pin explicitly.
The historical `bz-wire-v1` schema and discovery response retain their existing
meaning and digest. Registration must explicitly include `read-native-handoff`;
older profiles do not acquire this action automatically. The native owner must
also be configured. Configuration and source checks do not activate the profile.

The POST uses existing service NIP-98 authentication over the exact URL and body,
plus `X-Llull-Invocation` with purpose `llull-invocation+jwt`. The consumer issuer
binds the exact resource/revision, payload fingerprint, module and context to
current record access and an existing destination. Resource namespace equals
the registered consumer. The payload is exactly `community_id`, `channel_id`,
`audience_revision`, and explicit null or lowercase event hash `event_id`.
It cannot create a channel, select a network origin, supply a callback, carry a
prompt, or authorize a publication or task.

This new action requires a proved active enrollment, its current revision and
authority epoch, `represented_principal` equal to its subject, and existing
`browser_authentication` matching its issuer/subject. Browser authentication
must be no older than 60 seconds and unexpired; stale login requires a recent
sign-in. `delegation_id`, `root_task_id` and `grant_revision` must all be null;
`verdicts` must be empty and `release` null. No agent grant is invented for a
human navigation read. Existing actions retain their delegated-authority gate.
Registration, module issuer policy, recovery epoch, current binding, native
audience and final invocation/browser expiry are revalidated on every request,
including a reused intent. The read stores only existing authentication replay
and admission evidence; it creates no mutation receipt, task or observation.

The fixed native owner verifies any requested signed kind-9 event and its
existing thread root in the exact channel, then reads the current audience last.
The audience revision must match exactly and contain the proved native key.
The response format is `llull-buzz-native-handoff/v1`, identifies the complete
request/binding/destination scope, and expires at the earliest invocation expiry,
browser expiry or browser authentication time plus 60 seconds. `verified_until`
is Unix seconds. Consumers compare every echoed identity and reconstruct the
expected URI; schema validation alone cannot establish that correspondence.

The selected [desktop](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/desktop/src/shared/deep-link.ts)
and [mobile](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/mobile/lib/shared/deeplink/deep_link.dart)
parsers support `buzz://channel/<canonical UUID>` and
`buzz://message?channel=<canonical UUID>&id=<lowercase hash>[&thread=<root hash>]`.
No community selector, authentication grant, consumer data or callback is added.
The native app uses its own current key/relay and enforces its channel access.
The link is navigation, not an authenticated app switch or a business effect.
The consumer keeps its original browser tab, actor, route, draft and unresolved
command custody, provides explicit return guidance, and revalidates current
access when the user returns. The separate native identity-binding callback
must not be repurposed. Actual native return, PostgreSQL and composed journeys
remain unqualified until executed against the admitted candidate.

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

### Completed task and separately admitted native publication

Task completion attests the known business effects. It stops new work and does
not grant native output release. A completed or otherwise stopped root cannot
perform a new root-bound publication; an admitted pending publication cannot be
rebound by removing its original root from the assertion. Terminal delivery
observation and original-owner recovery retain their existing meanings.

A consumer may separately admit a publication under its current native policy,
required human verdicts and exact destination/content/audience release. Its
ordinary publisher then uses the existing rootless `publish` service action
with that separately verified release. This is a distinct native publication
intent, not a revived task, fresh model budget or permission inferred from a
completed effect, model text, channel membership or a task grant. Consumer
business completion and the publication's pending/unknown/completed status must
remain distinct. A lost native acknowledgement retains the exact signed event
and requires original-owner lookup; it cannot cause another submission.

This clarification adds no action or schema. Two controls appended to the
existing provider publication suite exercise completed-root denial, denied
rebinding, independently released signed replies, exact unknown recovery,
changed release/audience denial and unchanged completed root/budgets. They and
compilation remain authored/unrun; source inspection is not native/consumer or
human qualification.

BZ-PF01..07 cover verification, process/ACP isolation, native release, durable/cursor faults, budgets,
media and exact-profile evidence respectively. BZ-UAT01..05 separately judge user-visible completion,
enrollment, evidence, publication and recovery. Example expected outcomes are design assertions;
parsing/schema checks do not turn them into executed conformance tests or human verdicts.
