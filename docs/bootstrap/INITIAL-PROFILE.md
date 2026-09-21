# Initial restricted Buzz provider profile

Profile: `bz-restricted-2026-09/v1`. Contract realization: `llull-buzz integration v0.2`.
Status: proposed engineering selection; no runtime, security, performance or human acceptance is claimed.
This profile realizes the existing BZ capabilities. It is not a mandatory language, identity vendor,
model or hosting arrangement for every consumer. Original project distribution rights remain an
explicit owner decision; upstream's license does not license this project's original work.

## Selected composition and supported seams

Select Rust 2021 adapters, compiled with Rust 1.98.1, around standalone `buzz-acp` and
`buzz-agent` from `block/buzz` commit `01b6174a1cbad249e93f31df97d4b2ed1d0e8638`.
The workspace package version is 0.1.0 and its minimum Rust version is 1.88.0.
The commit, not that non-unique package version, identifies the upstream implementation.
Use the same-source native desktop/mobile clients and message deep links, NIP-42 WebSocket
authentication and Blossom media authentication. Built client/image digests remain build evidence.

Use upstream `buzz-sdk` for supported relay operations and `buzz-auth`/`nostr` for native
signature verification. Select `rmcp` 1.1.0 for the governed stdio MCP boundary, Serde for
closed typed envelopes, Axum/Tokio for the adapter HTTP/WebSocket services, SQLx/PostgreSQL
for durable records, and `jsonwebtoken` 10.4.0 with `aws_lc_rs` for ES256 invocation verification.
The [component inventory](../architecture/components/REGISTRY.yaml) records exact source and
license qualification. There is no custom cryptographic primitive or replacement model loop.

The inspected ACP and agent crates have private orchestration modules; their library files are
not a promise of an embeddable public orchestration API. Adopt their executables. The ACP
agent-command seam launches an owned wrapper; that wrapper mediates ACP protocol version 2,
normalizes `session/new` declarations and launches the unmodified agent. The agent's supported
`ANTHROPIC_BASE_URL` selects the owned model-admission proxy. Its stdio MCP declaration
selects only the owned tool bridge. No patch to a native client or upstream core is selected.

Logical ownership is concrete, although a logical component need not be a separate deployment:

| Process / module | Authority and durable owner | Allowed connections |
| --- | --- | --- |
| Provider control API and native-protocol gateway | Enrollment, admission, observation cursors and access leases; provider PostgreSQL | Registered consumer authority/context APIs, private relay, provider ledger, key verification endpoints |
| Trusted task supervisor and ACP wrapper | Task generations, reservations, process lifecycle and declared ACP configuration | Provider ledger, restricted runtime, governed tool and model boundaries |
| Restricted ACP/agent runtime | No business or publication authority; disposable context | Native relay protocol only through the provider gateway; model proxy; single admitted MCP bridge |
| Governed tool gateway | Typed consumer request admission, result lookup, effect-attempt records | Exact registered consumer command/query endpoints; never an operational database |
| Publisher and media release gateway | Publication intents, audience/content release and authorized native events/media | Private relay and private media store; consumer release/context ports |
| Model proxy | Vendor credential, model/request allowlist, cumulative reservation and usage settlement | Anthropic Messages/token-counting API only |
| Relay and media services | Native conversation/media storage, not consumer business truth | Their own PostgreSQL, ephemeral presence service and private object storage |

The agent cannot reach the relay, public internet, cloud metadata, a host Docker socket, SSH agent,
consumer service credentials or signing keys directly. Run it non-root with a read-only root,
empty task-specific HOME, no host project mount and a bounded writable scratch volume. The
supervisor has process-control authority but exposes no arbitrary execution endpoint to the model.
Separate the trusted credential-bearing processes from the restricted process namespace.

Both process inheritance and ACP-carried `mcpServers[].env`, executable, arguments and working
directory are closed allowlists. Upstream `mcp.rs` deliberately passes several signing, SSH and
proxy environment variables and applies wire declarations; `env_clear` alone is therefore not
containment. The wrapper removes these inherited values and replaces declarations before launch.
The only bridge executable is an image-owned fixed binary, with a task-scoped local handle that
cannot select another task or consumer. No arbitrary shell, `buzz-dev-mcp`, dynamic skill loading,
model-discovered server or general signing tool is admitted. Upstream hook and reply-nag behavior
is advisory; it is never an approval, publication, budget or revocation gate.

## Identity, independent enrollment and intended-key proof

Provider API resource authentication uses NIP-98 signed HTTP requests from a separately enrolled
consumer service key. Reuse `buzz-auth::verify_nip98_event` and its atomic replay-guard seam.
Bind the public HTTPS URL, method and SHA-256 of the actual request bytes; do not verify a
proxy-rewritten URL or trust client-supplied forwarding headers. Store replay claims durably per
consumer/community. A valid key proves possession, not a consumer entitlement or business grant.
Check the registered service key, allowed profile and provider-local resource scope independently.
The key remains in the trusted consumer adapter; it is not the human's client key.

Consequential API invocations additionally carry `X-Llull-Invocation`, an ES256 compact JWS.
The registration fixes its exact issuer, purpose-specific `typ`, audience, allowed action set,
verification keys and consumer namespace. The initial purpose values are `llull-invocation+jwt`,
`llull-publication+jwt` and `llull-evidence+jwt`; audiences are separately registered service origins.
There is no token-derived key URL: reject unregistered `jku`, `x5u`, issuer or audience, unknown
critical headers, duplicate claims and algorithm substitution. `kid` selects only an admitted key.

Claims bind executing principal, represented principal when applicable, delegation/grant reference,
consumer, root task, action, resource, resource revision, canonical payload digest, policy revision,
authority/recovery epochs, `iat`, `exp` and `jti`. Verify each required human verdict against the
same exact intent, target, revision and digest; mere presence of an approval identifier is insufficient.
Issuer registration determines which authority can attest those facts. Resource authentication and
invocation evidence must agree on the consumer and executing service. Neither replaces the other.

The signature lifetime is at most 60 seconds, with at most 30 seconds of clock tolerance; tolerance
does not extend root-task expiry or the 60-second authority lease. Reject future `iat` beyond that
tolerance. Revalidate current enrollment, authority epoch and required release/verdict state before
an effect. A queued operation needs fresh evidence from the registered trusted authority, not a
new user prompt when its existing exact-intent approval is still valid. Changed intent needs a new
approval. Unknown or unavailable required verification denies new effects, not result recovery.

Human enrollment reuses the consumer's authenticated issuer/subject. No employee password or
universal role directory is created. For the initial Workspace-compatible enrollment profile, verify
the consumer's signed enrollment assertion after its fresh browser authentication; the provider does
not receive the browser's Workspace credential. Other issuers can register equivalent profiles.

The authenticated browser enrollment transaction first fixes the **intended public key**, community,
consumer, issuer/subject and requested module. The provider then issues a random single-use
five-minute challenge. Through an ordinary native-client signed message to the enrollment bot,
the intended key returns that challenge and enrollment transaction ID. Verify the native event's
signature, destination/community, challenge, expiry, fixed key and still-authenticated transaction.
Consume the challenge and create the versioned binding in one transaction. A different key cannot
win a race by replying first. A supplied key, invitation, email address or challenge alone proves
neither side of the binding. Pre-enrollment channels carry no restricted information.

Native keys use the clients' secure storage and native encrypted pairing with the short-authentication-
string check. Each module retains its own enrollment and resource grants. Removing conversation
access does not delete a person or revoke unrelated mail/fiscal enrollment. No consumer role names
are built into the provider. Historical principal/key associations and event signatures are immutable.

Lost-key recovery requires fresh authentication, explicit old-key revocation and a replacement-key
challenge. Restore only currently permitted memberships. Retire affected task contexts and cached
observer transcripts. Do not impersonate the old key or rewrite history. Native encrypted private-
message history needs the user's old key or paired backup; explain this before retirement. Required
operational history uses relay-retained access-controlled channels and registered evidence rather
than relying exclusively on a recoverable personal decryption key.

## Bounded revocation and context retirement

Refresh active identity/authority/membership state at least every 30 seconds, complemented by
change notifications. A successful authoritative refresh grants at most a 60-second stale-admission
lease. Reachable surfaces target acknowledgment within 30 seconds. A notification is a wakeup,
not proof that every surface applied the change. Report per-surface pending and completed state.

Every new command, tool dispatch, model-context release, native event delivery, media read and
publication checks a current lease. The gateway closes stale connections and denies forwarding;
the private relay is not reachable around it. On epoch/domain change, fence the task generation,
cancel model work, retire the warm context and drop its caches. A disconnected worker cannot
keep using old context after its lease expires. Persist revocation state before acknowledging it.
Already committed effects remain committed. Restoration increases a provider recovery epoch;
pre-restore sessions, reservations and capabilities never become fresh merely because storage was
restored. Historical results remain discoverable with fresh, independently authorized access.

## Task admission, useful completion and cumulative limits

BZ-C04 accepts a versioned typed task manifest: consumer, root task/intent, permitted command
schema IDs, resource scopes/revisions, context domain, model profile, absolute expiry, exact-intent
verdict references and the finite budgets below. BZ-C05 changes or reconciles that durable task.
The model supplies proposed arguments, never its own principal, tenant, role, approval or grant.
Use closed Serde request types and schema digests; reject unknown operations/fields and unexpected
resource bindings. A consumer rechecks its business rules at its own commit boundary.

| Initial review default | Limit / meaning |
| --- | --- |
| Model generation attempts | 8 per root episode, including retries, compaction and child work |
| Tool admissions | 32 per root episode; failed/uncertain admitted attempts consume their reservation |
| Input | 32,000 admitted input tokens per generation; 128,000 cumulatively |
| Output | 16,000 cumulatively; each request's `max_tokens` is bounded by the remaining reservation |
| Monetary admission | USD 1.00 per root episode; reserve maximum admitted request cost before dispatch |
| Absolute lifetime | 10 minutes from original root admission; human waiting does not reset it |
| Request timeout | Model 180 seconds; consequential tool 30 seconds, both capped by remaining lifetime |
| Concurrency | 4 root episodes per deployment; child work shares parent admission capacity |
| Process recovery | At most 3 automatic runtime restarts within the same root lifetime and remaining budgets |

Use row-locked PostgreSQL reservations with one root budget shared across workers, retries,
steering, handoffs and children. Reserve before exposing a request to any effect-capable boundary.
A worker lease is 30 seconds, renewed every 10 seconds; all writes compare its generation. Timeouts,
process kills and lost responses do not prove an effect did not happen. Unknown reservations are
not refunded. A replacement first reads durable attempts and reconciles existing results; it cannot
create a new root identity to replenish authority, cost or time. Human wait is a durable state, not
an indefinitely running model. A genuinely new episode needs a new authority decision.

Select Anthropic `claude-sonnet-5` through Messages API with adaptive thinking, text/image context
and typed tools. Omit manual `budget_tokens`, non-default sampling parameters and unsupported
provider tools. Disable prompt caching in this initial pricing profile. The model proxy admits the
registered model/request shape, checks token-counting results and reserves the configured input
and maximum output allowance before sending. If it cannot establish an admissible bound, reject
rather than send an unbounded request. The reviewed base rate is USD 2/million input and
USD 10/million output; store a dated pricing-profile revision, not a permanent price assumption.
Unknown pricing or model identity blocks admission. External billing/usage can differ from an
estimate: retain unknown reservations at their maximum, record any excess as a profile incident,
and stop subsequent admission. The USD limit is a finite admission reservation, not a guarantee
about an external vendor's invoice. Actual accounting accuracy remains a required technical test.

The profile permits real authorized completion: a typed consumer command may commit an approved
business action, an evidence operation may retain an authorized artifact, and the publisher may
send an authorized result. It is not a blanket read/propose-only mode. Consumer-owned business,
mail and fiscal effects use their own stable intent IDs and result lookup. The provider keeps their
references and accountable outcomes, never a duplicate business ledger or direct database path.

Before each remote effect, persist the attempt ID, request digest, owner, root reservation and
expected revision. After the response, persist the actual outcome before reporting completion.
`end_turn`, an ACP stop, a tool timeout or a dropped connection is not a success oracle. A lost
response produces `effect-unknown`; query the existing effect owner using the same identity.
Never switch providers or resend under a fresh identity to make uncertainty disappear. Reconciliation
can continue as authorized recovery after episode expiry, but cannot add new business effects.

## Audience-controlled publication, native clients and evidence

BZ-C06 is the sole provider publication owner. It freezes destination, audience policy/revision,
content digest, attachment digests, allowed preview and explicit copy permission in a durable intent.
The publisher rechecks fresh release authority and actual destination membership immediately before
signing/forwarding. Reading restricted context does not authorize exporting it. Use a permitted
summary/link by default; a full copy requires explicit release of those exact bytes and recipients.
A changed audience, changed content or changed evidence digest invalidates the old release.

All provider-origin output is mediated: ordinary replies, notifications, previews, attachment metadata
and bytes, progress, observer transcripts, errors and diagnostics. The runtime has no signing key
that can reach the relay around the gateway. ACP's automatic content-bearing events are denied
unless they match an admitted publication record. Presence/control frames use a closed non-content
schema. A separate publisher tool lets the agent finish useful authorized work without depending
on native advisory reply heuristics. No unrestricted transcript is mirrored to a broader channel.

The selected transparent native-protocol gateway preserves NIP-42, NIP-98, event IDs/signatures,
Blossom GET/HEAD/upload and native deep links. It is an additive server-side adapter, not a client
fork. Upstream media verifies key possession and relay membership; those checks alone are not
an artifact-specific release decision. The gateway additionally maps each media digest/thumbnail
to its provider-owned release and intake record, verifies the requester and current audience policy,
and denies unregistered restricted media. Direct relay/media/object-store origins and administrative
routes are private. No public bucket or reusable signed URL bypasses this boundary. A requested
native surface that the gateway cannot completely mediate is unavailable in this profile, not
silently admitted; proving complete coverage is BZ-PF02/03/06 implementation evidence.

The initial operational profile admits native access-controlled channels, not consumer-required
records stored only in encrypted direct messages that the adapter cannot inspect. Private native
messages outside this provider profile do not become governed task input by accident. Audience-
permitted context is selected before model access. When an existing publication is read after a
membership change, the current policy decides whether the new reader may receive that historical
content; the gateway does not equate joining a channel with permission to every retained artifact.
Already delivered recipient copies cannot be recalled by revocation.

BZ-C07 keeps original native message/attachment identity, content hash, intake status and consumer
registration status distinct. Upload success means provider bytes are durably retained and checked;
consumer evidence registration has its own durable acknowledgment. Unregistered bytes are never
reported as complete consumer evidence. Fetches are bounded, same-origin or registered-host only,
with redirect revalidation, private-address/metadata denial and explicit size/media-type limits.
Treat all fetched text as data. Default adapter control requests are at most 1 MiB, individual intake
artifacts at most 25 MiB, and observation pages at most 100 records; reject excess explicitly before
acceptance. These are initial operating-profile limits, not universal product ceilings.

Provider publication is separate from a consumer's operational Web Push path. The consumer owns
its durable notification inbox/outbox, subscriptions, notification policy, browser permissions and
Push result. BZ-C08 supplies authenticated observations/correlation. This profile neither assumes
configurable native Buzz push nor substitutes a native client fork for consumer-owned Web Push.

## Durable operation, observation and recovery contract

Provider PostgreSQL owns consumer registrations, historical key bindings, authority/recovery epochs,
task roots/generations, budget reservations, effect attempts, intake registrations, publication intents,
release grants, observations and consumer acknowledgments. Native relay tables remain relay-owned.
Use unique `(consumer, operation, intent_id)` keys with the frozen payload fingerprint. Same intent
and payload returns its recorded result/current reference; a changed payload is `conflict`, not an
edit. Admission `accepted` means the provider transaction committed, not that a remote effect or
publication completed. Consumer acknowledgment means its durable receipt committed, not business
success, recipient reading or deletion permission.

| Adapter API surface | Stable capability and semantics |
| --- | --- |
| `GET /integration/v1/profile` | BZ-C01; contract/profile/schema digests, limits and unavailable capabilities |
| `POST /integration/v1/enrollments`, `POST /integration/v1/enrollments/{id}/proof`, `POST /integration/v1/access-changes` | BZ-C02; authenticated two-sided enrollment and versioned access lifecycle |
| `POST /integration/v1/conversation-intakes` | BZ-C03; native source identity, digest and durable normalized intake |
| `POST /integration/v1/tasks`, `GET /integration/v1/tasks/{id}` | BZ-C04; durable admission and independent result observation |
| `POST /integration/v1/tasks/{id}/cancel`, `POST /integration/v1/tasks/{id}/reconcile` | BZ-C05; compare generation, stop new work, retain committed/unknown effects |
| `POST /integration/v1/publications`, `GET /integration/v1/publications/{id}` | BZ-C06; immutable authorized publication and uncertain-delivery lookup |
| `GET /integration/v1/evidence/{id}` | BZ-C07; authorized registration/metadata; byte access is separately authorized |
| `GET /integration/v1/observations`, `POST /integration/v1/observation-acks` | BZ-C08; ordered scoped recovery and durable consumer acknowledgment |

These are owned adapter routes to implement, not claims of existing upstream routes. Commands
carry the common envelope in the owning contract; native-client protocol endpoints are unchanged.
Use 202 for durable asynchronous admission, 200 for replay/observation, 401/403 for authentication/
authority failure, 409 for changed intent/revision, 410 for expired observation cursor and 422 for
unsupported schema/profile. Errors return opaque operation/trace references, not protected content.

Observation sequence allocation locks a per-consumer counter in the same transaction as each
observation, so an uncommitted lower sequence cannot later appear behind an acknowledged cursor.
Cursor payload binds consumer, profile, recovery epoch and sequence and is authenticated by the
provider; it is not a timestamp. Pages give a committed high-water mark. ACK advances only through
a contiguous durably accepted prefix. Retain/redeliver until ACK or the explicit enrolled retention
policy, and return a gap with snapshot/result-reconciliation references rather than silently skipping
expired history. A lost native stream is recovered by history query with overlap and event-ID dedup;
an unfillable upstream history gap is visible and never represented as complete intake.

Publication persists the exact signed native event and its ID before network dispatch. Retry the same
event bytes/ID, not a newly signed duplicate. A relay receipt and subsequently observable event are
publication evidence; user receipt/reading is separate. An uncertain relay response is reconciled by
that event ID. Consumer-owned mail/fiscal recovery always queries that provider, not the relay.

## Operating topology, custody and distribution

Select persistent Linux containers on Ubuntu 24.04 LTS, Docker Engine 29.8.1 under systemd, with
an independent provider-owned PostgreSQL 16 database. The initial GCP deployment uses private
Cloud SQL connectivity, Secret Manager/KMS v1, and SeaweedFS 4.47's S3 surface for native media
with a separate PostgreSQL filer database. Valkey 8.1.10 is presence/cache only, never the task or
publication ledger. Separate restricted runtime, trusted control services, relay and object storage
network identities. No Kubernetes or consumer database is required. Exact image digests and
ordinary resolved dependency leaves are produced by the later build, not invented here.

The operator owns provider data custody and supplies explicit region, retention schedule, legal holds,
backup destinations and service quotas before live onboarding. Registration requires concrete raw-
intake, publication, evidence and audit retention rules; absence prevents accepting that data class.
Acknowledgment is not an implicit purge instruction. Purge workers honor holds and reference
ownership, delete bytes only under the enrolled policy, and retain non-secret deletion/audit receipts.
No secret, private consumer note or internal source reference belongs in published provider records.
Anthropic access requires the operator's approved data-processing terms; no zero-retention or
residency promise is inferred from an API model name.

Review recovery targets are RPO 15 minutes, regional RTO 4 hours and process/zone recovery within
30 minutes. Use PostgreSQL continuous recovery plus encrypted object backup and a manifest of
object generations/digests. Restore to a fenced namespace, disable outbound effects, advance the
recovery epoch, reconcile unknown attempts and only then resume admission. Daily backup checks
and monthly/release restore exercises are later technical evidence, not completed tests here.
The initial single provider topology has a finite failure domain; these targets are not an HA/SLA
certification or permission to incur cloud/model cost now.

The original llull-buzz license/distribution decision remains **unanswered** after record review and
an explicit owner question. Apache-2.0 is recommended for original reusable code/documents;
proprietary commercial distribution is the alternative. Do not publish a fabricated license or
infer an open-source grant from repository visibility. This blocks declaring distribution-ready
bootstrap completion, not authoring the neutral contracts or inspecting Apache-licensed upstream.

## Acceptance and implementation boundary

BZ-PF01..07 and BZ-UAT01..05 remain stable identities. The profile's new assertion, native gateway,
reservation, cursor and recovery semantics require updated technical fixtures and affected human
case versions. [Assurance](../architecture/security/ASSURANCE.md) owns technical expectations;
[UAT](../acceptance/UAT-CATALOG.md) owns human judgments. Synthetic examples demonstrate
reviewable intent, not executable conformance. Positive permitted completion is mandatory.

Later implementation supplies these named adapters, migrations, closed schemas, dependency
resolution, images and real fault/cryptographic/process tests. It does not select a new architecture
or reinterpret the public capability commitments. The sole designated reviewer assesses the
submitted documentation; the execution author does not resolve findings, approve or merge.

## Primary source bindings

- [Pinned workspace and declared SDKs](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/Cargo.toml).
- [ACP executable/library boundary](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-acp/src/lib.rs).
- [Agent configuration and model proxy seam](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/config.rs).
- [MCP inheritance and restarts](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-agent/src/mcp.rs).
- [Native auth primitives](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-auth/src/lib.rs).
- [Blossom verification](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-media/src/auth.rs) and [actual media admission](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-relay/src/api/media.rs).
- [jsonwebtoken 10.4.0 source/license](https://github.com/Keats/jsonwebtoken/blob/69a8fbf40a83c3d87301e75148e02b2090e4feed/Cargo.toml).
- [Rust 1.98.1 release](https://github.com/rust-lang/rust/releases/tag/1.98.1).
- [Sonnet 5 request compatibility and pricing](https://platform.claude.com/docs/en/models/sonnet-5/whats-new-sonnet-5).
