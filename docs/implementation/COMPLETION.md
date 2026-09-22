# Restricted provider completion

Work is in progress under [task 04](../../.scratch/llull-buzz/issues/04-provider-completion.md).
The stopping criterion is the complete accepted provider and applicable qualification,
including an isolated test deployment. [Slice 1](SLICE-1.md) and
[its validation](LOCAL-VALIDATION.md) remain historical evidence, not the current scope limit.

## Implemented continuation

`Provider::discover_profile` supplies independently authenticated discovery at
`GET /integration/v1/profile`. The enrolled service supplies fresh NIP-98 and ES256
evidence for operation `discover-profile`, intent `profile`, resource `profile`
revision `1`, and SHA-256 of empty bytes. `X-Llull-Consumer` selects only the registered
consumer to verify. The response includes the exact schema digest, source pin,
registration/policy/recovery revisions and only the admitted module's actions/domains.
It returns no verification PEMs, credentials or unrelated module configuration.

`Provider::observations` implements `GET /integration/v1/observations` for enrolled
service delivery. Evidence binds operation `observe`, intent/resource `observations`
revision `1`, and empty body digest. Optional query parameters are canonically encoded
as `cursor` then `limit`; the exact public URL, including the query, is NIP-98 signed.
Pages contain at most 100 content-minimal records for the current module/context.
The per-consumer sequence counter and event insert share the command transaction.
Ordering therefore follows committed transactions, without a timestamp or standalone
sequence allocator that can put a late commit behind an acknowledged cursor.

`POST /integration/v1/observation-acks` accepts an `ack-observations` command with
`{"cursor":"...","durable_receipt_id":"..."}`. HMAC-SHA256 cursors bind profile,
consumer, module, context, recovery epoch and the exact delivered interval. ACKs
advance only a contiguous prefix, retain immutable receipt identity and do not purge
source records. Reconnect without a cursor resumes from the persisted ACK. ACKs do
not recursively generate more observations. Expired/retained-out cursors produce an
explicit HTTP 410 gap. The recovery snapshot surface is still being completed.

Migration `0002_observations.sql` adds the journal, counters, offsets, receipts and
trusted gateway cursor keys. `rotate_observation_key` retains verification of previously
issued 24-hour cursors. Cursor keys stay outside the agent runtime and consumer APIs.
Normal observations contain provider references/status, never admission JWS, private
keys, model transcripts or enrollment proof contents. Full native/output mediation
and background-effect observation coverage remain under implementation.

## Local execution to date

The portable documentation stage passed on
`8b447d8203d373c011b7b7326a690da6d0015f0b`: both helper self-tests, six new checkout
regressions, complete-checkout checks, and unchanged supplemental ownership/schema
assertions. It covered 21 components, eight capabilities, six required ports,
14 commitments, seven technical profiles, five human case definitions and six schema
examples. This is documentation evidence only. Historical hosted failures remain intact;
the Actions workflow now requires manual dispatch while hosted capacity is exhausted.

New discovery and observation tests first failed on missing implementation. Three
new PostgreSQL scenarios subsequently passed in the working tree using PostgreSQL
16.15 and actual Nostr/ES256 verification. The observation test helper initially
unwrapped an intentionally invalid page-size result; that test-driver error was fixed
without removing the denial assertion. Final committed-source reruns and full-suite
regressions are recorded separately; a working-tree pass is not a pass of its parent SHA.

The HTTPS owner scenario now uses the production `HttpConsumer` transport against
an independently listening TLS server and a separate PostgreSQL database. The owner
verifies native signatures, ES256 evidence, exact command identity and its own current
authority inside its commit transaction. A useful `SetLabel` write commits, its response
is deliberately lost, and original-owner lookup returns the retained result with one
write. The provider then explicitly completes the task. A second request pauses after
dispatch; an owner-side revocation denies it before the write. An untrusted TLS root
also fails. This synthetic owner is protocol evidence, not composed application UAT.

The initial runtime attempt failed before any owner commit because the generated
certificate was marked as a CA certificate. The fixture now generates a leaf certificate
and asserts the owner commit before testing recovery. The corrected working-tree
scenario passed on 2026-09-22. `HttpConsumer::with_roots` permits operator-selected
private PKI with normal chain/hostname verification; no insecure TLS mode is added.

`POST /integration/v1/conversation-intakes` implements the schema's closed `intake`
payload. It authenticates the service before retrieving an exact native event from a
fixed private relay. It verifies the native signature, event/channel/content identities,
declared signed attachment metadata and the sender's active module enrollment. The
original event, its byte digest and historical enrollment revision are immutable in
PostgreSQL. Retries recover that retained original even when the relay is unavailable.
The source receipt explicitly distinguishes message-byte durability, attachment-byte
durability and consumer registration; native membership alone is not intake authority.

`GET /integration/v1/evidence/{source_id}` requires fresh artifact-specific evidence
purpose authentication for `read-evidence`, exact source resource/revision and current
module/context scope. `POST /integration/v1/intake-registrations` is an owned wire
addition: `register-intake` with closed `source_id` and `durable_receipt_id` payload.
It records the consumer's durable receipt independently of source storage or observation
ACK. The historical bootstrap schema remains unchanged; it does not describe this
additional command. Complete runtime schema inventory is still being assembled.

`HttpNativeOrigin` uses pinned upstream `/query` and `/events` protocol shapes, fixed
operator origins and NIP-98 authentication. `NATIVE_ORIGIN_CONFIG` selects community,
private/public origins and an owner-only service-key file. No caller supplies a URL or
signing credential. Migration `0003_native_intake.sql` adds the immutable source and
registration records. A new real PostgreSQL/signature ledger test passed after the
missing-implementation red and a corrected fixture tuple destructure. Its source
transport is an explicit fixture; actual relay/client qualification remains separate.

The dedicated Ubuntu 24.04.4 arm64 test VM now runs Docker Engine 29.8.1,
containerd 2.3.5 and runc 1.5.1. Only this task's daemon was upgraded. Package installation
initially rejected Colima's held versions; explicitly installing the selected versions
in the task-owned VM succeeded. This establishes environment identity, not a completed
containment test. The unmodified pinned relay, native CLI, admin CLI, ACP and agent image
build is in progress using immutable Rust/Debian base digests.

`Provider::publish` now adds durable delivery to publication admission. It checks the
current native audience, signs through the pinned `buzz-sdk` message builder, persists
the exact signed event and original native owner, and commits uncertainty before
dispatch. The subsequent dispatch rechecks current task/authority and audience under
the admission lock. The deployment must mediate every native mutation and subscriber
through that boundary; private-origin isolation and full native gateway tests are still
being completed. An unmediated native writer would invalidate the audience-race proof.

Migration `0004_publication_delivery.sql` retains original admission scope/root and
immutable native bytes independently of monotonic delivery state. An admitted publication
cannot drop its canceled root or adopt a different authority scope on retry. Historical
preflight records predating this scope ledger remain retained; they cannot silently
become new dispatch authority. `GET /integration/v1/publications/{id}` exposes scoped
state and original event identity. The owned `reconcile-publication` command at
`POST /integration/v1/publications/{id}/reconcile` performs only original-owner lookup;
an outage or miss cannot establish denial before effect. Audience changes do not prevent
learning that the original event already committed, and do not authorize another send.

The real PostgreSQL/signature publication ledger test passed in the working tree on
2026-09-22 after a missing-implementation red and correction of an SDK iterator use.
It covers lost response, one native event/send, immutable bytes, changed-audience denial,
and canceled-root/identity preservation. Its native transport is a declared fixture;
actual relay and client execution must qualify the production `HttpNativeOrigin` path.
That adapter verifies pinned relay signatures on native metadata/membership snapshots
and binds their identities into the release's audience revision. Native origin configuration
now also requires the relay public key. Health output reports configured surfaces
separately from the still-in-progress qualification status.

The complete seven-scenario PostgreSQL suite passed at clean source
`953767bbda59018ebe4b9f9aad19126937a6e3a4`, including the historical foundation
case. Its command log SHA-256 is
`b1a8a8c4fcd0f2a0cd298e925feb4d3c3cebbce69c255ccbc0ae1037c6739148`.
All twelve workspace library tests also passed at that source (log SHA-256
`ce81ffdd8205656bbdd8bcbf845bbc9b0212f5d8fcb776636e2ef82e437074d4`).
The native relay transports in the intake/publication cases remain declared fixtures.

### Observation snapshot recovery

`POST /integration/v1/observation-snapshots` accepts a closed empty payload under
`create-snapshot` authority for the consumer's `observations` resource at revision 1.
It freezes the latest retained observation for each stable operation identity in
the authorized module/context at one committed high-water boundary. It includes
minimal operation/resource references and outcomes, not source content or signatures.
Current task/source/publication reads retain their separate authorization gates.

`GET /integration/v1/observation-snapshots/{id}` requires `read-snapshot` authority
for that snapshot resource. Pages contain at most 100 records. Random page handles
are stored in PostgreSQL and bound to the snapshot; they cannot select an arbitrary
offset or supply independent read authority. Snapshots expire after 24 hours and
cannot cross the external recovery epoch. New work after capture is excluded from
the frozen pages and remains available through subsequent observation delivery.

Only the final-page handle can accompany `ack-snapshot` at
`POST /integration/v1/observation-snapshots/{id}/ack`. The signed command binds the
snapshot, handle and consumer durable receipt. This advances the scoped observation
offset without erasing history; an incomplete snapshot cannot silently skip a gap.
Reusing a durable receipt for another cursor now produces an explicit conflict,
rather than a database-error response. Snapshot creation/ACK produce no recursive
observation events. Migration `0005_observation_snapshots.sql` preserves immutable
snapshot rows, entries and handles.

The new PostgreSQL scenario passed in the working tree after a missing-method red
and a correction to its native-enrollment fixture: one existing principal cannot
silently replace its native key between modules. It exercises a retention gap,
module/cursor denial, immutable capture during new work, incomplete-ACK denial,
duplicate receipt handling and reconnect after durable snapshot acceptance.
Background task/effect event coverage and retained business-result reads remain
under implementation; this snapshot result alone does not close BZ-C08.

## Requested OAuth model amendment

## Isolated selected storage stack

[`scripts/local-stack.py`](../../scripts/local-stack.py) owns a private Docker
network and uniquely labeled PostgreSQL, Valkey and SeaweedFS resources in the
task's Docker 29.8.1 VM. It requires an explicit `DOCKER_HOST`. Named volumes
hold PostgreSQL data, SeaweedFS data and private config; no host path or socket
is mounted into a service. PostgreSQL 16.15 gives the provider, native relay
and Seaweed filer distinct database roles. SeaweedFS 4.47 uses its PostgreSQL
filer rather than its image's default leveldb2 store. The static S3 identity
is restricted to the synthetic `buzz-media` bucket, and Valkey 8.1.10 is
password protected and explicitly disposable. The Seaweed and Valkey processes
run as UID 65532 with a read-only root filesystem and no Linux capabilities.
Synthetic credentials and exact resource ownership stay in ignored
`artifacts/completion/stack` with private file modes.

The selected Docker engine/version check, immutable image digests, private
network, database-role denial, authenticated S3 PUT/GET/range, anonymous-read
denial and cross-bucket denial passed in the task VM. The exact command was
`python3 scripts/local-stack.py check-storage`, with `DOCKER_HOST` pointing at
that VM and `DOCKER_CONTEXT` empty; exit 0 and log SHA-256
`d46af8c75b116c9fd120833adab9efbd3a7cdc95305b864d86c0f6cd4f4abca6`.
The object digest and image digests are retained in the private test evidence.
The earlier failed attempts exposed a filer schema omission, filesystem UID
copying, and a four-volume limit consumed by the empty collection; these were
corrected in the task-only recipe. A raw `nc` request also returned empty
GET bytes after half-closing its socket, so the passing test uses curl's real
SigV4 and HTTP transport from an ephemeral, restricted client container.
This qualifies the storage component; native client authorization, media
disclosure, relay restart and backup/restore are separate gates.

## Pinned native relay and media disclosure counterexample

The same task-owned Docker 29.8.1 stack now starts the unmodified
`block/buzz@01b6174a1cbad249e93f31df97d4b2ed1d0e8638` relay and uses
its `buzz` and `buzz-admin` clients. The image ID is
`sha256:a66ab3005e2a458772109b98233bf5a48c21315e80bf55d703381e94acefa5b4`.
The relay runs unprivileged with a read-only root, no Linux capabilities,
an owned data volume and no host-published port. Its startup Git-store
conformance probe passed. `scripts/local-stack.py check-native` exited 0:
the real client created a private channel, signed and recovered a message,
denied an unenrolled identity, hid channel metadata and messages from an
enrolled nonmember, allowed a channel member to recover the retained message,
and removed that access after roster revocation. Upstream represents a hidden
private-channel query as an empty result, not an HTTP error. The fixed
synthetic event ID and channel ID are in the ignored task-local report.

`scripts/local-stack.py probe-media` uploaded a valid synthetic PNG through
the real Blossom client, attached it to an accepted signed private-channel
message and verified its `imeta` digest; its owner recovered identical bytes
by SHA-256. An unenrolled identity was denied. **The artifact-disclosure gate
failed:** a relay-enrolled bot with no private-channel membership recovered
the exact attached blob by its hash. The probe records
`enrolled_nonchannel_read_denied: false` and intentionally exits nonzero;
the counterexample digest is
`6935ddb5b3ba39a86e03f7394829f2e65f88003d311927b26e97db59537a9464`.
The pinned upstream media read checks Blossom signature and relay membership,
but this deployment cannot treat either as artifact-specific release. The
relay remains on an internal task network and the restricted profile is not
activated. Provider media mediation and bypass-proof client routing remain
required under BZ-PF03 and BZ-PF06.

`scripts/local-stack.py restart-native` exited 0 after restarting only its
owned relay. The original signed message event and the original media digest
were recovered with the same image. This is a process-restart check, not
PostgreSQL/Seaweed backup restoration or media authorization evidence.

## Isolated synthetic storage restoration

`scripts/local-stack.py backup-storage` quiesces only containers carrying this
task's owner label, then takes custom-format dumps of the provider, native and
filer PostgreSQL databases and tar copies of the Seaweed data and relay data
volumes. It includes the disposable test identities and expected event/media
references in the ignored owner-only backup directory; this is not a
production key-backup or encryption design. Valkey is intentionally disposable.
Each copy has a digest and size in the private manifest.

The first backup copied the data but exposed a startup-ordering fault: the
relay restarted before SeaweedFS could serve its authenticated retained object,
then exited during its Git-store conformance check. The corrected command
waits for an exact authenticated S3 read before starting the relay and for an
original signed event read before reporting success. Its later run exited 0.
The first fresh restore reproduced the same ordering failure; that run was
interrupted after the relay exit, and the failed target was removed using only
its own owner labels. The corrected `restore-storage` now applies the same
Seaweed readiness gate before starting the relay.

The corrected fresh run used `up-storage --state
artifacts/completion/restore-8b05` followed by `restore-storage --state
artifacts/completion/restore-8b05 --backup
artifacts/completion/backups/e71c6b57ac04409c8836337d6aea8950`; both
exited 0 with `DOCKER_HOST` set to the task VM and `DOCKER_CONTEXT` empty.
Manifest SHA-256 was
`6865188e5a72c7c80b009fe6cf7e86fedb1166fc14b89470100d019b1311e688`.
The new owner was `afaf2b5f87ac4b83abf069d5a1f4eeb0`, distinct from the
source `1866114f818d4b29b325b582c8a83197`. The restored relay recovered
the original signed event
`4c32971568c08e6a34c5fe4bcbea15aed49697e25450aa31ae57c2ba4548ea9f`,
the exact PNG digest
`6935ddb5b3ba39a86e03f7394829f2e65f88003d311927b26e97db59537a9464`,
and the private-channel revocation denial with a new empty Valkey cache.
Provider command/effect records were not populated in that dump, and protected
key restoration remains unqualified.

The owner directed Codex/ChatGPT Pro OAuth for this continuation. The installed
`codex-cli 0.155.1` reports a ChatGPT login. Pinned Buzz supports the OpenAI Responses
transport through `OPENAI_COMPAT_API=responses` and an owned base URL, so the Buzz
agent loop can remain unmodified. The observed Codex source is
[`be2951ea34f0d295ed0becf97079f92fa5f6950e`](https://github.com/openai/codex/tree/be2951ea34f0d295ed0becf97079f92fa5f6950e).
Its [provider configuration](https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/model-provider-info/src/lib.rs)
selects the ChatGPT Codex backend for subscription authentication.

One synthetic transport request for `gpt-5.6-luna` with a requested 256-token output
limit returned HTTP 400, `Unsupported parameter: max_output_tokens`. No completed
model response or provider qualification is claimed. Compatibility work must preserve
finite root reservations and report the output-limit difference; removing a failing
parameter cannot by itself establish the required bound. No paid API fallback or
unlimited subscription capacity is inferred. Credential values are never recorded.

The [official authentication documentation](https://learn.chatgpt.com/docs/auth)
distinguishes ChatGPT subscription authentication from API-key billing. That distinction
remains explicit in the amended configuration and eventual evidence.
