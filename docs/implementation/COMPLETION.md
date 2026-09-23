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

## Private provider image and pinned native origin

The provider image built from committed source
`eae913c6e4c9a9d4cfcf25bbd2c59be648aba438` on the selected Docker Engine
29.8.1 using BuildKit, an exact-ID local dependency-builder layer and immutable
Debian base. `scripts/build-provider-image.sh` archives the committed tree and
checks the image's source label. The image ID is
`sha256:e6707c512639123882dbd0ed134619c5d01054cb292634db9e1dcf101e6525b1`;
the Linux arm64 provider binary SHA-256 is
`5e11d861d2cb28be4d5ffc69d46ab1bcaf8fb4366b1908c3891e1f755daa34d4`.
The successful build log SHA-256 is
`0a7898bf2ceb4e4516f25d0296d685066da101a0664f189a403ce14f358be38d`.
The preceding full legacy-builder run compiled the release binary but was
interrupted during a long image-layer commit; the successful image reused that
builder layer. A clean independent final image build and complete OS notices
remain open.

`scripts/local-stack.py up-provider --provider-source eae913c6e4c9a9d4cfcf25bbd2c59be648aba438`
enrolled a synthetic service in the original private channel, migrated the
isolated provider database and started the provider as UID 65532 with a
read-only root, no Linux capabilities and no host port. The first admin enrollment
attempt exited 5 during a competing image build; a redacted retry succeeded,
and the owned deployment then exited 0. `check-provider` exited 0 before and
after the owned process restart. Health reports native intake and publication
delivery configured, but model dispatch, native gateway and media gateway false;
qualification remains `in-progress` and the restricted profile inactive.

The first `switch-native-wss` recipe changed the public URL from
`ws://buzz-relay.synthetic.invalid:3000` to
`wss://buzz-relay.synthetic.invalid`. Pinned upstream treats the host **and
non-default port** as tenant authority. That switch created a new empty
community; its admin list contained only the owner, while the service and
original event remained in the old community. The signed native-origin probe
failed. Commit `8ec269206ebbb86d776b406c8c52a364addf4649` preserves
`buzz-relay.synthetic.invalid:3000` while changing the scheme to `wss` and
signing `https://buzz-relay.synthetic.invalid:3000`. The corrected admin list
contained the enrolled service. The production `HttpNativeOrigin` probe then
exited 0 against the unmodified pinned relay: original event
`4c32971568c08e6a34c5fe4bcbea15aed49697e25450aa31ae57c2ba4548ea9f`,
retrieved byte digest
`5687040ef6378848c883704cd1358cb047a2a71c545743a5f9a91a9e3bb8a483`,
and current two-member audience revision
`9ee50d635e7761cb481a2cef03b7ce498c885f4f9a42cec9d2dae0de5f93f43c`.
This proves the fixed-origin signed read, not consumer command admission,
publication through the live process, an external TLS terminator or native
client compatibility over TLS. The source stack remains private and profile
activation is still prohibited.

The corrected WSS-posture `backup-storage` command exited 0 from clean
`8ec269206ebbb86d776b406c8c52a364addf4649` script source. It quiesced
only the owned provider, relay and SeaweedFS, then restarted them in dependency
order and used the signed fixed-origin probe to verify the original event.
The command log SHA-256 is
`07473efd374c1ba94efcf082ac8b7ba4ca8843f8c26917851e1013eb8320c78d`;
the private manifest SHA-256 is
`1794af5ed6a918307b0ca9177a15f32f9b22266d87e0c5e8315dfacf4f872b18`.
The first WSS-posture backup also exited 0, but its wrapper expected one JSON
document while the command printed both the readiness probe and backup report.
The script now suppresses the nested report; the clean-source run parsed one
report. Subsequent provider health and signed native-origin checks exited 0.
This is a quiesced backup/restart check, not a fresh WSS restore of populated
provider effects or protected production keys.

## Live publication and populated restore

The `live_provider_publishes_one_signed_event_to_pinned_relay` integration case
was compiled in the selected Linux arm64 Docker 29.8.1 VM and executed as UID
65532 against the running provider image from `eae913c6e4c9a9d4cfcf25bbd2c59be648aba438`,
actual PostgreSQL and unmodified pinned relay. The manually invoked test at
source `c3d6bd0ef19a02ce2a4fc1fb9c974b4a7e95a42e` exited 0; its owner-only
log SHA-256 is `83de1724375ec0499293234679d3b09e21ba9ed3ba4c35d7a009c8ea8be7b5c3`.
A synthetic signed `publish` command completed, the exact event was fetched
from the relay and matched PostgreSQL's retained signed bytes, and a fresh
signed retry of the same command returned the original event identity with
one publication ledger row. The logged event ID is
`21a2906a6af601dfdbbe53940a393e649aacccd88941f5015fbf0bfc966f3672`.
This is real text publication, not an attachment or native-client gateway pass.

The first scripted container attempt failed on compiler-image selection, then
missing offline dev dependencies, then a root/UID 65532 key-file permission
boundary. A later script compiled the test executable but hit its 30-minute
window while Cargo also compiled the provider CLI; its target artifacts were
retained. The corrected runner separates public dependency fetch, no-network and
credential-free compilation, and UID 65532 execution with synthetic secrets on
the private network. `check-publication-live` exited 0 at committed test source
`b8399e74db3795852ae4d011e0ccaf0045840ab1`; its compiler and test log
SHA-256 is `b9f85c3ba5bf5383a9284ef188e53b503d734320089db5e2cb84bfe6e0d0ddc4`.
The Linux release build finished in 33 minutes 56 seconds; one named test
passed with native event ID
`0dedff134b9fc8b8c1308785850bdb5c53a985e2883c223a6f489e9095ba08fb`.
The compile container had no network, provider environment or service-key
mount; the separate read-only UID 65532 container received only synthetic
test credentials on the owned private network. Subsequent source-stack
`check-provider` also exited 0.

The source stack's subsequent `backup-storage` and fresh `restore-storage`
into owner `6369e174a9194176b500cf99151878eb` both exited 0. The source
owner was `1866114f818d4b29b325b582c8a83197`; the private backup manifest
SHA-256 is `b5c486d487f4d17293f293705bc339238972047fcae7800c7fd6eab53802fcda`.
Two completed publication rows, including their original native event IDs and
signed-byte digests, matched after restore, and the restored owner client found
both native events. The original media digest and revoked-channel denial also
recovered. `check-provider` exited 0 on the source stack after backup. This
does not qualify protected service-key restore, external TLS, native gateway
mediation or a lost upstream publication response.

Attachment compatibility is still open. The pinned
[`buzz` CLI media URL validator](https://github.com/block/buzz/blob/01b6174a1cbad249e93f31df97d4b2ed1d0e8638/crates/buzz-cli/src/client.rs#L270-L334)
refuses to sign a media GET on an origin different from its configured relay.
The current [publisher assembly](../../crates/buzz-provider/src/main.rs) gives
`Publisher` the provider origin for attachment URLs, while the native client
uses the relay origin. A governed gateway on that relay origin and actual
artifact-specific authorization are required before attachments can work
without bypassing release policy. This is pinned-source inspection, not a
passing attachment test.

The subsequent archived test source
`68cc4d2498429c271341650b0e743da02644abb9` added a relay fault proxy
that forwards a signed `/events` request to the real pinned relay, waits for
its accepted receipt, then returns HTTP 502 to the provider. The provider
recorded an unknown publication; reconciliation queried the original relay
owner and completed the same signed native event. The test observed one relay
submission. `check-publication-live` exited 0 in the selected Linux arm64
runtime with **two passed, zero failed** tests, including the earlier positive
publish/same-command retry. Its private combined log SHA-256 is
`c527f91e5e7d6470d99b5fa218706512ac7977fbbd38ef6bee8bc19e5584c2ae`;
the build took 23 minutes 49 seconds and test execution 9.04 seconds. The
provider source/image remained
`e87d1b87571e28bf99531cba670e5ecba889b575` /
`sha256:daba1b7d778e8f17140ef2d41568a1683046c621a88eda2aab7a7bdafebcf50c`.
`check-provider` exited 0 afterward, with model/native/media gateways still
disabled and the restricted profile inactive. This qualifies relay response
loss and original-owner lookup for text publication; process death after
dispatch, changed audience, attachments and client-gateway delivery remain
separate tests.

A subsequent quiesced `backup-storage` from the source stack and fresh
`restore-storage` into independently owned namespace
`6b06c138d9864adf9b92018ce4f168d9` both exited 0. The backup manifest
SHA-256 was `da8e9a74e54ea59b2f95d5594b2f1432da2e89e2f6cd1712636d9b2ea0fe92e6`.
The restore compared all five completed publication rows, including the
lost-response event identity and signed-byte digests, found the original native
event and media bytes, and rechecked revoked-channel denial. Its private
`restore-check.json` records `exact_event_and_media_recovered: true`,
`revoked_channel_read_denied: true`, and `publication_rows_recovered: 5`.
Protected production-key restoration and restoration of an unresolved in-flight
effect remain unqualified.

## Distribution inventory in progress

Host `cargo +1.98.1 metadata --locked --offline` resolved 338 workspace graph
packages. `cargo +1.98.1 tree --locked --offline --target aarch64-unknown-linux-gnu
-p llull-buzz-provider -e normal,build` identified 222 distinct package versions
after collapsing repeated `(*)` tree entries for the selected provider target.
The new `scripts/distribution-inventory.py` copied exact source-package license
and notice files, including the workspace-root Apache text for original and
pinned Buzz crates. The two CC0 Bitcoin crates and `nostr` lacked license text in
their published crate archives, so their full texts were taken from matching
pinned upstream commits. Those three upstream file hashes are enforced by the
script and recorded in [the source register](../../deploy/licenses/README.md).

The host inventory command exited 0 with 222 declared licenses and zero missing
texts. Its private manifest SHA-256 is
`96c56e0a775a350602c911ff89ad1f31ea41b39320edc8e652b4bc1166520a52`.
The revised provider Dockerfiles now run that check during their builds and
record installed OS package names, versions, architectures and copyright-file
hashes. The cached-builder image from committed source
`e87d1b87571e28bf99531cba670e5ecba889b575` built with ID
`sha256:daba1b7d778e8f17140ef2d41568a1683046c621a88eda2aab7a7bdafebcf50c`.
Its executable SHA-256 is the same
`5e11d861d2cb28be4d5ffc69d46ab1bcaf8fb4366b1908c3891e1f755daa34d4`
as the prior live-tested image. The build log SHA-256 is
`0cbefb75f364aab6478f95b925ccd021fc46cb3039a1eb57c8bb9c5bef3fe870`.
Inside the Linux image the applicable graph has **221** packages with zero
missing license texts; the host-only `core-foundation-sys` accounts for the
host inventory's extra entry. The image's bundled manifest SHA-256 is
`5be1b47d2064e15ed8ba244967a0369a1f901f1e4def4387f97fce18cb793484`.
The task-owned provider was switched to this image; `up-provider`,
`check-provider` and `probe-provider-origin` exited 0. This image still uses an
inspected cached dependency builder, so a clean independent distribution build
remains unqualified.

Inside the deployed image, 91 installed Debian packages each had a readable
`/usr/share/doc/<package>/copyright` after architecture suffix normalization.
It bundles a sorted 91-row package/version/architecture manifest and hashes
for 90 distinct copyright files. The extra package shares a copyright file;
the build checks each package's readable path. A clean independent build and
final source/image applicability checks remain before distribution closure.

The pinned unmodified Buzz executable graph has a preliminary host target
inventory of 500 packages. Eighteen registry archives omit local license
texts; the inventory maps them to checked upstream files or, for one declared
`MIT OR Apache-2.0` package, the selected standard Apache-2.0 option. The host
command exited 0 with zero missing texts, manifest SHA-256
`a28c861da05626d5350ad2e26509b07dc36bd152821b46b4224829cc09ebc219`.
The updated upstream image recipe has not yet been built; its Linux-applicable
package graph and OS notices require image inspection before closure.

## Requested OAuth model amendment

The owner directed Codex/ChatGPT Pro OAuth for this continuation. The installed
`codex-cli 0.155.1` reports a ChatGPT login. Pinned Buzz supports the OpenAI Responses
transport through `OPENAI_COMPAT_API=responses` and an owned base URL, so the Buzz
agent loop can remain unmodified. The observed Codex source is
[`be2951ea34f0d295ed0becf97079f92fa5f6950e`](https://github.com/openai/codex/tree/be2951ea34f0d295ed0becf97079f92fa5f6950e).
Its [provider configuration](https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/model-provider-info/src/lib.rs)
selects the ChatGPT Codex backend for subscription authentication.

One synthetic transport request for `gpt-5.6-luna` with a requested 256-token output
limit returned HTTP 400, `Unsupported parameter: max_output_tokens`. A separate
`codex exec --ephemeral --ignore-user-config --sandbox read-only --model gpt-5.6-luna`
probe using the ChatGPT login exited 0 and returned `OK` with no tool call. Its reported
usage was 17,960 input tokens and five output tokens; the private JSONL log SHA-256
is `49f6438698d2a939af60cd53499b7942da1d84d8d308604781c142aeee56bb69`.
This confirms subscription-backed Codex execution for one synthetic prompt, not a
Buzz agent/model-proxy call or a pre-dispatch output bound. Compatibility work must
preserve finite root reservations and report the output-limit difference; removing a
failing parameter cannot by itself establish the required bound. No paid API fallback
or unlimited subscription capacity is inferred. Credential values are never recorded.

The [official authentication documentation](https://learn.chatgpt.com/docs/auth)
distinguishes ChatGPT subscription authentication from API-key billing. That distinction
remains explicit in the amended configuration and eventual evidence.

## Free-tier Gemini test route and upstream agent execution

The owner subsequently authorized a new Google free-model test API in the existing
`llull-buzz` Cloud project. Google AI Studio imported that project, but its first
key-creation attempt returned “The request is suspicious.” The Google Cloud CLI
then enabled `generativelanguage.googleapis.com`, `apikeys.googleapis.com`, and
`iam.googleapis.com`; a dedicated service account and a service-account-bound,
Generative-Language-only key were created. The first CLI creation unexpectedly
printed key material despite an output-format restriction. That key was deleted
immediately. The replacement was captured only to an ignored local file,
`artifacts/completion/secrets/gemini-api-key` (mode 0600). An active-key listing
showed one bound, API-restricted replacement and no deleted original. Cloud Billing
reported `billingEnabled: false`; AI Studio showed this key's project as **Free
tier**. No paid billing account or test-spend ceiling was added. Google documents
the [auth-key requirement](https://ai.google.dev/gemini-api/docs/api-key),
[OpenAI Chat Completions compatibility](https://ai.google.dev/gemini-api/docs/openai),
and [Gemini 3.6 Flash free-tier pricing](https://ai.google.dev/gemini-api/docs/pricing).

The currently available `gemini-3.6-flash` returned HTTP 200 for bounded Chat
Completions. A 64-token request returned `finish_reason=length` without visible
content; a 256-token request with `reasoning_effort=low` returned `OK` and
`finish_reason=stop`. A synthetic `set_label` tool-call probe with a 512-token
bound returned one structured call containing the requested item and label.
`gemini-2.5-flash` returned HTTP 404 for this new project, with Google's model
retirement message. These are transport probes, not business effects.

The unmodified pinned `buzz-agent` executable from upstream image
`sha256:a66ab3005e2a458772109b98233bf5a48c21315e80bf55d703381e94acefa5b4`
also completed a real ACP `initialize` → `session/new` → `session/prompt` turn.
It emitted an `OK` message chunk and `stopReason=end_turn`; the private result
SHA-256 is `1fd68012f62e5d1a43272904fa515b4d12a63dac72b4cfe4f0f4a319b3b3302c`.
The agent ran without the Google key on the task-owned internal Docker network.
A task-owned, locally scripted test proxy held the key in a read-only secret
volume, used a separate egress network, and enforced one model, low reasoning,
a 1,024-token per-request maximum and a four-request process-local limit.
Its image ID was
`sha256:f0f9abb1515abf91dfd32b12d60347241731f5ace95f6d11a04e6da182230c1b`.
The proxy was an ignored local test harness, not a durable model gateway: no
task/generation reservation, live MCP business bridge, governed publication,
selected Sonnet 5 profile, or complete `buzz-acp` supervision is qualified.

## Dependency advisory findings

Task-local `cargo-audit 0.22.2` fetched RustSec database revision
`f7dc4b2860b29978f400fda0aab31cc4dbd21134`. Before remediation, the
provider lock had one vulnerability,
[RUSTSEC-2026-0189](https://rustsec.org/advisories/RUSTSEC-2026-0189.html)
in `rmcp 1.1.0`, plus one unmaintained-package warning for `instant`.
The affected rmcp transport is Streamable HTTP; the existing probe uses stdio.
The direct dependency and lock were updated to `rmcp 1.4.0`, which contains the
fix. The revised lock SHA-256 is
`5f81524ddb7076a45690d189ca378d1b66d75e8cde6e00e04f209858c785e0b5`.
`cargo +1.98.1 check --locked -p llull-buzz-launch` and its three library
tests passed; the repeat provider audit reported zero vulnerabilities and one
unmaintained warning. The revised Linux image and MCP process probe remain to
be run against this lock.

The immutable pinned upstream lock separately reported four vulnerability
entries across `quick-xml 0.38.4` and `0.39.4` for
[RUSTSEC-2026-0194](https://rustsec.org/advisories/RUSTSEC-2026-0194.html)
and [RUSTSEC-2026-0195](https://rustsec.org/advisories/RUSTSEC-2026-0195.html),
plus two unmaintained and two unsoundness warnings. This is a distribution
security finding, not an accepted exception or evidence of exposure on every
runtime path. Pinned-upstream revision and affected parser use require review
before security qualification.

The pinned `buzz-media` code uses a plain `Reader` for S3 version listings and
does not iterate XML attributes. Version 0.38.4 also enters through `rust-s3`
and its credential parser; 0.39.4 enters through `iroh`/`netdev` and Mesh LLM
dependencies of `buzz-relay`. The advisories identify checked attribute
iteration and `NsReader` as the vulnerable operations. The direct media parser
does not establish reachability of either operation, while transitive parser
paths and input provenance remain to be audited. No blanket waiver is claimed.

The first actual `buzz-acp` launch initialized the pinned agent through a
separate credential-free process container, then failed NIP-42 authentication
with `relay url mismatch`. The relay advertises
`wss://buzz-relay.synthetic.invalid:3000`, while that probe dialed `ws://`.
This is a real transport/configuration failure, not a model or agent pass.
The pinned build currently trusts only WebPKI roots for WebSocket TLS. The
distribution recipe now additionally enables Cargo's
`tokio-tungstenite/rustls-tls-native-roots` feature without changing upstream
source, so a task-local CA can qualify the selected WSS origin. At that point
the amended executable and complete ACP/native journey were unexecuted.
Operator CA distribution and the agent's separation from the bot key require
runtime checks.

The task-owned TLS terminator subsequently served the exact advertised WSS
host and port on a second internal Docker network, forwarding to the original
relay without publishing a host port. A short-lived synthetic CA signed a
leaf with the exact DNS SAN. `openssl verify` exited 0. A TLS client trusting
that CA reached the relay and received HTTP 200; a wrong hostname and a client
without the CA each failed certificate verification. The terminator image ID
was `sha256:83b5982891746e067748c169c05ed51b5611b2d260c004183e3ec072b3f4d692`.
The real `buzz` CLI then completed a signed channel search over the verified
HTTPS endpoint. A separate synthetic channel was created and the test bot
enrolled there; the provider service channel was left untouched.

With that CA installed in the test image, the original WebPKI-only `buzz-acp`
still initialized the separate `buzz-agent` but exited 1 on an unknown TLS
issuer. Its private log SHA-256 is
`a7dd3d0a3e4c5cc7b7d8d8e8062b2f05f684e8fefce8cd8bf17edaee548149e8`.
This red test isolates the missing native-root feature from the previously
observed NIP-42 URL mismatch. The later amended build and journey results are
recorded below. These task-only TLS fixtures are not a production certificate
or credential-delivery design.

## Selected PostgreSQL runner and current source checks

The first `scripts/test-postgres.sh` run at `24afe6f15eab19c246faf745dd1b4d0809122af5`
exited 101: seven cases passed, the two live-relay cases failed because the
disposable database runner did not supply their separate live-stack inputs,
and the long foundation case hit `Admission(Exhausted)` on a worker claim.
The private log SHA-256 is
`dea276c9350d043c74d18a69dae94b55581b69bf0ab61676c343e235cfb297d2`.
The later pass does not erase this failure or establish which foundation
worker claim exhausted; its two-second expiry fixture was susceptible to a
loaded host between root start and claim.

Commit `b4f3cc5da493bb19653be9350b8c7020e3f2ba51` separated the two
live-relay cases, which `scripts/local-stack.py check-publication-live` runs,
and pinned the disposable suite to the selected PostgreSQL 16.15 image digest
`efedf3595f1d6f415c08568ba171029bf54052e754cc9f030e3f2412b21f3d67`.
The corrected runner exited 0 with eight passes, two filtered live cases, and
an unchanged durable-record digest after a real PostgreSQL restart; its log
SHA-256 is `6bc4db7c3da9589655660b381ebbcca2bcf14102a17136400a26700ab4f35557`.
Commit `86d7ac4e85039dbdd9f4173d5f318c00db3ef311` widened only the
test's pre-claim lifetime to ten seconds and waited eleven seconds before
checking absolute-expiry denial. The same disposable suite again exited 0:
eight passes, two filtered live cases, and an unchanged restart digest. Its
log SHA-256 is `a1320f263a1195c626768314e3960cf9821543b72ff9599c380443ef7c0ea630`.
Both runs used the selected task-owned Docker Engine 29.8.1 and an isolated
loopback-only disposable database. The restore-only namespace was then
removed using its exact owner label; the source test deployment stayed up.

At `86d7ac4e85039dbdd9f4173d5f318c00db3ef311`, `cargo +1.98.1 fmt --check`,
`cargo +1.98.1 test --locked --workspace --lib` (12 passed), and
`cargo +1.98.1 clippy --locked --workspace --all-targets -- -D warnings`
exited 0. The portable `scripts/check-docs.py --base
f3fe82e94e878eba7173aaf326085b77b9c9bc51 --subject HEAD --output
artifacts/completion/docs-check-86d7ac4` also exited 0 in all five stages.
These checks do not activate the restricted profile or qualify the still
missing model, MCP, native/media gateway, and attachment paths.

## Effect-transition observation and restart evidence

An admitted tool attempt now emits a scoped, content-minimal `effect-outcome`
observation when its state becomes uncertain before dispatch, including a
pending attempt fenced by revocation/restart or reconciled after process loss.
An exact original-owner completion or denial emits a second transition only
when the retained attempt actually changes state. Each event uses the stable
attempt UUID and is inserted in the same PostgreSQL transaction as its state
change. It does not expose the command bytes, result value or invocation proof.
The normal observation cursor, module/context scope and durable ACK rules apply.

The real HTTPS-owner test first failed at an assertion of two transitions:
zero existed after a committed `SetLabel` write and lost-response recovery.
That working-tree red run exited 101; six other cases passed and the long
foundation case also hit an exhausted worker claim. Its log SHA-256 is
`f56451857998e7543110fa86d78981d15688486b01bac383de36eea558ebaa12`.
After the journal change, the HTTPS scenario passed in a full working-tree
run, including its revocation-fence assertion; the foundation case still
failed at the shared worker helper. That run exited 101, with seven passes;
its log SHA-256 is
`811c2503d1808f0831ee2851ad6ceab2b6b4e7454994c9ca502dec72c41331fa`.
The common helper now reports the task and generation on failure. A filtered
real-PostgreSQL foundation run with the then 60-second pre-claim fixture
passed and preserved its restart digest (log SHA-256
`bd49dd8d08a92a86028a94505ffb379be8abe517e2b7eed223c5bc0a16229aa3`).
That isolated pass does not identify the prior exhausted claim. The fixture
now allows 120 seconds before the signed claim and still waits beyond the
absolute expiry for its denial assertion.

At committed source `35e23aadc5b3ecce503a716c6870df1259fdda0a`, the
default `scripts/test-postgres.sh` exited 0: eight cases passed, the two
separately qualified live-relay cases were filtered, and a real PostgreSQL
restart preserved the existing root/effect/publication digest. The log
SHA-256 is
`cb060e7e0de2822884172a17ef1c94b33522cc99bf32eb065cd7bb1a231db753`.
The full command, with the selected task-owned Docker socket, was:

```sh
DOCKER_HOST="unix://$HOME/.colima/llull-buzz-completion/docker.sock" DOCKER_CONTEXT= DOCKER_CONFIG="$PWD/artifacts/local-validation/docker-config" CARGO_BUILD_JOBS=1 RUST_BACKTRACE=1 bash scripts/test-postgres.sh
```

The optional case filter initially failed only on the default macOS Bash
path because an empty array expanded under `set -u`; that invocation reached
no test and its disposable database was removed. Commit
`35e23aadc5b3ecce503a716c6870df1259fdda0a` corrected the runner.

The restart digest was then extended to observation counters, records,
offsets and durable receipts. At committed source
`56582c40708979bd46ce1053409db91feaee1aab`, the filtered HTTPS-owner
case and its real PostgreSQL restart both exited 0; the log SHA-256 is
`aa7f010e23eff51858723c3352e91d9225fd316d0eafdc341683cc81553baa92`.
It used the same Docker selection and `CARGO_BUILD_JOBS=1`, then
`bash scripts/test-postgres.sh --case
https_consumer::https_owner_commits_once_recovers_lost_response_and_rechecks_revocation`.
The changed code still does not mediate an actual MCP/model request, native
subscriber, attachment byte release or composed consumer application.

## Native-root upstream image and actual agent-turn boundary

The selected Docker Engine 29.8.1 built all five unmodified pinned upstream
executables at `block/buzz@01b6174a1cbad249e93f31df97d4b2ed1d0e8638`.
The additional `buzz-acp` build enabled
`tokio-tungstenite/rustls-tls-native-roots`; the source itself was unchanged.
At provider source `01cdf3eca45601e8d35b7b0b31b4c6eed5e58fc8`,
`bash scripts/build-upstream-image.sh` exited 0 with image ID
`sha256:2825e586e8b22de794243baac27f9691cf43da128ba845b24368d960756994b3`;
the local build log SHA-256 is
`bc80457097ccb711106577f8b0c697ca14841f380a6541fe6ae5e167761ee3e0`.
The Linux arm64 inventory has 499 selected Rust packages, zero missing local
license texts and manifest SHA-256
`60b473a0b34b7cf7e1fd141c17490fb5df5792c850fcfb8655c48aa8156c309c`.
The runtime image records 114 OS package rows and verifies installed copyright
file hashes. The `buzz-acp` executable SHA-256 is
`f270faf5ae00f4d6c533f4f53bdfb4c217a1a34e466a3c0ebc48ac463b858f8e`.

The first image's inventory step unnecessarily invoked the upstream default
Rust toolchain for `cargo metadata`, even though the binaries and inventory
script used 1.98.1. Commit `221d4e8ad1ebd477ef0d385d7134ed6321328725`
pins metadata to 1.98.1 as well. A second selected-engine build from that
committed source exited 0 with image ID
`sha256:4a568ca4afebb23cda22ae1f803cea4ddf160af758968bdc0953dea9c3a6f174`.
Its build log SHA-256 is
`529a2783cee6f8e80caf433d243e723d2fb6b89647e6bdb759b1d14897de5048`;
its inventory again reported 499 selected packages and zero missing texts,
with the same manifest digest.
The first image remains the exact base used for the following native-root test
image; the second image is the corrected distribution artifact. This is
target-specific inventory evidence, not a resolution of the previously
recorded pinned-upstream `quick-xml` advisories or a production CA rollout.

The task-only test image containing the amended ACP and synthetic CA built with
image ID `sha256:77b603b39a8c25b2da10183bf671684b0e39242889f2c01b7f9b11cf512d14c4`
(build log SHA-256
`cd898f602d72f5bfafc30d4f33bece325b6de43df562f9876b2bf229b49efe56`).
The first mention journey timed out because its runner read only Docker's
stderr stream while ACP logged readiness to stdout; its log SHA-256 is
`c4c95c42b5192b92e0a987e6c242fd52d21aae60960d06cbc298382a06d47eeb`.
After correcting that harness error, ACP initialized the separate pinned agent,
verified the synthetic WSS relay and subscribed to the authorized channel.
The `gemini-3.6-flash` model service then returned HTTP 503 `UNAVAILABLE`
after three attempts; no signed reply was produced. The corrected failed
runner log SHA-256 is
`aea83a966e3b5577c0cc41bdb3195ec55e6ae1c418d7b5548fbe3a147afc7b76`.

The [published Google free-tier schedule](https://ai.google.dev/gemini-api/docs/pricing)
lists `gemini-3.5-flash-lite` as free for standard input and output. The
existing synthetic project listed that model, and one bounded direct
Chat Completions request returned HTTP 200 and `OK`. The task-owned test proxy
and separate agent bridge were switched to that model without placing its API
key in the agent container. The proxy image ID is
`sha256:8dc8d633db8514ba51b98a17b246b5c8b88d9131a2a05c5e0947a3ddec0b67bd`.
A direct ACP `initialize` → `session/new` → `session/prompt` using the unchanged
`buzz-agent` and a 512-token output bound exited 0: `agent_message_chunk`
contained `OK`, followed by `end_turn` (log SHA-256
`1fd68012f62e5d1a43272904fa515b4d12a63dac72b4cfe4f0f4a319b3b3302c`).
The request-count cap in this disposable proxy is process-local; it is not
the required durable root/task budget or production model gateway.

The full ACP mention journey with the same free model still exited 1: agent
stderr recorded a completed model call (677 input, 89 output tokens), but the
private channel retained only the two synthetic owner mentions and no signed
bot reply. The runner and ACP log SHA-256 values are respectively
`d6766b532db9562fac4a94f2381e92d0eb8b5f95abab648a66a2515fb51d728e`
and `3fb8a0768bedf4ac66e93f53357fa594fd32c51a7fe28b5bab060484acbdfbc2`.
The completed agent call's private stderr log SHA-256 is
`cf5b9987a70fae4b7561d2f7d6268079af9141202000f68eb5a6572f78e8e1ee`.
An [upstream report](https://github.com/block/buzz/issues/6160) describes
plain-text agent turns that finish without posting to the channel unless the
agent uses an explicit send path. That is a plausible explanation here, not
a proven diagnosis of this pinned executable. The accepted profile therefore
still needs its separate governed publisher tool, actual supervised task/model
and MCP dispatch, and mediation of every native content surface. No ACP success,
production model amendment or native-reply qualification is claimed.
