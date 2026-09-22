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

## Requested OAuth model amendment

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
