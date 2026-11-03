# Identity result recovery and native challenge transport

This additive implementation belongs to provider [task 04](../../.scratch/llull-buzz/issues/04-provider-completion.md),
under the owner's 2026-11-02 isolated source implementation authorization. The
starting provider revision is `da0a05dacf6501fdf2972be260dcc1dfb6edf435`.
Runtime results and final reviewed revisions must be recorded separately. This
document does not assert a deployment, profile activation, native human UAT or
completion of the provider task.

`POST /integration/v1/identity-results` accepts a `read-identity-result` Command.
Its payload contains only `original_command`, the exact original `enroll` or
`prove-key` Command. Consumer, resource and correlation remain identical;
causation names the original intent. A separate read intent and fresh registered
service NIP-98/ES256 credentials authorize this read. The module must explicitly
permit the read action and the original context domain. Fresh browser provenance
must identify the same original issuer/subject; a new login transaction is
permitted for the read, without modifying original login evidence.

The implementation joins the immutable command result with its original
admission evidence. It returns consumer/module/context/operation/intent/resource,
the full original command fingerprint, the complete unchanged `CommandResult`,
and a separately identified current binding. Missing result/evidence remains
unknown. Changed intent/fingerprint/scope is refused. Existing bindings must
still be active, unretired and attributable to the original module/person/key;
proof-result reads require that binding to exist. Original challenge, browser
and proof deadlines are never extended. An expired challenge can be observed as
history and cannot be used for enrollment. The read does not insert a command
receipt, consume a challenge or mutate a binding; its fresh authorization is
retained separately by the existing admission ledger.

The optional trusted `ENROLLMENT_RELAY_ORIGIN` is a fixed `wss://` origin. `serve`
mounts `/native/enrollment/{consumer}/{enrollment}` only when configured. This
limited pre-enrollment transport authenticates the intended native key through a
fresh NIP-42 kind-22242 connection challenge, then accepts only the separate
kind-9 enrollment message with the exact registered bot/channel/text/window.
Neither login nor native message receipt binds a key or grants conversation
access. General subscriptions receive a restricted refusal. The broader
`native_gateway` surface is not qualified by this endpoint.

The later optional [native enrollment directory](NATIVE-ENROLLMENT-DIRECTORY.md)
adds original-owner directory records and a separately tracked current moderation
read. Its focused execution and remaining desktop/mobile gap are recorded there;
they do not change historical recovery's independent acceptance boundary.

The pinned desktop transport converts the relay scheme to HTTPS and submits
native events to the same relay path plus `/events`; the limited native HTTP
endpoint requires the same intended key's exact body/method/URL NIP-98 proof and
the separately retained NIP-42 login. Mobile publishes the signed event over the
authenticated WebSocket. Native keys remain in those clients. The provider
does not create either native proof with a browser or service signer.

`POST /integration/v1/enrollment-proofs` accepts `read-enrollment-proof` with
`{"enrollment_id":"..."}` and the exact enrollment resource/revision `1`.
It requires fresh registered service credentials and the unchanged, still-valid
original browser transaction/module/context. It returns the exact native event,
separate NIP-42 event, original enrollment fingerprint, fixed relay URL and
custody time. The consumer must pass that exact event to the ordinary proof
command. Lost native acknowledgments recover the same retained event; a changed
event cannot overwrite it. Post-window proof-result recovery uses the historical
read, never this pre-enrollment retrieval.

Use the maintained Rust `1.98.1` locked build and focused cases through
`scripts/test-postgres.sh --case identity_history::lost_enrollment_after_window_is_exact_read_without_new_admission`,
the other `identity_history` case, and the `enrollment_gateway` cases in
`crates/buzz-provider/tests/cases/`. Those are authored synthetic/local checks
until an exact executed result is attached. Native desktop/mobile graphical
journeys and named human judgments remain separate acceptance evidence.

## Focused local execution, 2026-11-03

At provider `0639040608a04132403aee9686e39526670afcbd`, Rust `1.98.1`
locked compilation of the provider library and PostgreSQL integration binary
passed. Three `enrollment_gateway::tests` unit controls and all five focused
PostgreSQL scenarios passed: lost enrollment result after the original window,
lost proof result with current revocation fencing, native WebSocket login/message
separation and exact-event recovery, native desktop HTTP submission with separate
NIP-42/NIP-98 evidence, and service revocation before message custody. Each
database case used the maintained `scripts/test-postgres.sh --case ...` runner
and preserved its records across a real PostgreSQL restart.

The disposable PostgreSQL image was
`postgres@sha256:efedf3595f1d6f415c08568ba171029bf54052e754cc9f030e3f2412b21f3d67`.
Execution used one CPU and at most two GiB aggregate; fixtures had fresh databases,
synthetic signing identities and loopback-only listeners. The runners removed
their own containers and volumes, and a post-run label query returned no retained
fixture containers. Raw logs remain in the operator's private Lane H runtime
record. An initial service launch failed before compilation because its working
directory was wrong; the first compile then exposed the missing `SinkExt` import.
Both failures are retained separately from the passing incremental build.

These are actual provider code/database tests with synthetic native clients and
the pinned SDK message builder. They do not establish a graphical desktop/mobile
journey, consumer native-database/API composition, live identity access, human
UAT, complete provider qualification, or production deployment. No timing or
performance qualification is inferred from these functional checks.
