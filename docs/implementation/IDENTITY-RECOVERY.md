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
