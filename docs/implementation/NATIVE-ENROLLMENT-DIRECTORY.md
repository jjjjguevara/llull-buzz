# Limited native enrollment directory

The enrollment gateway can supply existing native clients with the original
owner-signed channel metadata, channel roster, optional native profiles and
applicable relay membership. It exposes one pending enrollment to its intended
native key after separate NIP-42 authentication. Desktop HTTP queries also need
fresh, exact NIP-98 authorization. The gateway does not create membership,
profiles, invitations, joins, or general publication authority.

`ENROLLMENT_RELAY_ORIGIN` enables the existing limited gateway. A configured
`NATIVE_ORIGIN_CONFIG` supplies its fixed native directory source. Directory
execution additionally requires `enrollment_moderation_read: true` in that private
configuration, tracked native custody, and an existing native service authorized
by the original owner to read `GET /moderation/restricted`. This setting grants
no native role. The default is false. Missing permission, incomplete or malformed
responses, redirects, timeouts and active restrictions fail closed. The complete
restriction response stays private; only the intended identity's eligibility is
used. No caller URL or native query filter reaches that read.

The separate `native-enrollment-admission` custody capability permits only an
empty-body, nonce-bearing NIP-98 GET to that exact fixed-origin path. Existing
`native-http` POST rules remain unchanged. Issuance, capability closure and
process release continue through the existing custody journal and collector.
An absent target in a complete successful current read is an observation from
the authenticated native owner, not a replacement for its permission decision.

Both `/info` and the NIP-11 response describe this gateway's own one-shot query
surface, eight WebSocket filters, 64 KiB messages and no persistent subscriptions.
The original native descriptor is retained as `native_owner` provenance. Original
signed events remain unchanged. General push, media, GIF, channel administration
and join capabilities are not advertised. A pairing relay is retained only when
the original native owner explicitly supplies one; no pairing service is created.

An optional enrollment payload field selects the native-visible challenge:

```json
{"native_challenge":{"version":"mention-json/v1","bot_mention":"@enrollment_bot"}}
```

The mention must match both the registered `enrollment_bot_mention` and the
existing bot profile's effective native display name. The exact challenge text
is that mention, one space, then the unchanged canonical enrollment JSON. Absent
the optional field, legacy command and challenge bytes remain unchanged. The
human's native client still signs the separate kind-9 challenge event; the
provider and browser never substitute a human signer.

Ordinary desktop clients also send signed presence, typing and conditional
read-state events on their authenticated connection. Unsupported event kinds
receive a negative acknowledgement without dropping that connection. They are
neither stored nor forwarded and do not become enrollment proof. Their author
must still match the original NIP-42 login, and the current native directory
gate still applies. A wrong author or failed admission closes the connection.
Neither auxiliary traffic nor a successful challenge resets the original socket
deadline or frame budget. This does not add presence, typing or read-state
publication support to the gateway.

The continuity repair is implemented at
`3395ea9aecc4289195d9148eae8667d377421770`. Its new PostgreSQL regression covers
wrong-author refusal, three unsupported kinds on one authenticated socket,
unchanged effect counts, subsequent exact kind-9 retrieval and expiry under the
original short browser transaction. Source formatting and whitespace checks
passed; execution of this new regression is pending. The preceding runtime
results below do not qualify this repair.

This source increment is separate from historical full-result recovery. A raw
WebSocket fixture does not establish desktop/mobile or human acceptance. Live
moderator authority and live enrollment remain unexercised.

At `6655f6d6804cf38723b81c27c77cab337e50e133`, the Rust 1.98.1 locked, offline
provider binary and PostgreSQL test binary built successfully. The focused cohort
passed 17 directory, three gateway, 19 standing and nine receiver tests; the
standing harness's child-only case remained excluded as prescribed. One wire
test separately passed exact optional-field identity and null/shape rejection.
All eight isolated PostgreSQL cases passed with actual database restart/hash
preservation: both historical recovery cases, three existing transport/custody
cases, and the new directory, revocation and final-custody expiry cases.

The expiry regression introduces a two-second database delay after a one-second
native admission observation. Final custody rolls back, leaving zero retained
login rows. A distinct fresh 30-second observation then succeeds under the same
unchanged original challenge. This is a functional regression, not a benchmark.
The measured source list now additionally binds directory parsing, gateway
enforcement, native proof verification and library wiring. Existing custody
lifecycle and retirement logic remain unchanged; old trust profiles/evidence are
retained and do not acquire the new implementation digest implicitly.

The first unit attempt retained 13 passes and four fixture failures because its
temporary root was below world-writable `/tmp`. The rerun used an owned private
temporary root with non-writable ancestors; the production custody guard was
unchanged. Logs and both attempts remain retained. Rust ran within one CPU/two
GiB; PostgreSQL runs used 1536 MiB for the test process plus 512 MiB for the owned
database on the same CPU. All owned database containers/volumes were removed and
the compiler/fixtures stopped. Private `native-provider-result-r1.json` retains
individual log hashes and cleanup readback. The preserved provider binary hash is
`d0510d0ad6cba5fa028d037bd2941cd4bd26011af75efbd0cd5844d953dc527f`.

Native-owner HTTP response/admission fixtures and HTTP/WebSocket clients in these
checks are synthetic. Request signatures, strict adapter, tracked signer, served
provider routes and PostgreSQL custody/restarts are real. An unmodified
desktop/mobile journey and actual admitted native-owner access still require
their own execution; no whole-product, live-provider or human acceptance follows.
