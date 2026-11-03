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

This source increment is separate from historical full-result recovery. Its
tests and actual native-client journey need their own execution evidence; neither
this description nor a raw WebSocket fixture establishes desktop/mobile or human
acceptance. Live moderator authority and live enrollment remain unexercised.
