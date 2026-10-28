# Private local metadata inspection — source candidate

This delivery prepares 27 fixed PostgreSQL metadata views and the standalone
`buzz-inspection` command. It adds no HTTP route, invocation/publication/evidence
purpose, replay admission write, agent credential daemon or native business effect.
The prepared forward migration is `0009_private_metadata_inspection.sql`. No
installation, grant, account creation or activation was executed for this source
candidate. The existing eight migrations and ordinary provider source stay intact.

The [2026-10-24 execution record](#linux-source-execution-2026-10-24) supersedes
the historical uncompiled status below. Locked source tests, all-target build,
strict Clippy, the selected upstream build and the final containment gate have
passed; installed PostgreSQL and profile qualification remain unrun.

The command accepts no arguments. Its input directory is fixed at
`/etc/llull-buzz/inspection`. Each ancestor is held through a safe no-follow Unix
file descriptor, the leaf must be owned by the executing identity with mode 0700,
and each input must be a single-link regular mode-0600 file. The closed input set
is `trust.json`, `profile.jws`, `request.jws`, `response-key.pem`, `sql-password`,
`sql-root.pem`, and `schema-manifest.json`. Inputs are re-read under held parent
identity before publication. No actual credential files are supplied by this
source delivery.

Trust binds the exact profile bytes, issuer/subject, generation, source revision,
root public-key PEM/hash/derived P-256 thumbprint, implementation hash and current
microsecond observation/expiry. The root-signed profile fixes installation,
configured membership, separate request and response keys, physical database and
role OIDs, TLS root, all 27 current view-definition hashes and the schema-manifest
hash. The request is separately ES256-signed and binds original operation,
configuration/generation, both copy hashes, controller/run, recovery epoch,
challenge, basis and deadline. These private purposes are separate from the three
existing public purposes. No signing/verifier key is discovered from a token URL.
The implementation hash uses path/length-framed compiled source inputs; the schema
manifest commits all original and forward migration sources plus current catalog
bytes. These source commitments do not themselves prove a current installation.

The prepared roles are a NOLOGIN view owner and a distinct LOGIN inspector.
Existing roles' effective PUBLIC CREATE, TEMP and EXECUTE capabilities on the six
selected application trigger functions are captured and preserved by explicit
individual grants before those PUBLIC grants are removed. Inspection identities
receive neither capability. Future ordinary-role provisioning must explicitly
provision its own ordinary rights. The role/catalog reader checks actual effective
privileges, membership, ownership, selected-database ownership/ACL and effective
CREATE/TEMP, base and column access, schema CREATE, sequence capabilities, every
application function, view definitions, exact columns, security-barrier options,
physical endpoint and original session identity. Constructor and verifier share
one exact `pg_catalog, buzz_inspection` search path. Bounded catalog custody also
includes the original enforcing triggers (including enabled state and attachment),
constraints, validation, foreign-key triggers and backing/explicit indexes. Exact
installed definitions remain bound by the independently provisioned manifest;
source-derived structural expectations do not invent installed deparser output. A
native installed privilege/ordinary-runtime regression is still required; prepared
SQL text is not an executed privilege proof.

One owned read-only repeatable-read SQL transaction acquires fixed view/base read
locks. Every metadata relation and every closed catalog query gets scalar count,
UTF-8 byte and largest-row preflight before any body transfer. Metadata quotas are
10,000 aggregate rows and 2,097,152 aggregate projected raw bytes across all 27
relations; a single lawful row may use that whole raw-byte quota. Catalog custody
has a separately bounded 10,000-row/2,097,152-byte proof inventory. An oversized
inventory returns UNKNOWN rather than an empty complete inventory. Fixed
MATERIALIZED statements and a named WITHOUT HOLD cursor transfer one opaque
700,000-byte chunk per FETCH, preserving snapshot, ordinal, raw hash, counters and
EOF. No arbitrary relation/role/filter can enter the production acquisition.

The recursive private raw parser preserves original numeric lexemes and rejects
UTF-8 errors, duplicate decoded JSON keys and trailing data. Existing public wire
safe-number/1MiB policies remain unchanged. Each view commits the original server
`to_jsonb(actual_row)::text` bytes before projecting metadata. Original private
sub-bodies retain separate server commitments. Unconstrained nested worker,
registration/module/tool, binding and observation data are projected through
closed fields/type checks; unknown shape/type remains a named uncertainty with
its original commitment. Raw inventory bytes are retained, without normalizing
Unicode or deduplicating original identities. Current/historical registrations,
enrollments, attempts, reservations, publications/deliveries, native input and
observation/snapshot/cursor custody are checked together. Unresolved effects,
claimed reservations and missing historical current ancestry cannot become
success or disappear from the retained data. Enrollment histories reconcile every
revision from 1 through current, immutable identity and each authority-epoch/state
transition against the selected writer. Snapshot entries reconcile the original
latest-per-operation records at the frozen scope/high-water. When retained rows
cannot reconstruct that boundary, the receipt names
`inventory-snapshot-original-completeness-unproven`; a contiguous prefix alone is
never completeness. The selected writer's lawful empty snapshot with high-water 0
and no counter/observations/entries remains supported without fabricating a counter.

Private signed page files contain reversible length-framed original metadata
bytes in base64url chunks of at most 500,000 raw bytes. This smaller transport
chunk accounts for JWT expansion; it is not a smaller row quota. Each complete
signed envelope remains within the unchanged 1MiB wire ceiling. Raw data quotas,
8-byte-per-row framing overhead, SQL chunk limits and signed-envelope limits are
separate and reconciled. A final signed receipt names every page, relation,
original binding, snapshot, schema/catalog custody and EOF. Filenames are hashes
of their actual signed bytes, created exclusively at mode 0600. Every output is
reopened under its held parent with no-follow, exact identity/owner/mode/link/size
checks, bounded persisted-byte hashing and genuine ES256/body-binding verification.
All outputs are reverified before terminal publication, then checked again for
identity/generation drift before directory close. Only the receipt filename is
printed. A consumer must verify every signed page and receipt and
reconstruct the exact framed data; no read-side installed bridge is asserted by
this delivery.

Every receipt has status `PARTIAL`, including a lawful zero-work observation.
Delivery 2/3 gaps are always retained: native owner incarnation, credential
exposure, credential channel and external authority remain unobserved/unverified.
Metadata acquisition does not manufacture full provider standing or qualification.

One sticky 20,000,000-microsecond invocation clock covers authentication, SQL,
current-file reads, hashing, encoding/signing, output construction and cleanup.
The earliest trust/profile/request/schema expiry constrains it. Initial schema
authentication checks every original/forward migration pin before SQL, followed
by current checks after SQL cleanup and at the final boundary. The CLI registers
SIGINT/SIGTERM handlers before owned work. One latched cancellation future is
polled before inputs, at live budget boundaries and alongside native awaits; it
remains observable through cleanup, page retention and final publication. It
retains the owned SQL session for attempted cursor close, rollback and checked
connection close, with the original independent one-second cleanup attempt caps. File close/rollback/output-removal uncertainty overrides a pass.
Only exact owned output inode identities may be removed; terminal reopening also
requires the original protected parent identities. Cleanup-only reopening cannot
reset or admit the failed acquisition clock. Failed private byte owners clear their own buffers on drop. This is best-effort buffer clearing, not a claim of compiler-guaranteed memory zeroization or of clearing SDK-internal secret allocations.

## Historical source checkpoint (2026-10-15)

The following checkpoint records its original source-only authority and results.
Subsequent authorized execution is recorded separately below; it does not supply
installation or native privileges.

This current-ledger integration retains the R2 fixes and addresses the nine findings in the independent source review
of the immutable first packet. It is **uncompiled and unexecuted**; independent source review and published-source binding are separate gates.
The authored complete-port controls now enter the same owner flow with genuine
closed parsing/ES256, actual scalar/preflight/chunk/catalog/history verification,
owned private fixture files and terminal cleanup. Only the final SQL socket and
explicit adverse file-transport observations are inert under `cfg(test)`; no
production transport/profile override exists. Fixtures include full configured
0/1/201/1000-member inventories and lawful empty work, retained histories, changed
migration pins, original request/response bindings, omitted/duplicate/malformed
records, private sentinels, early EOF/chunk corruption/oversize before transfer,
cancellation, late clocks and uncertain SQL/file cleanup. They are authored methods,
not executed results. SQL projection/server-hash semantics, actual TLS and native
privilege behavior still require their separate PostgreSQL methods.

The original candidate remains **uncompiled and unqualified**. The first bounded helper build
stopped during dependency compilation, reached zero new cases, and lost its
initiating resource-cap/child-exit details when the monitor's kill path failed.
Process absence was independently established, and only the owned build scratch
was retired. That failure is retained; no retry or Actions dispatch was launched.

The source-leaf configured locked workspace lib tests, all-target build, clippy
`-D warnings`, upstream build and containment gates remain required under
separately authorized suitable capacity. Native PostgreSQL installation/privilege
gates remain a separately admitted installed verification stage, rather than a
source-leaf closure gate. Source controls here are authored,
not passing evidence. The original five methods and added R2 methods in
`tests/inspection_postgres.rs` are AUTHORED UNRUN and ignored by default. They additionally require
`BUZZ_INSPECTION_NATIVE=authorized-isolated`, explicit isolated admin/inspector URL
inputs, and a database name beginning `buzz_inspection_test_`. They cover installed
privilege denial, nested private sentinel/original server commitment, 201/1000 real
cursor traversal effective PUBLIC/inherited privilege checks, and transactional before/after preservation of ordinary runtime effective privileges. They must never
be pointed at an existing live database. They do not replace the original native
provider and tenant/runtime regressions, independent review, installation standing
or named human acceptance.

## Current-ledger reconciliation and execution handoff (2026-10-15)

The retained R2 packet was based on `b244ba7560112e498ee6d68a48d035c99cb0b8c2`.
This integration starts from `34bb093e20ed02b12d4975523f0dfdc3ce0ff8da` and
leaves migrations 0001–0008 byte-identical. The new forward migration is 0009.
All nine migration bytes enter the closed schema-manifest map; implementation
custody also includes the three intervening migration sources. A legacy six-entry
manifest is refused, never extended or adopted as an installed receipt.

The 27 metadata views, configured-membership inventory and history checks remain
the original fixed scope. `model_dispatches`, `native_attachments` and
`native_attachment_leases` add **enforcement-only** catalog contracts: 42
constraints, four triggers, two explicit indexes and the exact
`freeze_model_dispatch` PL/pgSQL body. They add no views or view-owner SELECT and
do not establish export completeness for those tables. Raw requests, claims,
attachment bytes and model pricing remain outside the metadata export. The five
original function commitments and 118/23/6 original constraint/trigger/index
contracts are preserved separately. The sixth routine participates in the same
capture-effective-privilege → individual GRANT → PUBLIC REVOKE loop; removing its
PUBLIC privilege without those original grants is not permitted.

In an independently admitted Linux locked build job, run the existing pinned
Rust 1.98.1 workspace gates, including these exact authored selectors:

```sh
set -eu
cargo +1.98.1 test --locked -p llull-buzz-provider --lib inspection::catalog::tests::
cargo +1.98.1 test --locked -p llull-buzz-provider --lib inspection::port::tests::
cargo +1.98.1 test --locked -p llull-buzz-provider --test inspection_source
cargo +1.98.1 test --locked -p llull-buzz-provider --test inspection_history_source
cargo +1.98.1 test --locked -p llull-buzz-provider --test inspection_postgres -- --list
```

These commands have **not run** in this delivery. Preserve exit status, named
methods, exact source/lock/toolchain hashes, bounded logs and owned-resource
cleanup. A compilation failure or missing test is not a pass and does not authorize
a retry. The separate native PostgreSQL campaign requires its original explicit
isolated fixture admission, all migrations through 0008 before the transactional
forward-migration preservation method, TLS/role custody, and the original ignored
methods invoked deliberately. Do not run it against existing business data. Verify
before/after effective privileges for every original role and every public routine,
including `freeze_model_dispatch`, before accepting installation. Existing broader
provider, containment, build/clippy and tenant regressions remain required.

Static formatting/source comparisons are the only locally permitted validation;
no PostgreSQL, Cargo build, dependency fetch, runtime, grant or provider action is
implied. Actual compiled/native results, installation standing, independent result
review and human acceptance remain open. The immutable R2 manifest and packet are
unchanged; this checkout is the forward source candidate, not a rewritten packet.

Local source-only checks on 2026-10-15 used the existing pinned rustfmt
1.98.1 toolchain (rustfmt 1.9.0-stable): formatting/syntax parsing and diff
whitespace checks passed. A bounded in-memory source comparison independently
matched the three current DDL files to the 42-entry constraint multiset, four
trigger signatures and two explicit indexes; verified the eight prior migrations,
27 view statements and original contract arrays remain unchanged; and checked
that the lock delta contains only the retained nix/rustix/linux-raw-sys additions.
This is static source evidence, not execution of any authored Rust control or
validation by a PostgreSQL server. The first comparison attempt rejected its own
identifier scanner because it omitted digits in `byte_sha256`; the scanner was
corrected and the comparison then passed. No product predicate was relaxed.

## Linux source execution (2026-10-24)

Actual code/test revision: `518f880e3b1f3cfdc6fa703ad49b16d20e5f7d34`.
The core checks and standalone upstream build used Linux arm64, Rust/Cargo
1.98.1, two virtual CPUs, a 2 GiB VM and one Cargo build job in a 1.5 GiB compiler container. This is correctness
evidence for that local profile. Cargo.lock remains
`02c8c1e8a28bbb6617de9574c83306f21fb5d85b096d5285ae7c714fc528b796`.
The selected upstream remains `01b6174a1cbad249e93f31df97d4b2ed1d0e8638`;
its separate lockfile hashes to
`d73c16b2c36d97390db4fe856fa4e1ee856110a7933a8921d0e8c90614af25dd`.

The following actual commands passed on that exact source:

```sh
cargo +1.98.1 clippy --offline --locked --workspace --all-targets -- -D warnings
cargo +1.98.1 build --offline --locked --workspace --all-targets
cargo +1.98.1 test --offline --locked --workspace --lib
cargo +1.98.1 test --offline --locked -p llull-buzz-provider \
  --test inspection_source --test inspection_history_source --test inspection_postgres
bash scripts/build-upstream.sh
bash scripts/test-containment.sh
```

All 61 runnable library methods and ten focused source/history methods passed.
The complete-port controls cover lawful zero work and configured 1/201/1000-member
inventories through actual parsing, signatures, private files, catalog/history
verification and cleanup. Their final SQL transport remains explicitly inert.
Seven PostgreSQL methods remain ignored and **UNRUN**: six integration methods
and the catalog module's native adverse method. Compilation supplies no installed
projection, TLS, effective-role privilege or full standing result.

The unmodified upstream script built the two selected native executables in
14m16s. Both output hashes were independently read and checked against its
generated SHA256SUMS. Retained raw log hashes are:

| Log | SHA256 |
| --- | --- |
| Ordered four core commands | `a64481451c7d327bd568f6e49ec794689912b5c399750e7ba3ee6ea9acebd67f` |
| Selected upstream build | `95bf19222d85f78f39af8ea3ecdc65c5bc9ce192c7af1662d25d5ff556e73048` |
| Original containment script | `9978a6421d9a3dedccc8cbb97fc870919c3f5c20f0376d59f8dfd1438a20c4ae` |

Initial real compilation exposed SQLx 0.9 owned-SQL requirements, integer/borrow
types and previously uncompiled publication test errors. Fixed SQL builders were
audited; execution/scalar helpers are private and the sibling owner receives only
the fixed session query. Publication tests retain complete state equality.
Strict lint fixes preserve short-circuiting, identity values and other Unix ABI
conversions; no warning was disabled or dependency pin changed. Different-author
source and core execution review accepted these repairs and results.

Failed attempts remain retained: the initial compile, read-only fixture mount,
group-writable archive ancestors, all-target and lint failures, and an upstream
mountpoint failure before its script started. Only owned disposable test paths
were adapted; protected-file checks remain unchanged. All 140 archived source
members matched after the successful core run, with no fixture paths remaining.
Eleven stopped compiler containers and the hashed compiler volume were retired.
Its 6,324,215,808 allocated bytes corresponded to 6,325,702,656 additional guest
free bytes; observed host free space rose only 196,608 bytes. Equivalent host
reclamation is not claimed. Existing provider data and shared caches were preserved.

The unmodified containment script rebuilt the selected upstream and workspace
from the same immutable Git source, then passed actual ACP2-session/MCP
negotiation and kernel filesystem/network negative probes with zero model calls.
Its probe ran as UID 65532, without networking, with a read-only root, all
capabilities dropped, no-new-privileges, 64 PIDs, 512 MiB, one CPU and the original
16 MiB noexec work tmpfs. The script removed its exact probe image, containers and
archive context. Its resolved test-only Debian base was
`7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8`;
no production image pin changed.

After terminal results and source custody, the two stopped upstream containers,
five remaining disposable source/vendor/compiler volumes and two helper images
were removed. Sorted no-follow archive hashes, logical/allocated byte counts and
absence checks are retained for each volume. The two built upstream executables,
their source/license/SHA256SUMS and the 28,742,915-byte artifact volume remain
retained. The separate owned host vendor copy was hashed before removal. Across
this final retirement, guest free space rose from 17,871,040,512 to 19,053,608,960
bytes and host free space from 48,017,960,960 to 48,401,588,224 bytes; these are
observed filesystem deltas, not a claim that all VM allocations returned to the
host. Existing provider containers stayed stopped, with their data and retained
backups preserved. The owned VM was stopped, and its original configuration was
restored byte-for-byte with mode 0600. Global Docker configuration, the separate
Email profile, shared PostgreSQL and usernet were unchanged. The final document
publication carries the tested code bytes forward; it is not a second execution.
No migration,
inspection role/profile installation, live provider/model effect, full restricted
profile activation or named human acceptance is established by this record.

## Instrumented native credential custody (source extension)

The optional, private `Profile.native_standing` extension is
`llull-buzz-native-standing-profile/v1`. A profile without that field retains the
v1 receipt and its four unresolved standing scopes. The new inspector emits
`llull-buzz-private-metadata-receipt/v2` only when the separately root-signed
profile selects the extension. Existing public routes, request authentication,
SQL relations, membership and metadata contracts do not change.

This extension observes the provider's instrumented native service credential.
It is not a complete inventory of consumer credentials, model gateways or remote
provider authority. Neither a local `RETIRED` observation nor a successful native
read proves that a relay has revoked a key, discarded a token or erased copies.
The response remains `PARTIAL`, with `external-authority-unverified` retained.
The outer receipt also retains the original unresolved-scope list, so an older
consumer cannot mistake an additive local observation for complete standing.

Before the original native key load, an operator supplies `NATIVE_ORIGIN_CONFIG`
with its existing fields plus `custody: NativeCustodyScope`. The scope binds the
installation, exact source/implementation and static membership commitments,
original operation/configuration/generation/source and target copies, native
community/origins/relay key, original credential public key and protected key
pathname. `custody_id` is a fresh lowercase 32-hex identity. The operator provisions
`/var/lib/llull-buzz/native-custody` and the key parent as owner-only directories;
this source does not install profiles, grant privileges or create credentials.
The configured community/origins/relay must equal the existing native configuration.

The actual acquisition uses a no-follow, owner-only regular key file. Before any
signing capability is returned, the daemon creates a new, exclusive
`<custody_id>.jsonl` and durably appends the original acquisition. It never resumes,
truncates or reconstructs an earlier log. One in-memory native key allocation
supplies named `native-http`, `native-publication` and optional `consumer-http`
aliases. The typed HTTP consumer adapter has an additive tracked constructor;
its original command/lookup origin must match the tracked scope. Legacy supplied-key
constructors cannot claim prior acquisition history. Real NIP98,
artifact-scoped attachment authorization and publication signatures enter the log
before their bytes are returned to the existing transport. Aliases close before
the final key release is logged. Failure to append refuses the signing operation;
a failed/drop-time release is not converted into a successful cleanup assertion.
The legacy constructors remain available and do not acquire standing by inference.

New instrumented signatures use the distinct `CredentialIssuedV2` journal event.
Its `public_claims.kind` is `llull-buzz-native-public-claims/v1`: signer public key,
creation timestamp, exact UTF8 content hash, and RFC 8785 tag-array hash. The
closed `scope.type` selects one of:

- `nip98`: exact public URL, method, payload SHA256 and optional nonce SHA256;
- `media-get`: exact blob SHA256 and claimed expiration;
- `publication`: channel UUID, original publication UUID and root/reply event IDs.

These fields come from the actual signed event before transport, not a later
operator assertion. The existing original custody scope binds the key, operation,
configuration, copies and configured origin. The tracked signer refuses missing,
duplicate, foreign or unaccounted tags instead of emitting an incomplete scope.
No reusable signature, bearer encoding, nonce plaintext or publication text enters
the inspection journal. Event and complete-token hashes remain commitments, not
independent rederivations of the undisclosed signed bytes. Historical
`CredentialIssued` records remain parseable and retain the explicit unresolved
`credential-public-claims-unavailable`; they are never relabelled as V2 records.

Claims do not establish current receiver policy. At the selected upstream
`01b6174a1cbad249e93f31df97d4b2ed1d0e8638`, `buzz-auth::verify_nip98_event`
checks a ±60-second creation-time window. The upstream media GET route passes a
3600-second maximum age to `verify_blossom_get_auth`, while this provider's local
native-media requester uses a 600-second age check; both separately enforce
expiration and scope. An `x`-only token has no signed server restriction, even
though its transport uses the configured origin. Neither implementation read is
a current remote installation readback. Publication has no demonstrated expiry
or remote deletion guarantee. Consequently the collector retains
`external-authority-unverified` for every V2 issuance, including expired claims;
local process/key retirement does not retire signed remote capabilities.

The authenticated profile lists every original scope and a `retained_anchors` map
keyed by `custody_id`. Each anchor contains the independently retained original
`acquisition_sha256`, positive `prefix_records`, and `prefix_head_sha256`. A new
request/challenge cannot supply a replacement beginning or erase an exposed
prefix. Records use RFC 8785 canonical JSON without Unicode normalization, one
record per newline. Each record hashes the prior canonical record without its
newline; the complete-history hash includes all original newline bytes.

The inspector reads the complete physical directory and requires its filenames
to equal the signed scope inventory. Missing, extra, truncated, replaced, linked,
mis-moded or oversized history refuses the observation. It retains all records
within the bounded selected path; no “latest N” history or metadata membership
inference is substituted. Each file is limited to 4 MiB; over-limit histories are
unqualified, not truncated. The existing overall response-size and invocation
budget can impose a smaller compositional bound, which also refuses rather than
silently omitting records.

Current owner facts come from Linux machine/boot identity, PID birth ticks,
UID and the exact PID/mount/user/network namespaces. Current socket inode owners
are read from that same stable process incarnation. A PID in another machine,
boot or PID namespace, an inaccessible kernel observation, or an ownership race
stays unknown. An original protected key pathname still present is a live local
exposure even after the signing aliases closed. Local `RETIRED` requires the
original process absent or replaced, the original key pathname absent, no open
tracked capabilities and a genuine final release record. The inspector only
reads: it never stops an owner, deletes a key, closes another process's channel,
validates credentials at a remote provider, revokes a token or sends a native event.

Source controls use genuine synthetic keys, signed separate-root profiles and
requests, the real acquisition/signing/release code, real protected files and the
same inspection fold. On the local non-Linux test host, only the final Linux
process/socket lookup is an explicit inert seam. This does not qualify Linux
installation, a remote relay, current live standing, provider IAM or human acceptance.
Installed kernel controls and independent result review remain separate.


## Provider-owned model and media authority (forward source extension)

Forward migration `0010_private_authority_inspection.sql` extends the fixed
metadata inventory to 30 relations. Migrations 0001–0009 remain byte-identical.
The three added security-barrier views are `model_dispatches`,
`native_attachments` and `native_attachment_leases`. They use the same complete
scalar preflight, aggregate bounds, named cursor/EOF, physical catalog,
independently pinned view definitions and persisted ES256 page verification.
The new source requires all ten migration hashes and all 30 view definitions;
an old schema manifest cannot silently acquire the expanded scope. Original
model/media constraints, triggers and indexes remain mandatory enforcement
contracts. Source implementation custody now also includes the selected ordinary
DB, task, effect, model-dispatch and native-media guards.

Model projection retains the immutable reservation/consumer/root/task/generation,
state, send/deadline/settlement times and original request/pricing/settlement
hashes. It exports no prompt, price body or usage body. A dispatch must join its
original reservation and retain the original generation and identities. Only an
actual `settled` row discharges the previously unconditional unobserved-reservation
gap. A missing dispatch, `unknown` or `incident` remains unresolved; passing a
send deadline never proves a vendor call did not happen.

Attachment projection retains exact scoped consumer/source/evidence identities,
byte hash/length, configured origin owner and retention time with original
evidence/byte commitments, without exporting bytes or evidence bodies. Leases
retain their actual immutable identity, enrollment revision/epoch, native public
key, module/context, owner and lifetime with original request/claims commitments.
The inspector joins intake → attachment → lease and the lease's exact historical
enrollment revision. A later current binding can have advanced or retired; it
cannot replace the original key/epoch/consumer/module proof. A missing or
cross-owner original binding is refused. The lease must retain its actual intake
module/context and cannot outlive that intake's original retention deadline.
Unattributable original metadata uncertainty blocks every selected member's
quiescence disposition. The native SQL methods already authored
in `tests/inspection_postgres.rs` now name both forward migrations and all 30
views, continue denying raw model requests/media bytes/lease claims, and remain
AUTHORED UNRUN until a genuine isolated installed execution is recorded.

The new source emits `llull-buzz-private-metadata-receipt/v3` with mandatory
`provider_authority.kind = llull-buzz-private-provider-authority/v1`. This is a
projection of the same authenticated PostgreSQL snapshot. It binds request hash,
snapshot, observation time and exact member registration row commitment,
registration revision, authority epoch and recovery epoch. Its per-member
`QUIESCENT` positive requires an inactive registration, no active nonretired
enrollment, all retained task roots closed with no current worker lease, no
unresolved consumer attempt, every model reservation joined to a settled dispatch,
every admitted publication joined to a terminal delivery, and no current media
lease. Each contrary domain emits a named blocker and `LIVE_OR_UNRESOLVED`.
Uncertain original metadata also blocks that positive. Consumers must rederive
these facts from the signed original rows; the projection is not a supplied
operator policy flag or an effect authorization.

This positive establishes the selected provider's own ledger conditions at the
snapshot. It does not establish that no external process can act or that the
snapshot remained current afterward. The DTO explicitly retains
`provider-post-snapshot-authority-unverified` and
`remote-consumer-native-relay-authority-unverified`; the outer receipt remains
`PARTIAL`. Original native custody, actual current control fences, recipient and
relay authority, and full credential exposure history remain separate obligations.
Calling credential-bearing `POST /query` or issuing a media proof is not an
inspector revocation check. The read-only inspector does neither, and it never
converts signed claim expiry into a claim about installed receiver policy.

Source controls use the production bounded port, catalog/history validators,
closed parsers, ES256 signer/verifier and real protected fixture files. Only the
final SQL socket is explicitly INERT. The populated positive contains a retired
enrollment, closed task, settled model reservation/dispatch and expired media
lease with original joins. Controls separately retain live registration, task,
model and media blockers, absent dispatch/delivery uncertainty and adversarial
cross-generation/key/epoch/owner bindings. These source methods do not replace
installed SQL, runtime or human acceptance.
