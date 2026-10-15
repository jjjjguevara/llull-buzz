# Private local metadata inspection — source candidate

This delivery prepares 27 fixed PostgreSQL metadata views and the standalone
`buzz-inspection` command. It adds no HTTP route, invocation/publication/evidence
purpose, replay admission write, agent credential daemon or native business effect.
The prepared forward migration is `0009_private_metadata_inspection.sql`. No
installation, grant, account creation or activation was executed for this source
candidate. The existing eight migrations and ordinary provider source stay intact.

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

## Current-ledger reconciliation and execution handoff

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
