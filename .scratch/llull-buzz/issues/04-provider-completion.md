# Complete and qualify the restricted communication provider

Type: task
Status: claimed
Blocked by: none
Driver: Codex local implementation and test operator, 2026-09-21
Parent: [Provider map](../map.md)

## Authority and completion criterion

Owner instruction: complete the entire accepted restricted provider, with actual
agent execution, governed business tools, publication, native/media surfaces,
recovery, distribution closure and test deployment. Continue draft PR #2 using
non-forced commits. Foundation-only and stop-before-integration restrictions are
superseded. No new Wayfinder session, client fork or replacement agent loop.

Complete production paths and applicable automated qualification for BZ-C01..08;
bind exact sources, dependencies, images, clients, commands and results. Supply a
working isolated test deployment and automatable human journeys. Actual human UAT
and independent review remain attributable judgments. A partial suite cannot resolve
this ticket or accept a whole proof profile. Preserve task 03's reviewer-owned state.

## Claimed work and existing contracts

| Item | Implementation / selected component | Capability / commitment | Controls, technical and human applicability |
| --- | --- | --- | --- |
| 04.1 | Discovery, enrollment, current authority and context retirement; contract ports / identity binding | BZ-C01/02; BZ-CMT01/02/03/06/09/14 | BZ-CTL01/06; BZ-PF01/05/07; AC-BZ05; BZ-UAT02 |
| 04.2 | Native intake, attachments, retained evidence, ordered observations and durable ACK; delivery ledger / publisher | BZ-C03/07/08; BZ-CMT02/08/10/12 | BZ-CTL03/05/07; BZ-PF01/03/04/06/07; AC-BZ01/04/06; BZ-UAT03/05 |
| 04.3 | Actual buzz-acp / buzz-agent, admitted model proxy and typed MCP bridge; launch protocol / task supervisor / tool gateway | BZ-C04/05; BZ-CMT05/06/07/09/10/11/12 | BZ-CTL01/02/04/05/06; BZ-PF01/02/04/05; AC-BZ02/06; BZ-UAT01/05 |
| 04.4 | Durable signed publication, audience changes, native and Blossom gateways; publisher / media | BZ-C06/07; BZ-CMT06/08/09/10/12 | BZ-CTL01/03/05/07; BZ-PF01/03/04/06; AC-BZ03/04; BZ-UAT03/04 |
| 04.5 | Real HTTPS consumer commit-time authority and original-owner recovery; tool gateway | BZ-C04/05; BZ-CMT06/10/11/12 | BZ-CTL01/04/05/06; BZ-PF01/02/04/05; AC-BZ02/06; BZ-UAT01/05 |
| 04.6 | Restore, upgrades, operations, performance, dependency/OS notices, portable delivery and isolated deployment | BZ-C01..08; BZ-CMT04/10/11/12/13/14 | BZ-CTL02/05/06/08; BZ-PF02/04/05/07; AC-BZ01..06; BZ-UAT01..05 setup only |

Contracts: [provided/required](../../../docs/architecture/contracts/PROVIDED-REQUIRED.md),
[wire](../../../docs/architecture/contracts/WIRE-PROFILE.md),
[profile](../../../docs/bootstrap/INITIAL-PROFILE.md),
[components](../../../docs/architecture/components/REGISTRY.yaml),
[assurance](../../../docs/architecture/security/ASSURANCE.md),
[human cases](../../../docs/acceptance/UAT-CATALOG.md).
These bindings claim work, not completed capability or acceptance.

## Comments

2026-10-12 — Item 04.3/04.5 governed tool dispatch source increment. Refreshed
local/live PR #2 at `c838c54bcdbf8354f0438b530a4faefdf7571311`, open/draft
with no reviews. Integration owner and delegated provider implementation owner
repair the existing typed consumer boundary: original root/worker/credential
checks now sample database time after awaited current scope checks, and durable
custody/commit consumes one frozen monotonic interval. A final bounded real
PostgreSQL clock read can only shorten that interval. Expiry or unavailable
clock preserves exact durable unknown with no consumer execute; original lookup
never becomes a new send or inferred nonexecution. No new action/schema/ledger
or product-specific implementation is introduced.

Independent finite source review accepted the repair. Edition-2021 formatting,
whitespace and bounded source assertions pass; all preceding PostgreSQL controls
remain a byte-identical prefix. Three appended real-clock/row-lock/custody-trigger
controls and compilation are **AUTHORED/UNRUN**, with commands and exact source
hashes in [completion evidence](../../../docs/implementation/COMPLETION.md#governed-tool-dispatch-deadline-source-increment-2026-10-12).
The source defect is established; it is not a proven diagnosis of the old native
mention without signed reply. Actual supervised model/MCP/native publication,
consumer composition and named-human UAT remain open. The profile stays inactive,
the historical 15,134,720-byte physical storage deficit remains unresolved, and no
compiler/cache allocation or runtime environment was created. Task 04 remains
claimed; no capability or human case is accepted.

2026-10-12 — Integration owner and delegated provider agent continue items
04.1/04.2 with the consumer-neutral native navigation read. Refreshed local/live
PR #2 at `bf3db77a3580701d80fbdf4f30052a9db8828668`, open/draft with no reviews.
The optional `read-native-handoff` action uses the existing signed service
transport, proved human enrollment and fresh browser assertion; it verifies the
current native audience and emits only selected upstream channel/message URIs.
No callback, task, prompt, publication, key grant or observation is created.
Repeated intents revalidate current access rather than replaying permission.
Existing action grants and wire/discovery responses retain their meaning.

Independent integration-owner source review accepted the finite implementation.
Edition-2021 Rust formatting, whitespace and 53 bounded schema/legacy-source/local
link assertions passed. The first streamed assertion script had an unmatched
parenthesis and executed no checks; the corrected script produced the reported
53 passes. The entire previous intake test file remains a byte-identical prefix;
historical authentication freshness/browser/release methods and publication,
discovery, main wire schema and shared PostgreSQL fixture are unchanged.
The six appended real-signature/PostgreSQL/HTTP controls and compilation are
**AUTHORED/UNRUN**. The separately versioned optional schema has RFC 8785 SHA-256
`381c8cf4f2b574285bb39e01bd3ab16d369e923e1ea33f0eb1c82cee6d007d7f`.
See [completion evidence](../../../docs/implementation/COMPLETION.md#current-human-native-navigation-source-increment-2026-10-12)
for scope and reproduction. No compiler/cache allocation, new environment,
runtime or temporary evidence assembly was created. The earlier 15,134,720-byte
physical deficit remains unresolved; this source pass does not clear its gate.
The profile stays inactive and the task remains claimed; installed native return,
composed journeys and named-human acceptance are unqualified.

2026-10-11 — RootSuccessor integration owner and `buzz_runtime` implementation
agent continue items 04.3/04.4 outside the deployment VMs. Published
`b75d2b46e00083a6e06be9de9939f696723c275b`: after awaited native audience/parent
reads, publication rechecks the original task deadline/state before durable
signed custody and before submission. The existing lock order and original
unknown/no-resend semantics remain. Independent source review accepted; configured
edition-2021 formatting and whitespace pass. Six existing PostgreSQL controls
and signing helpers remain byte-identical; the new two-boundary expiry/positive
control is authored/unrun, as is compilation. Root's first formatting invocation
used the wrong edition2024, changed no files and was corrected. This does not
establish the cause of the old missing native reply or activate the profile.

The bounded read-only storage reconciliation found no known residual or open
consumer; all31 repaired aliases and31 siblings still match the original custody
record. The retired576-path manifest and precompile linkage inventory were lost,
so the historical15,134,720-byte physical deficit remains unresolved. No safe
deletion target, new compiler allocation or new environment was introduced.
The actual PR record is
https://github.com/jjjjguevara/llull-buzz/pull/2#issuecomment-6112942633.

Item04.3 now implements current root-state reconciliation on first valid late
model settlement. Existing `recovery_pending` semantics retain stop-new-work,
no worker, original generation/budgets/receipts and unresolved tool/model
incidents. Only the last known original outcome permits stopped Pending;
completion still requires the explicit business attestation. Root independently
reviewed the production path and exact three-file seals, reproduced edition2021
formatting and whitespace checks, and verified the three previous PostgreSQL
controls remain byte-identical. Two additional controls cover partial/final
settlement, foreign scope, business uncertainty, model incident, immutable replay,
denied replacement work and explicit completion after original owner lookup.
They and compilation are AUTHORED/UNRUN. No automatic completion or new execution
authority is introduced. Runtime, provider, distribution and human qualification
remain open; this ticket is not resolved.

2026-10-11 — Items 04.2/04.4 native original-byte lease claim and source increment.
Refreshed local/live PR #2 at `0c36e784008928f69595ed93e8c5d962beb14c7e`,
open/draft with no reviews. The selected native CLI emits a relay-wide BUD-11
identity proof; it does not prove release of one artifact. The existing BZ-R05
registered assertion/lease option is realized as a new closed, explicitly
registered `lease-native-attachment` operation, rather than changing the old read
or retention operation. The original consumer EvidenceAccess assertion is the
authority; release_ref remains consumer provenance. Native key identity comes
from the existing proved enrollment, with no parallel principal/grant registry.

The configured provider now wires this lease POST and inert native GET/HEAD to
the fixed original owner. Exact source/hash, same module/context, enrollment and
authority epochs, audience revision/membership and the original assertion and
retention deadlines fence reads. Immutable command/lease custody commits together;
fresh retries cannot renew an old lease. Ambiguous current key/hash leases deny.
The schema digest changes and migration 0008 must be adopted explicitly; existing
consumer pins/actions/profile activation are unchanged. Attachment publication,
upload, range and preview guards remain intact. Authored signed-proof and actual
PostgreSQL/HTTP controls remain **UNRUN** pending the unresolved physical compiler
storage gate and an admitted external runtime. No new compiler/cache allocation,
container, provider effect or human UAT verdict is claimed.

Source-only checks for this lease increment: formatting and whitespace pass;
six unchanged documentary schema scenarios and fourteen lease shape controls
pass with the existing Python/JSON Schema toolchain. An initial additional
invalid-date expectation failed because that environment lacks JSON Schema's
optional date-time format checker; timestamp rejection remains covered by the
authored, **UNRUN** Rust deserializer control, not a claimed Python format pass.
All four preceding native-intake test bodies and the existing publication,
attachment retention and authentication modules remain byte-identical. Local
document targets and four credential-pattern families pass. No compilation or
PostgreSQL execution occurred. A bounded read-only disk observation reports
60,559,056 KiB available; this does not reconcile or reattribute the earlier
15,134,720-byte unresolved compiler deficit.

2026-10-11 — Item 04.4 native thread correlation claim. Refreshed local and live
open/draft PR #2 at `fb9e826604e689d5656ae705e134120f2caa3875`, no reviews.
The publisher verifies the signed immediate parent but currently signs every reply
with root equal to parent. A native mention already inside a conversation therefore
loses its original thread root. Reuse the selected `01b6174` shared NIP-10 parser
used by CLI/ACP/relay, verify the derived signed root through the same fixed owner
and channel, and preserve exact ancestry at both publication fences. No new
publication field, release authority, dependency or schema digest is needed.
Historical missing signed-reply causation remains unestablished; correcting this
source defect does not qualify a full native journey. The implementation and
existing native-source/PostgreSQL controls remain provider-neutral.

2026-10-11 — Thread correction ready for independent review. The native owner
now resolves and validates the signed conversation root before signing and again
before send; frozen bytes must match that exact root/immediate-parent pair.
Top-level publication and the optional JSON field retain their existing meaning.
Actual cached source checks: `cargo test --offline --locked -p
llull-buzz-provider --lib publication::reply_tests -j1 -- --nocapture` passed
all three controls (8.83 seconds compilation, 0.01 seconds execution), including
direct/nested ancestry, missing root, foreign channel and missing signing context.
`cargo check --offline --locked -p llull-buzz-provider --test postgres -j1`
passed in 6.01 seconds. The existing PostgreSQL signed-reply case now asserts the
original root as well as the immediate parent; it is **COMPILED, RUNTIME UNRUN**.
No native service, model, consumer effect or human acceptance was exercised.

Compiler storage was bounded to 180 seconds, 256 MiB growth and 128 KiB output in
the existing cache; observed peak growth was 150,552,576 bytes. Initial cleanup
refused a replaced shared build-script alias before deletion; reconciliation also
refused an omitted wire-object name in its narrow allowlist before deletion. Both
failures remain recorded. With no active compiler and the cache lock held, exact
invocation-created directory/file identities were reconciled and 576 output paths
retired; no such path remained. Actual retirement returned 153,894,912 filesystem
bytes (61,861,888,000 to 62,015,782,912 free). The 31 replaced shared aliases were
preserved: each is byte-identical to its older adjacent hashed executable, totaling
23,953,808 logical bytes and 24,027,136 stat-allocated bytes; combined path/inode/
size/allocation/content identity digest is
`300351cfa21c9dda7846a58320974d349f132c9e001ed396d4200ce74b1a223b`.
Stat allocation does not establish exclusive physical allocation. Precompile
alias allocation/link relationships cannot be reconstructed from the failed
supervisor's lost memory-only inventory; no restoration is claimed. A bounded
current-user deleted-open-file observation found no removed target output still
open (107,388 bytes inspected in memory, zero errors). Original free
space was 62,033,969,152 bytes; the latest two sync/read observations were
62,012,428,288 and 62,012,436,480 bytes. The global 21,532,672-byte deficit remains
unresolved and is not attributed to unrelated work or declared a storage pass.
No next large task is admitted by these results. No shared cache was pruned or
relinked. Item 04.4 and full native qualification remain open.

2026-10-11 — Subsequent bounded cache reconciliation preserved every logical
shared path. For the 31 aliases proven replaced during this invocation, verified
regular distinct-inode/nlink-one originals with matching bytes, mode and extended
attributes were cloned using APFS `clonefile`, one same-directory temporary at a
time, then atomically substituted only after identity rechecks. Original hashed
executables were unchanged; final contents, access/modification timestamps and
modes matched, with no temporary or deleted-open target residual. This was cloning,
not hardlink creation or restoration of unknown historical link relationships.
The first metadata probe refused an unavailable Python `listxattr` API before
writing; the bounded system attribute reader supplied the actual comparison.
The operation took 16.29 seconds. Its free-space observation was negative:
62,022,410,240 to 62,021,308,416 bytes (minus 1,101,824), so no additional physical
reclamation is claimed. Final verification observed 62,018,830,336 and
62,018,834,432 free bytes, 15,134,720 below the original compile observation.
The compact private custody receipt explicitly records completed alias replacement
and **unresolved physical reconciliation**; its digest is recorded in the current
review handoff. The earlier positive output retirement and every failed custody
check remain valid observations, with no speculative cause for the global deficit.

2026-10-11 — Items 04.3/04.6 successor claim: Codex provider implementation
agent owns the existing task replay projection correction. Refreshed public
PR #2 and clean local branch both select
`bea4aae17d38a4b29b7d98bae2e840749188d16f`, open/draft with no reviews.
The start/cancel/reconcile replay paths currently replace recorded receipt
execution/revision with later task state; control replay also drops the
original response's task/attempts/recovery wrapper. Preserve immutable command
receipts while returning the current scoped projection in the existing result
field, and exercise lost-acknowledgement/unknown-effect reconciliation in the
existing PostgreSQL suite. No provider activation, fresh execution, authority
extension, consumer source or new wire field is authorized by this correction.
Source work remains outside VMs, with no dependency fetch or new environment.
Initial observed Mac free space: 60,557,716 KiB; owned source delta bounded below
128 KiB. Existing shared target cache is not a task-owned disposable tree.

2026-10-11 — Replay correction ready for independent source review. Start replay
preserves the original receipt; cancel/reconcile replay preserves that receipt
and its existing task/attempts/recovery wrapper. Current scope and final assertion
freshness remain required. One new real-PostgreSQL scenario covers pending receipt
versus running/completed projection, a committed consumer effect with lost ACK,
both control routes across generation fences, exact original-owner lookup without
redispatch, unchanged stored results, changed intent, cross-module denial and
revocation. Prior PostgreSQL test bodies are unchanged; the existing start fixture
now exposes its actual original command/result through a reusable helper.

Actual local source checks: host-filtered locked/offline Cargo metadata PASS;
`cargo check --offline --locked -p llull-buzz-provider --test postgres -j1` PASS
(8.76 seconds), compiling the provider and the complete PostgreSQL test target;
`cargo fmt --all -- --check` and `git diff --check` PASS. The first unfiltered
metadata command refused missing `android_system_properties v0.1.6` without any
download; host filtering resolved only the applicable cached dependency graph.
No PostgreSQL, native service, model, consumer or provider effect was executed.
Run the new control in an admitted disposable environment with
`scripts/test-postgres.sh --case task_replays_preserve_receipts_and_current_original_owner_recovery`.
It remains **AUTHORED/COMPILED, RUNTIME UNRUN**, not a qualification or profile
activation. This task and all outstanding capability/human acceptance claims stay open.

Compiler custody: no active compiler before launch; existing target inventory
contained 68,459 entries. Execution was limited to 180 seconds, 64 MiB of allocation
growth and 128 KiB of output. Observed peak growth was 61,353,984 bytes. Initial
retirement stopped because deleting children changed a new parent directory's
mtime; this failure is retained. Reconciliation verified the invocation's exact
APFS birthtime/inode identities and no remaining compiler, then removed its three
empty incremental directories, three zero-byte locks and three generated metadata
files. Final reconciliation returned 4,182,016 observed filesystem bytes
(62,039,052,288 to 62,043,234,304 free); final free was 42,987,520 bytes above the
62,000,246,784 precompile observation. No invocation-created inode remains.
Preexisting shared parents, fingerprint and dependency records were preserved;
this is not a claim that compiler-updated cache metadata was restored byte-for-byte.

2026-10-10 — Items 04.2/04.4 successor claim: Codex Buzz implementation agent
owns a bounded native attachment retention and EvidenceAccess byte path. The
refreshed public draft PR and clean checkout are both `b31dbccb879274d222bae12193a89ad0dc713030`.
Original signed metadata alone remains insufficient. The increment uses the
existing native-input identity, registered consumer authority and fixed private
native origin; no caller-selected URL or parallel evidence registry. Original
command receipts remain immutable, and consumer registration/native media
publication remain separate. Source work uses existing tooling outside VMs;
new real PostgreSQL/installed media controls remain unrun until qualified.

2026-10-10 — Items 04.2/04.4 attachment source increment: actual configured native
origin now supplies exact-hash BUD-11 reads for separate transactional retention;
EvidenceAccess returns immutable bytes under fresh registered scope and purpose.
Historical intake receipts and consumer registration are unchanged. Migration 0007,
three PostgreSQL cases, byte-integrity/native HTTP controls and restart snapshot
coverage are authored. Rustfmt, locked offline metadata, Bash syntax and Git
whitespace passed. JSON Schema checked six unchanged examples, one new positive
and six negative shapes; new schema SHA-256 is
`9f006108c8b66ac9432a2dafdc59c19651464e2535b24b0d6387386a814e9b89`.
No compiler or new Rust/PostgreSQL/runtime test was run locally; hosted controls,
selected source adoption and native media/publication/UAT remain outstanding.
No runtime/cache/archive/environment was created. Owned retained output is the
finite source/docs delta below 128 KiB; measured Mac free space before final source
checks was 77,845,000,192 bytes. The existing shared target cache was not touched.


2026-10-10 — Item 04.4 source increment: optional `reply_to_event` is bound to
the exact publication release. The publisher verifies original signed native
message identity/channel through the existing owner before signing and again
before dispatch; the unchanged upstream SDK supplies native reply tags. Omitted
fields preserve historical serialized bytes. Added source signature/correlation
controls and a PostgreSQL delivery/denial/replay case. Twelve provider/wire library
tests passed (3 + 9); strict offline Clippy including authored PostgreSQL tests
passed in 7.10 seconds after correcting a test-module placement lint. Rustfmt and
whitespace checks passed. PostgreSQL, installed native clients and composed
mention-to-reply remain unrun for this increment. The restricted profile stays
inactive. The existing source cache was reused without an environment or runtime.

2026-10-10 — Item 04.6 source correction: all three native Docker recipes
now derive the distribution inventory target from the exact Rust 1.98.1
compiler that built the executable, and provider metadata uses that same
compiler. This removes an unconditional Linux arm64 inventory label from
native amd64 builds. The existing compiler/build flags, immutable upstream
source and runtime safeguards are unchanged. Static recipe inspection and
Git whitespace checks passed; amd64/arm64 image builds remain unrun. No
provider profile is activated and earlier image results do not carry forward.

2026-10-10 — Item 04.3 successor claim: Codex Buzz implementation agent owns
the reservation-to-dispatch accounting increment under the owner's full Akita
implementation kickoff. Live PR #2 and clean local head are both
`b244ba7560112e498ee6d68a48d035c99cb0b8c2`, open/draft, with no comments,
reviews or inline review comments. The existing task remains claimed.
Implement signed begin/settlement operations for the existing trusted model
gateway, immutable original reservation/request identity, no replayed dispatch,
retained unknown charges and root fencing. Bind BZ-C04/05, BZ-CTL01/05/06 and
BZ-PF04/05 using the existing PostgreSQL suite; no new agent loop, provider
activation, model credential, human verdict or parallel tracker. The integration
owner owns consumer assembly and all VM operations. Source/compact records are
bounded below 1 MiB; initial Mac available space is 80,467,448 KiB. The existing
12 GiB target cache is shared retained work and is not owned by this increment.

2026-09-21 — Starting inspection: local and remote PR head
`667f8118b2386e5a4dd98e90885b266a4432bfc9`; main
`f3fe82e94e878eba7173aaf326085b77b9c9bc51`. Clean local checkout, PR open/draft,
no comments or reviews. PCR2 remains accepted at bootstrap scope. Historical local
validation and hosted failures remain intact.

2026-09-21 — Owner answer to test-provider question: “Use codex/chatgpt pro oauth”.
This directs the model-provider amendment away from the initial Anthropic selection;
compatibility, token/accounting limits and isolated credential handling require actual
qualification. Local `codex-cli 0.155.1` reports “Logged in using ChatGPT”. No token
value was printed or copied into the repository. Pinned buzz-agent supports the
OpenAI Responses base-URL seam; that source fact alone does not prove OAuth service
compatibility. No paid API fallback or new spend is inferred.

2026-09-21 — Owner answer to deployment/private-coordination question: “continue
independently until that lane completes”. Independent implementation and isolated
local qualification proceed. Composed counterpart evidence and the external target
remain pending; interim synthetic counterparts are not final integrated evidence.

2026-09-21 — Item 04.6: six checkout regression cases first failed against the old
checker (unsupported implementation-stage argument), then passed after stage-aware
applicability and complete-subject contract loading. Both original helper self-tests
also passed. The portable command retains the unchanged supplement and verifies its
preceding checker against the immutable bootstrap object. Full current-subject results
are recorded separately after committing a clean subject. Hosted history is preserved;
automatic PR runs are replaced by explicit manual dispatch while Actions is exhausted.

2026-09-21 — Items 04.1/04.2: authenticated discovery and a transactionally ordered,
module/context-scoped observation journal are implemented in the working tree.
Three new real PostgreSQL/signature scenarios passed after missing-method red tests
and a corrected invalid-query test helper. See [continuation details](../../../docs/implementation/COMPLETION.md).
No whole capability/proof profile is accepted; snapshot recovery, native mediation
and background effect coverage remain in progress. Item 04.5 is adding an actual
HTTPS/independent-database synthetic owner, not a `ConsumerPort` double.

The first OAuth compatibility request returned HTTP 400 for `max_output_tokens`.
The exact backend output-limit behavior is a qualification gap, not a reason to
silently drop cumulative accounting or declare a live model pass.

2026-09-22 — Clean-source continuation results: discovery/observations at
`d6e9288cff7613c9e793367e9ee804bfa666eea2`, HTTPS owner commit/recovery at
`2fb25e84d6b6e8580cf796a62a93212e501eda21`, and retained native intake at
`8b9056f96f262b53e1415fb07bd42a2e28fe220c` passed their targeted PostgreSQL scenarios.
Strict Clippy passed before the latter clean-source reruns; the full portable document
stage passed at `8b9056f…`. That source is pushed to the same draft PR, whose description
now reflects full completion scope and continuing work. No new hosted Actions run
appeared after publication; the historical failures remain visible.

Item 04.4 now has a passing working-tree publication ledger scenario: frozen signed
identity, original-owner lookup after lost response, changed-audience denial and
preserved canceled-root scope. Its native transport remains an explicit fixture pending
the real relay/client run. Item 04.6 has an isolated Ubuntu 24.04.4 arm64 VM running
the selected Docker 29.8.1; pinned native executables are compiling there. Full gateway,
agent/model/tool, media, restore and distribution qualification remains claimed work,
not an accepted capability or proof profile.

2026-09-22 — All seven PostgreSQL scenarios and twelve library tests passed at
`953767bbda59018ebe4b9f9aad19126937a6e3a4`. Item 04.2 adds frozen, scoped snapshot
recovery with final-page durable acknowledgment, plus explicit duplicate-receipt
conflicts. Its working-tree PostgreSQL scenario passed after a missing-implementation
red and fixture correction. Current scope and precise remaining boundaries remain
in [continuation details](../../../docs/implementation/COMPLETION.md).

2026-09-22 — Item 04.6: the selected Docker 29.8.1 task VM built the unmodified
upstream `buzz-agent`, `buzz-acp`, `buzz-relay`, `buzz` and `buzz-admin` at the
pinned revision. The build log SHA-256 is
`410b1dc2d0bf7e2202a8ba2628691f5a5e78c905a70a72867fb6d4736fba4282`.
The isolated PostgreSQL 16.15, SeaweedFS 4.47/PostgreSQL filer and Valkey 8.1.10
storage stack passed real authenticated S3 write/read/range and role/access
denials, with evidence recorded in continuation details. These qualify the
storage component, not yet the native relay/agent/client or media gateway.

2026-09-22 — Items 04.4/04.6: the pinned upstream relay and real `buzz` CLI
passed private-channel create, signed-message recovery, relay enrollment
denial, channel-member grant/revocation and owned relay restart with exact
event/media recovery on the selected Docker Engine. A real Blossom upload
then exposed a concrete disclosure counterexample: the original signed
private-channel message carried the PNG `imeta` digest, yet a relay-enrolled
identity outside that channel retrieved the exact PNG by hash.
`probe-media` records the failed artifact gate and exits nonzero. The origin
has no host-published port; this is not permission to activate the profile.
Provider media mediation and bypass-proof native routing under item 04.4
remain required. See [continuation details](../../../docs/implementation/COMPLETION.md).

2026-09-22 — Item 04.6: a corrected task-only backup/restart and a fresh
isolated PostgreSQL/Seaweed/relay-data restore passed. The first attempts
exposed a relay-versus-Seaweed startup race; the corrected path waits for an
authenticated retained S3 object before starting the relay. The new namespace
recovered the original signed event, exact media digest and revoked-channel
denial after rebuilding its disposable Valkey cache. The restored provider DB
contained no populated command/effect records, and protected key backup is
still open; this does not resolve item 04.6 or BZ-PF05. Evidence and exact
source/target identities are in [continuation details](../../../docs/implementation/COMPLETION.md).

2026-09-22 — Items 04.2/04.4/04.6: a BuildKit image from committed provider
source `eae913c6e4c9a9d4cfcf25bbd2c59be648aba438` booted with the real
PostgreSQL database and pinned relay in the owned private stack. The initial
`wss://host` switch changed upstream tenant authority from `host:3000` and
created a new empty community. Commit `8ec269206ebbb86d776b406c8c52a364addf4649`
retains the host and port while changing only the signing scheme. The production
`HttpNativeOrigin` then recovered the original signed event and current
two-member audience; a clean-source WSS-posture backup/restart also passed.
The image used an exact-ID cached dependency builder, so a clean independent
distribution build remains open. No external TLS terminator, live publication
command, media gateway, model/tool execution, populated-effect restore or
human UAT is qualified by these results. The status stays claimed.

2026-09-22 — Items 04.4/04.6: a compiled Linux arm64 test executed a signed
synthetic `publish` command through the running provider, real PostgreSQL and
unmodified pinned relay. It recovered the exact signed event from the relay;
a fresh signed retry reused the original native identity with one delivery
row. The manually invoked case exited 0 at test source `c3d6bd0ef19a02ce2a4fc1fb9c974b4a7e95a42e`;
its private log SHA-256 is
`83de1724375ec0499293234679d3b09e21ba9ed3ba4c35d7a009c8ea8be7b5c3`.
An initial scripted cold build hit root-versus-UID key permissions, and a
revised run retained a completed test executable but timed out compiling the
provider CLI. The credential-separated runner is being qualified separately;
these failures are not erased by the direct positive case.

The selected stack then backed up and freshly restored two completed
publication rows into a separately owned PostgreSQL/Seaweed/relay namespace.
Signed-byte digests, native event IDs and completed states matched, both
native events were present, and the original media digest and revoked-channel
denial recovered. Backup and restore exited 0; manifest SHA-256 is
`b5c486d487f4d17293f293705bc339238972047fcae7800c7fd6eab53802fcda`.
The restore-only namespaces were removed by exact owner labels; the source
test deployment remains running. Protected-key restoration and full native
gateway coverage remain open.

Item 04.3: `codex exec` with ChatGPT login completed one synthetic
`gpt-5.6-luna` turn (`OK`, 17,960 input/five output tokens, no tools); log
SHA-256 is `49f6438698d2a939af60cd53499b7942da1d84d8d308604781c142aeee56bb69`.
This does not cure the observed 400 for `max_output_tokens`, prove a bounded
Buzz model proxy or execute the ACP agent loop. Pinned `buzz` CLI source also
refuses to sign media GET for a non-relay origin; the publisher at that source emitted
provider-origin attachment URLs. Item 04.4 requires a relay-origin governed
media gateway and actual artifact release before attachment UAT. No item or
whole proof profile is accepted.

Item 04.6: the locked Linux arm64 provider target has 222 distinct package
versions, not 290 once repeated Cargo tree entries are collapsed. A new build
inventory copies each selected package's license/notice texts, pinned workspace
root texts, and three exact upstream texts absent from published crate archives.
The host run exited 0 with no undeclared or missing texts; its manifest SHA-256
is `96c56e0a775a350602c911ff89ad1f31ea41b39320edc8e652b4bc1166520a52`.
The revised Dockerfile records OS package versions and copyright-file hashes
and requires every installed package's copyright file. This source has not yet
produced a revised image, so distribution closure stays open.

The corrected credential-separated `check-publication-live` command later
exited 0 at archived committed test source
`b8399e74db3795852ae4d011e0ccaf0045840ab1`. One Linux arm64 release
integration test passed in the read-only UID 65532 container after an offline,
credential-free build; its log SHA-256 is
`b9f85c3ba5bf5383a9284ef188e53b503d734320089db5e2cb84bfe6e0d0ddc4`.
The original provider image remained healthy after the run. This upgrades the
scripted live publication evidence, not the media/client/model claims.

The cached-builder provider image from source
`e87d1b87571e28bf99531cba670e5ecba889b575` built with ID
`sha256:daba1b7d778e8f17140ef2d41568a1683046c621a88eda2aab7a7bdafebcf50c`.
Its binary hash equals the prior live-tested image. The Linux image includes
221 applicable Rust package licenses (zero missing) and 91 OS package/version
rows with 90 distinct copyright-file hashes. The host-only
`core-foundation-sys` caused the earlier 222 count. The owned test provider
was switched to this image; health and fixed native-origin probes passed.
This is still a cached-builder build, not a clean independent distribution
qualification. The pinned upstream graph has a host-preliminary 500-package
inventory with zero missing texts after 18 absent crate-archive licenses were
resolved to pinned upstream texts or the declared Apache option. Its updated
image is not yet built.

2026-09-22 — Item 04.3: the owner authorized a Google free-model test API in
the existing `llull-buzz` project. AI Studio imported it but rejected its UI
key-creation request as suspicious. The Cloud CLI created an auth-enabled key
bound to a dedicated service account and restricted to the Generative Language
API. The first CLI key was immediately deleted after its output unexpectedly
contained the key value; the replacement is in an ignored mode-0600 local file
and a task-owned read-only Docker secret volume. The old key is absent from the
active list. Cloud Billing returned false and AI Studio labeled the project
Free tier. `gemini-3.6-flash` completed bounded Chat Completions and returned
one synthetic typed `set_label` tool call. The unchanged pinned `buzz-agent`
completed a real ACP prompt through a credential-separated, internal-network
test proxy and returned `OK`/`end_turn`. The private result hash and exact
limits are in [completion evidence](../../../docs/implementation/COMPLETION.md).
This proves the upstream model seam, not durable task-budget mediation or a
business MCP bridge. The selected profile and human UAT remain unqualified.

2026-09-22 — Item 04.6: task-local RustSec scan found the provider's direct
`rmcp 1.1.0` dependency vulnerable in its optional Streamable HTTP server
transport. The lock and manifest now select patched `rmcp 1.4.0`; host check,
three launch-library tests and a repeat audit with zero vulnerabilities passed.
The pinned upstream lock separately has two `quick-xml` versions affected by
two denial-of-service advisories. These findings are recorded without a
security-certification claim. Revised image/runtime verification is pending.

2026-09-22 — Item 04.4: committed test source
`68cc4d2498429c271341650b0e743da02644abb9` passed two Linux arm64
publication integration cases. The new case made the pinned relay commit a
signed event, hid its accepted response behind HTTP 502, and then reconciled
the provider's unknown record by looking up that original relay event. Exactly
one relay submission was observed. `check-publication-live` and subsequent
`check-provider` both exited 0; the private test log SHA-256 is
`c527f91e5e7d6470d99b5fa218706512ac7977fbbd38ef6bee8bc19e5584c2ae`.
This covers one lost-response boundary, not process death or media/client
delivery. The deployed provider health still marks model/native/media gateways
false and restricted activation false.

The next isolated backup/fresh restore exited 0 with five completed publication
rows, including the lost-response event and exact signed bytes. The restored
owner also recovered the retained native event and media bytes while a revoked
channel read remained denied. The backup manifest and target owner are recorded
in [completion evidence](../../../docs/implementation/COMPLETION.md).

The first actual `buzz-acp` launch initialized the pinned `buzz-agent` through
a credential-separated process container, but NIP-42 rejected the native
WebSocket because the relay's public WSS URL differed from the dialed WS URL.
Item 04.3 remains open. A build-feature amendment for native TLS roots is being
qualified against a task-local CA and exact WSS origin; it changes no pinned
upstream source.

2026-09-22 — Items 04.3/04.6: a task-only TLS terminator on an internal network
now serves the relay's exact advertised WSS host and port. The synthetic CA
and hostname passed TLS verification, while wrong-host and untrusted-root
clients were denied. The real `buzz` CLI performed an authenticated HTTPS
channel search and created a separate bot test channel. The old WebPKI-only
`buzz-acp` initialized the credential-separated agent but exited 1 on unknown
issuer, establishing the need for the native-roots build feature. The amended
binary/mention journey is still pending. Exact image/log identities and limits
are in [completion evidence](../../../docs/implementation/COMPLETION.md).

2026-09-22 — Item 04.6: the initial broad disposable PostgreSQL run exited 101
because it included two live-relay cases without their separate stack inputs;
the long foundation case also hit an unidentified exhausted worker claim.
The runner now filters only those two independently run live cases and pins
the selected PostgreSQL image. Eight real database cases and a restart digest
comparison passed at `b4f3cc5da493bb19653be9350b8c7020e3f2ba51`.
After widening the test fixture's two-second claim window while preserving its
absolute-expiry denial, the same eight cases and restart comparison passed
again at `86d7ac4e85039dbdd9f4173d5f318c00db3ef311`. Rust formatting,
12 workspace library tests, strict all-target Clippy and the five-stage local
documentation check exited 0. This remains partial technical evidence, not
a whole proof-profile or human UAT acceptance.

2026-09-22 — Items 04.2/04.5/04.6: background effect transitions now enter
the scoped, content-minimal observation journal with their original attempt
identity, atomically with the durable state change. The HTTPS owner test first
failed with zero of two expected transition records after a committed write
and lost-response lookup, then passed after the change. Revocation fencing
also emits an uncertain transition. Earlier full PostgreSQL reruns still had
an unidentified exhausted worker claim in the long foundation case; the
case-specific real database run passed, and the pre-claim fixture was widened
while preserving a real-clock expiry denial. At `35e23aa`, all eight disposable
PostgreSQL scenarios and the original restart digest passed. At `56582c4`,
the HTTPS scenario plus a PostgreSQL restart digest expanded to observations
passed. Exact command/log hashes and limits are in
[completion evidence](../../../docs/implementation/COMPLETION.md). This does
not accept BZ-C08 or substitute for the missing live agent, business MCP,
native/media gateway, composed consumer or human UAT evidence.

2026-09-22 — Items 04.3/04.6: the native-roots `buzz-acp` and all four other
pinned upstream executables built on selected Docker 29.8.1. The corrected
distribution build at `221d4e8` packaged a target-specific inventory of 499
Rust packages with zero missing local license texts, plus OS package/copyright
evidence. The task-only synthetic CA let the amended ACP initialize its
separate agent and subscribe to the authenticated WSS channel. The first
journey runner had a Docker stdout/stderr bug; after correction,
`gemini-3.6-flash` returned 503 and no native reply. The authorized free-tier
`gemini-3.5-flash-lite` then returned `OK`/`end_turn` in a direct unchanged
`buzz-agent` ACP session. A full ACP mention caused a completed model call
but no signed bot reply. The provider still lacks the separate governed
publisher tool and production model/task supervisor. Details and hashes are
in [completion evidence](../../../docs/implementation/COMPLETION.md); neither
ACP journey nor the selected production model profile is qualified.

2026-09-23 — Items 04.4/04.6: committed source `a395617` built a selected
Linux arm64 provider image and replaced only the owned provider in the private
test stack. Its native-origin probe and before/after health checks passed.
An offline release integration test from that same clean source ran two real
PostgreSQL/relay publication cases: signed delivery with same-command retry,
and lost native response reconciled from the original event without resend.
The log SHA-256 is
`ff3ad9a97b01642856169ddde0b47d2a1b1cd15b20790fac33d45ed0f366cfea`.
The provider image includes 221 selected Rust license records and OS copyright
evidence; it still used an exact-ID cached dependency builder. Model/native/
media gateways, full publisher handoff and clean independent distribution
qualification remain open. See [completion evidence](../../../docs/implementation/COMPLETION.md).

2026-09-23 — Item 04.6: committed backup tooling at `6cc7bde` hashed every
row of every public provider table before an isolated backup. A fresh
separately owned restore matched all 28 table digests, including 16
observations and seven publication deliveries, plus the retained native
event/media bytes and revoked-channel denial. The restored database's
immutable publication trigger rejected a direct tamper; one intentional
counter change in that disposable namespace was detected by the table
comparison. The restore namespace was removed by exact owner label, while
the source provider stayed healthy. Protected-key backup/restore, production
scheduling/encryption and a clean independent provider image remain open;
the test does not accept whole BZ-PF05 or BZ-C08. Exact commands, identities
and log hashes are in [completion evidence](../../../docs/implementation/COMPLETION.md).

2026-09-23 — Item 04.2/04.5: a fresh signed `observe-effect` GET now returns
the retained original owner, request identity, state and consumer result
reference after task completion, scoped to the original root and current
module/context authority. A focused real PostgreSQL/signature scenario passed
and a different module was denied; the script's PostgreSQL restart preserved
durable records. The broader foundation case hit a worker-lease conflict in
its later budget loop while the selected VM built dependencies. The focused
direct-API result also passed at clean source `5704abc` with a PostgreSQL
restart, alongside strict Clippy, 12 library tests and all five document
stages. A subsequent working-tree test passed through the mounted HTTP route
and required a cross-module HTTP 403. The full suite, retained business-result
bytes and gateway integration remain open.

2026-09-23 — Item 04.5: the new effect-result read first deadlocked with a
concurrent consumer/attempt lock order (`40P01`), then blocked on a held root
row (`55P03`). Red runs are retained. The implementation now reads the
database-protected immutable attempt and root identities without row locks,
checks fresh consumer/scope authority, and rereads the current effect outcome.
The focused working-tree PostgreSQL/signature scenario passed both concurrency
cases and a real database restart. The full suite and other command lock
orders remain separately unqualified; no proof profile is accepted.

2026-09-23 — Item 04.6: an independent selected-engine release image build
from committed `7794f927d9444ce0511f6032bbf17c6904be9bf5` exited 0 without
the cached dependency builder. Its provider binary equals the previously
live-tested `a395617` binary; 221 selected Rust package notices had no missing
local texts, and all 91 installed OS packages had readable copyright texts.
The image was deployed privately; health and fixed native-origin probes passed.
This closes the earlier *build execution* gap at that source, not final-source
distribution or the separate security findings. See
[exact identities and log hashes](../../../docs/implementation/COMPLETION.md).

The new effect-read route built in a second Linux arm64 image from committed
`db20d17da2c572bad4d1886728d86b050b0a0362` using an inspected exact-ID
cached builder. The task-owned provider now runs that image; health and native
origin checks passed with no host-published port. Its source has not received
the same clean independent build, and the deployed check does not yet send a
signed effect GET.

2026-09-23 — Item 04.6: two broad PostgreSQL runs on one shared disposable
database failed with varying inter-case assertions; failure logs are retained.
Commit `6b19ce377a23445e3672e89ee7f1143980493c96` gives each discovered
non-live scenario a fresh selected PostgreSQL container and real restart
comparison. All nine isolated cases and nine restart comparisons passed at
that committed source, including the new effect-read lock tests and the long
foundation capacity/budget/lease case. This is local real-database evidence;
the two live-relay cases remain covered by their separate runner, and model,
MCP, media/client, protected-key restore, composed Akita and named human UAT
qualification remain open. No entire capability or proof profile is accepted.

2026-09-23 — Item 04.6: committed operator tooling at `185d00e` encrypts the
task's five synthetic native signing identities with a separate owner-only
32-byte key and authenticates the backup owner before restore mutation. A
new backup from that source contained `native-identities.enc` and no plaintext
identity file. A wrong-key restore was denied before any target service was
stopped. A correct-key fresh restore matched all 28 provider tables, seven
publication rows, original native/media identities and revoked-channel denial.
The restored provider booted with the original service public key, then recovered
the exact event and audience through the source WSS signing posture. The restore
namespace was removed by exact owner label; the original private deployment
remains healthy. Exact commands, manifest/image identities and log hashes are
in [completion evidence](../../../docs/implementation/COMPLETION.md).

This is local synthetic protected-key recovery, not complete BZ-PF05 or BZ-C08.
Production key escrow, whole-archive encryption/authentication, backup scheduling,
failover, model/MCP/native/media gateways, composed Akita results and human UAT
remain claimed work. Historical private plaintext-key backups are preserved as
past test evidence and require an explicit legacy restore flag.

2026-09-23 — Item 04.4: `10491be` binds prospective attachment URLs to the
configured native relay origin and prevents signing/dispatch of attached
publications until artifact-specific media release is installed. A new
PostgreSQL/signature case was red before the guard and green afterward: its
authenticated intent stayed pending, no delivery row or relay submit appeared,
and a real server restart preserved the record. The existing text-only
publication/recovery case and strict Clippy remained green. This is an interim
fail-closed boundary, not an attachment or native-client pass; the gateway
and full item 04.4 remain claimed.

2026-09-23 — Item 04.4 follow-up: `adced75` closes the preexisting-unknown
delivery retry path that bypassed the signer guard. A real PostgreSQL/signature
regression retained a valid signed attachment event, then reproduced the unsafe
retry before the top-level check and passed after it. The original unknown row
and event ID remained intact, with zero native submit calls after the guard;
restart digests matched. This remains an interim boundary while actual
artifact-specific media delivery and native-client qualification are open.

2026-09-23 — Item 04.6: all ten discovered non-live PostgreSQL/signature
scenarios passed at committed `d6757eb`, each with its own selected PostgreSQL
16.15 container and matching real server-restart digest. This includes both
attachment first-dispatch/retained-unknown denial and text publication's
positive/recovery path. The earlier clean-source live runner passed its two
actual relay text-publication cases against image source `10491be`; the
`d6757eb` image booted privately with health/origin checks. Full native/media,
model/MCP, composed Akita and human UAT remain open.

2026-09-23 — Item 04.4 follow-up: `742dd78` restores truthful terminal
publication retry behavior for legacy attached events. The focused
PostgreSQL/signature case first failed because the earlier fence hid completed
status, then passed after the guard moved behind original-owner/terminal-state
lookup but ahead of pending/unknown dispatch. A text-only positive/recovery
case and strict Clippy also passed. This does not authorize attached media
delivery or accept a full native/media proof profile.

2026-09-23 — Item 04.6: the first clean build after the terminal fix was
cancelled at exit 130 because it archived superseded source `d6757eb`.
A new clean independent build of committed `742dd78` exited 0 on selected
Docker 29.8.1 with 221 applicable Rust notices (zero missing), 91 OS package
rows and 90 copyright-file hashes. The exact-source image booted in the
task-owned private stack; health and fixed native-origin checks passed.
The model/native/media gateway flags remain false and no whole capability,
proof profile or human UAT is accepted.

2026-09-23 — Item 04.6: the first final-source ten-case suite invocation
stopped before an assertion when its disposable PostgreSQL container exited.
The selected VM Docker partition had only 27 MB free. Two unattached,
exact-owner live-test cache volumes totaling about 1.6 GB were removed by
name; no shared resource or global prune was used. The same command then
passed all ten cases and ten real PostgreSQL restart comparisons at committed
`742dd78`, including the terminal-truth attachment regression. The original
startup failure remains in the evidence; no entire BZ-C01..08 profile is
accepted.

2026-09-23 — Item 04.4: `2f2cfbc` closes a same-command retry path that
resubmitted an `unknown` signed text publication after a lost native response.
The PostgreSQL/signature case was red before the fix (retry returned
`completed` after a second submit) and green afterward (original event ID,
`unknown` state, one submit, original-owner reconciliation to `completed`).
`d3f9555` adds the same one-submission assertion to the pinned-relay fault
case. The exact-source live run passed both text cases: the running provider
HTTP publication and the direct Provider-library lost-response scenario
against actual PostgreSQL and the pinned relay. The latter did not use the
deployed HTTP listener. Exact commands, log hashes and image/test identities
are in [completion evidence](../../../docs/implementation/COMPLETION.md).
Attachment delivery, native-client mediation and model/MCP publication are
still open; this is not an acceptance of item 04.4 or BZ-C06/07.

2026-09-23 — Item 04.6: the selected Docker 29.8.1 VM built and privately
deployed an exact-source `d3f9555` Linux arm64 image with no host port and
inactive profile. This was a cached iteration build; the last independent
clean image remains `742dd78`. At `d3f9555`, all ten non-live PostgreSQL
cases and ten restarts, twelve library tests, formatting and strict Clippy
passed locally. Review of the restart script found that its digest omitted
signed publication deliveries and scopes. The script now includes both
tables; the populated publication recovery case passed a real restart with
the stronger digest. The earlier ten-case pass used the old digest and is
reported separately. The guest-root build cache and exact-source test image
were used because the VM Docker partition was nearly full; only positively
identified unused task images were removed. Full distribution, protected
restore, production model/native/media gateway, composed Akita and human UAT
qualification remain claimed work.

2026-09-23 — Item 04.2: `5f65e5b` binds each declared attachment to a
different signed native `imeta` tag. A PostgreSQL/signature regression first
showed that two declarations could match one tag and leave another
unaccounted for; it then passed after the bijection check. The same case
admits two exact, distinct signed attachments and retains their metadata and
original event, while reporting that attachment bytes are not durable.
`e4ecc59` rejects a single signed tag with duplicate required fields; the
duplicate-hash case was red before the check and green afterward. These
are attribution guards, not media-byte registration, gateway delivery,
client download or acceptance of BZ-C03/07/08. Exact logs and limits are in
[completion evidence](../../../docs/implementation/COMPLETION.md).

2026-09-23 — Item 04.6: the first full suite after the intake change stopped
before its first assertion when Docker had 14 MB free. The task's disposable
PostgreSQL runner had left anonymous image-declared data volumes after
removing containers. `510ae1a` now removes each invocation's container and
its anonymous volume. Fifteen detached volumes from this task's recent test
window were verified as PostgreSQL 16 data or the failed empty directory and
removed by exact name; no global prune or shared VM/daemon stop occurred.
The count remained 74 before and after the later ten-case suite. At committed
`e4ecc59`, all ten PostgreSQL/signature cases and ten strengthened restart
digests, twelve library tests, formatting and strict Clippy passed. A cached
exact-source Linux arm64 image was built and booted privately; health and
fixed native-origin probes passed, with the profile inactive and no host
port. The last independent clean build is still `742dd78`. Production
model/native/media gateway, complete restore/distribution, composed Akita
results and named human UAT remain open.

2026-09-23 — Item 04.4: `9c1c572` closes malformed native-roster
interpretation at the publication audience gate. The decoder now accepts only
the pinned relay's signed `p` tag shape and five defined roles; nonempty relay
addresses and unknown roles are denied. The targeted Rust regression was red
before the decoder and green after it. Thirteen library tests, formatting and
strict Clippy passed. The exact-source cached Linux arm64 image built on the
selected Docker 29.8.1 VM, booted privately, and passed provider health and
fixed-origin checks against the signed two-member relay audience. This does
not resolve native subscriber/media mediation, the actual agent/model/MCP
path, composed Akita qualification or human UAT. Exact source, image and log
identities are in [completion evidence](../../../docs/implementation/COMPLETION.md).

2026-09-23 — Item 04.3: `2968100` adds a one-use exact-text ACP prompt
filter bound to a supplied canonical prompt digest and the recorded session.
The default probe still refuses prompts. Fourteen library tests, formatting
and strict Clippy passed; the new guard case first failed to compile before
the constructor existed. The trusted supervisor has not yet linked a durable
reservation to this filter, and no model transport or usage settlement is
qualified by it. The exact-source Linux containment script then exited 0:
pinned agent/ACP executables, ACP2/MCP handshake, closed inherited
environment and kernel process/filesystem/network denials passed with zero
model calls. The separately running provider remained healthy afterward.
The reserved prompt branch itself was not exercised by that probe, so actual
supervision and model settlement remain open. Item 04.3 remains claimed.

2026-09-23 — Item 04.6: on the task-only selected VM, 73 detached anonymous
volumes were verified as PostgreSQL 16 test data and one detached anonymous
volume was empty after a failed start. All 74 exact names were removed;
the ten named local-stack volumes and every mounted volume remained. The
Docker partition rose from 193 MB to 3.8 GB available. No global prune or
shared resource cleanup occurred. The ignored identity-manifest SHA-256 is
recorded in [completion evidence](../../../docs/implementation/COMPLETION.md).

2026-09-23 — Item 04.3: `3c7bdbd` closes a cancellation hole in the new ACP
prompt filter. Source inspection found that the old guard allowed a reserved
prompt and repeated cancel after the first cancel; the focused regression
failed at the repeated-cancel assertion before the change and passed both
denials afterward. Fifteen locked library tests, formatting and strict Clippy passed.
The Linux containment pass remains bound to `2968100`, not this revision;
the selected VM had 1.1 GB free after that clean build. Durable supervisor,
token-counting proxy and actual task-bound agent work remain unfinished.
